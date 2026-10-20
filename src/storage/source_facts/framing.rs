//! The one bounded framing state machine of §17.2.
//!
//! Both the slice-based [`super::FramingScan`] and the streaming
//! [`FramingStream`] drive this single machine: the slice scan feeds it through
//! a `Cursor`, a real file feeds it any [`BufRead`]. Keeping one machine is what
//! makes "the same bytes frame the same way" a property of the code rather than
//! of two implementations that happen to agree today.
//!
//! The machine never holds a record's bytes. It consumes the caller's buffered
//! chunk in place and keeps only the running digest of the record in front of
//! it, an ASCII-blank flag, one undecided separator byte, the counters and at
//! most one frame waiting for the next page. Its resident state is therefore
//! independent of how long a record or an input is; the bounded read window is
//! the `BufRead`'s, which every accepted input must already provide.

use std::io::{self, BufRead};

use sha2::{Digest, Sha256};

use super::{
    FramedSourceRecord, FramingSummary, Sha256Digest, SourceFormat, SourceInstallError,
    SourceRecordLocator, SOURCE_FRAMING_DOMAIN, framing_leaf,
};

/// The default record target of one page (§16).
pub const FRAMING_DEFAULT_MAX_RECORDS: usize = 64;

/// The default byte target of one page (§16): 8 MiB of original record bytes.
pub const FRAMING_DEFAULT_TARGET_BYTES: u64 = 8_388_608;

/// The stage name an I/O failure is reported with (§17.2).
const READ_STAGE: &str = "framing-read";

/// A bounded, streaming independent framing scan (§17.2).
///
/// The scan owns its own denominator: it counts records and blank lines, hashes
/// each record's own bytes and streams the `cass.source-framing/1` digest,
/// without consulting a parser, a reader or any FAD output.
pub struct FramingStream<R: BufRead> {
    reader: R,
    core: FramingCore,
    /// The kind of a read failure already observed. Once set, the reader is
    /// never polled again and every further step repeats the failure instead of
    /// pretending the input ended: a half-read input must never be continued,
    /// and must never look like a complete one.
    failure: Option<io::ErrorKind>,
    /// At most one frame held back by the bounded pager.
    pending_frame: Option<FramedSourceRecord>,
}

impl<R: BufRead> FramingStream<R> {
    /// Start a scan over one input.
    #[must_use]
    pub fn new(reader: R, format: SourceFormat) -> Self {
        Self {
            reader,
            core: FramingCore::new(format),
            failure: None,
            pending_frame: None,
        }
    }

    /// Whether the scan has delivered everything it found.
    ///
    /// Blank lines advance the scan without producing a frame, so a page can
    /// come back empty while the scan is still running; this is the flag to
    /// drive a loop on, and it is false while a frame is still held back.
    #[must_use]
    pub fn is_done(&self) -> bool {
        self.core.done && self.pending_frame.is_none()
    }

    /// Take the next page of at most `limit` frames.
    ///
    /// This is the historical count-only pager: `limit` bounds the record count
    /// and nothing else, and the pages it returns are unchanged.
    ///
    /// # Errors
    /// `Overflow` when an ordinal or byte counter would not fit a `u64`; `Io`
    /// when the input could not be read.
    pub fn next_page(
        &mut self,
        limit: usize,
    ) -> Result<Vec<FramedSourceRecord>, SourceInstallError> {
        let mut page = Vec::new();
        while page.len() < limit {
            if let Some(frame) = self.pending_frame.take() {
                page.push(frame);
                continue;
            }
            match self.step()? {
                ScanStep::Done => break,
                ScanStep::Blank => {}
                ScanStep::Record(record) => page.push(record),
            }
        }
        Ok(page)
    }

    /// Take the next page under the frozen defaults:
    /// [`FRAMING_DEFAULT_MAX_RECORDS`] records and
    /// [`FRAMING_DEFAULT_TARGET_BYTES`] original record bytes.
    ///
    /// # Errors
    /// As [`Self::next_page_bounded`].
    pub fn next_page_default(&mut self) -> Result<Vec<FramedSourceRecord>, SourceInstallError> {
        self.next_page_bounded(FRAMING_DEFAULT_MAX_RECORDS, FRAMING_DEFAULT_TARGET_BYTES)
    }

    /// Take the next page under both the record target and the byte target
    /// (§16).
    ///
    /// Records are accumulated by their original byte span
    /// (`locator.byte_end - locator.byte_start`). The page ends before a record
    /// that would push it past either target; a record that alone exceeds the
    /// byte target still gets a page of its own. Every other page therefore
    /// satisfies both targets.
    ///
    /// # Errors
    /// `Staging` when either target is zero — a zero target can never make
    /// progress, so it is refused rather than looped on. `Overflow` when an
    /// ordinal or byte counter would not fit a `u64`; `Io` when the input could
    /// not be read.
    pub fn next_page_bounded(
        &mut self,
        max_records: usize,
        target_bytes: u64,
    ) -> Result<Vec<FramedSourceRecord>, SourceInstallError> {
        if max_records == 0 || target_bytes == 0 {
            return Err(SourceInstallError::Staging {
                detail: format!(
                    "framing page targets must be non-zero (max_records={max_records}, \
                     target_bytes={target_bytes})"
                ),
            });
        }
        let mut page = Vec::new();
        let mut page_bytes = 0u64;
        loop {
            let record = match self.take_frame()? {
                Some(record) => record,
                None => break,
            };
            let record_bytes = record
                .locator()
                .byte_end
                .checked_sub(record.locator().byte_start)
                .ok_or(SourceInstallError::Overflow { field: "byte_end" })?;
            // The page ends *before* the record that would overflow either
            // target; an empty page always accepts its first record, which is
            // how a single oversized record comes to occupy its own page.
            if !page.is_empty()
                && (page.len() as u64 >= max_records as u64
                    || page_bytes.saturating_add(record_bytes) > target_bytes)
            {
                self.pending_frame = Some(record);
                break;
            }
            page.push(record);
            page_bytes = page_bytes.saturating_add(record_bytes);
            if page.len() as u64 >= max_records as u64 || page_bytes >= target_bytes {
                break;
            }
        }
        Ok(page)
    }

    /// Consume the rest of the input without keeping any frame, for callers
    /// that only need the counters and the stream digest.
    ///
    /// # Errors
    /// `Overflow` when an ordinal or byte counter would not fit a `u64`; `Io`
    /// when the input could not be read.
    pub fn run_to_end(&mut self) -> Result<(), SourceInstallError> {
        self.pending_frame = None;
        while !matches!(self.step()?, ScanStep::Done) {}
        Ok(())
    }

    /// Close the scan against the bytes it read.
    ///
    /// `byte_len` is the number of bytes actually consumed, which equals the
    /// input's length once the scan reached its end. `complete` reports whether
    /// it did; a scan that stopped early — or failed — still yields its
    /// counters, and the caller must not treat it as an authorisation.
    #[must_use]
    pub fn finish(self) -> FramingSummary {
        let byte_len = self.core.bytes_consumed;
        self.finish_with_byte_len(byte_len)
    }

    /// Close the scan, reporting the given input length rather than the
    /// consumed count.
    ///
    /// The slice scan knows its input's full length up front and reports it
    /// exactly as it always has; a stream cannot, so [`Self::finish`] reports
    /// what it consumed.
    #[must_use]
    pub(super) fn finish_with_byte_len(self, byte_len: u64) -> FramingSummary {
        let content_bytes: [u8; 32] = self.core.content.finalize().into();
        let framing_bytes: [u8; 32] = self.core.framing.finalize().into();
        FramingSummary {
            byte_len,
            sealed_sha256: Sha256Digest::from_slice(&content_bytes).expect("sha256 is 32 bytes"),
            records: self.core.records,
            blank_lines: self.core.blank_lines,
            blank_bytes: self.core.blank_bytes,
            framing_sha256: Sha256Digest::from_slice(&framing_bytes).expect("sha256 is 32 bytes"),
            complete: self.core.done,
        }
    }

    /// Take one frame, consuming any blank lines in front of it.
    fn take_frame(&mut self) -> Result<Option<FramedSourceRecord>, SourceInstallError> {
        if let Some(frame) = self.pending_frame.take() {
            return Ok(Some(frame));
        }
        loop {
            match self.step()? {
                ScanStep::Done => return Ok(None),
                ScanStep::Blank => {}
                ScanStep::Record(record) => return Ok(Some(record)),
            }
        }
    }

    /// Consume one frame.
    fn step(&mut self) -> Result<ScanStep, SourceInstallError> {
        loop {
            // A failure already observed stays observed: the scan never resumes
            // a half-read input, and never reports it as an end of input.
            if let Some(kind) = self.failure {
                return Err(SourceInstallError::Io { kind, stage: READ_STAGE });
            }
            if self.core.done {
                return Ok(ScanStep::Done);
            }
            let mut finished = None;
            let mut at_eof = false;
            {
                let chunk = match self.reader.fill_buf() {
                    Ok(chunk) => chunk,
                    // A signal that interrupted the read is retried, not
                    // surfaced as a failure of the input.
                    Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
                    Err(err) => {
                        let kind = err.kind();
                        self.failure = Some(kind);
                        return Err(SourceInstallError::Io { kind, stage: READ_STAGE });
                    }
                };
                if chunk.is_empty() {
                    at_eof = true;
                } else {
                    let mut used = 0usize;
                    for &byte in chunk {
                        used += 1;
                        if let Some(step) = self.core.consume(byte)? {
                            finished = Some(step);
                            break;
                        }
                    }
                    self.reader.consume(used);
                }
            }
            if let Some(step) = finished {
                return Ok(step);
            }
            if at_eof {
                self.core.done = true;
                return self.core.finish_input();
            }
        }
    }
}

/// The counters, digests and in-progress record of one framing scan.
///
/// It is separate from the reader only so the reader's borrowed chunk and the
/// scan's own mutable state are disjoint borrows.
struct FramingCore {
    format: SourceFormat,
    /// The record in front of the machine.
    record_start: u64,
    record_hasher: Sha256,
    record_raw_len: u64,
    record_blank_so_far: bool,
    pending_cr: bool,
    // Counters and stream digests.
    next_ordinal: u64,
    records: u64,
    blank_lines: u64,
    blank_bytes: u64,
    bytes_consumed: u64,
    content: Sha256,
    framing: Sha256,
    done: bool,
}

impl FramingCore {
    fn new(format: SourceFormat) -> Self {
        let mut framing = Sha256::new();
        framing.update(SOURCE_FRAMING_DOMAIN.as_bytes());
        Self {
            format,
            record_start: 0,
            record_hasher: Sha256::new(),
            record_raw_len: 0,
            record_blank_so_far: true,
            pending_cr: false,
            next_ordinal: 1,
            records: 0,
            blank_lines: 0,
            blank_bytes: 0,
            bytes_consumed: 0,
            content: Sha256::new(),
            framing,
            done: false,
        }
    }

    /// Fold one input byte into the machine. Returns a step when the byte
    /// closed a physical line.
    fn consume(&mut self, byte: u8) -> Result<Option<ScanStep>, SourceInstallError> {
        self.bytes_consumed = self
            .bytes_consumed
            .checked_add(1)
            .ok_or(SourceInstallError::Overflow { field: "bytes_consumed" })?;
        self.content.update([byte]);

        // A document has no line structure: every byte, including any newline
        // or carriage return, is raw document content.
        if self.format == SourceFormat::JsonDocument {
            self.push_raw(byte)?;
            return Ok(None);
        }

        if self.pending_cr {
            self.pending_cr = false;
            if byte == b'\n' {
                // CRLF: the carriage return already consumed is separator, not
                // raw content, so it stays out of the record's range and digest.
                return Ok(Some(self.finish_line()?));
            }
            // The carriage return was a bare one; it belongs to the record.
            self.push_raw(b'\r')?;
        }

        match byte {
            // A carriage return is undecided until its successor is known.
            b'\r' => {
                self.pending_cr = true;
                Ok(None)
            }
            b'\n' => Ok(Some(self.finish_line()?)),
            other => {
                self.push_raw(other)?;
                Ok(None)
            }
        }
    }

    /// Append one byte to the record in front of the machine.
    fn push_raw(&mut self, byte: u8) -> Result<(), SourceInstallError> {
        self.record_hasher.update([byte]);
        self.record_raw_len = self
            .record_raw_len
            .checked_add(1)
            .ok_or(SourceInstallError::Overflow { field: "byte_end" })?;
        // Only ASCII JSON whitespace makes a blank line; every other byte,
        // including invalid UTF-8, keeps the line a record.
        if !matches!(byte, b' ' | b'\t' | b'\r') {
            self.record_blank_so_far = false;
        }
        Ok(())
    }

    /// Close the physical line in front of the machine and start the next one.
    fn finish_line(&mut self) -> Result<ScanStep, SourceInstallError> {
        let ordinal = self.next_ordinal;
        self.next_ordinal = ordinal
            .checked_add(1)
            .ok_or(SourceInstallError::Overflow { field: "ordinal" })?;
        let raw_len = self.record_raw_len;
        let raw_end = self
            .record_start
            .checked_add(raw_len)
            .ok_or(SourceInstallError::Overflow { field: "byte_end" })?;

        let step = if self.format == SourceFormat::Jsonl && self.record_blank_so_far {
            self.blank_lines = self
                .blank_lines
                .checked_add(1)
                .ok_or(SourceInstallError::Overflow { field: "blank_lines" })?;
            self.blank_bytes = self
                .blank_bytes
                .checked_add(raw_len)
                .ok_or(SourceInstallError::Overflow { field: "blank_bytes" })?;
            ScanStep::Blank
        } else {
            self.records = self
                .records
                .checked_add(1)
                .ok_or(SourceInstallError::Overflow { field: "records" })?;
            let hasher = std::mem::replace(&mut self.record_hasher, Sha256::new());
            let digest_bytes: [u8; 32] = hasher.finalize().into();
            let raw_sha256 = Sha256Digest::from_slice(&digest_bytes).expect("sha256 is 32 bytes");
            let leaf = framing_leaf(ordinal, self.record_start, raw_end, &raw_sha256);
            self.framing.update((leaf.len() as u64).to_be_bytes());
            self.framing.update(&leaf);
            ScanStep::Record(FramedSourceRecord {
                locator: SourceRecordLocator {
                    ordinal,
                    record_pointer: String::new(),
                    byte_start: self.record_start,
                    byte_end: raw_end,
                },
                raw_sha256,
            })
        };

        // The next physical line begins after this line's terminator, and the
        // consumed count is already past it.
        self.record_start = self.bytes_consumed;
        self.record_hasher = Sha256::new();
        self.record_raw_len = 0;
        self.record_blank_so_far = true;
        self.pending_cr = false;
        Ok(step)
    }

    /// Close the machine at the end of the input.
    fn finish_input(&mut self) -> Result<ScanStep, SourceInstallError> {
        if self.format == SourceFormat::JsonDocument {
            // A document is exactly one frame, covering the whole file. An
            // empty document is still one empty frame, as it always was.
            return self.finish_line();
        }
        if self.pending_cr {
            // A trailing bare carriage return is raw content, not a terminator.
            self.pending_cr = false;
            self.push_raw(b'\r')?;
        }
        if self.record_raw_len > 0 {
            // The last line has no terminator, and it is still a record.
            return self.finish_line();
        }
        Ok(ScanStep::Done)
    }
}

/// One step of a framing scan.
pub(super) enum ScanStep {
    /// The input is exhausted.
    Done,
    /// A blank line advanced the scan without producing a frame.
    Blank,
    /// One physical record.
    Record(FramedSourceRecord),
}
