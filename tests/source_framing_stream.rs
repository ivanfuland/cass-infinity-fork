//! SRC05B-02: independent verification of the streaming framing engine.
//!
//! The expected values in this file come from a naive whole-input reference
//! implementation written from §17.2's prose and from the documented page
//! defaults. No assertion here asks the engine what it thinks: comparing the
//! slice entry with the streaming entry would prove only that they delegate to
//! the same machine, so both are compared against that reference instead.

use std::fs::File;
use std::io::{self, BufRead, BufReader, Cursor, Read};
use std::path::{Path, PathBuf};
use std::time::Instant;

use tempfile::TempDir;

use coding_agent_search::sources::config::ExcludedContextPaths;
use coding_agent_search::storage::source_facts::{
    FRAMING_DEFAULT_MAX_RECORDS, FRAMING_DEFAULT_TARGET_BYTES, FramedSourceRecord, FramingScan,
    FramingStream, FramingSummary, Sha256Digest, SourceFormat, SourceInputDeclaration,
    SourceInstallError, SourceSafetyConfig, VerifiedSourceInput, context_digest,
    encode_expected_manifest_header, expected_manifest_digest,
};
use franken_agent_detection::LosslessSourceValue;
use sha2::{Digest, Sha256};

// =============================================================================
// A naive whole-input reference (§17.2), written from the contract's prose
// =============================================================================

#[derive(Debug, Clone, PartialEq, Eq)]
struct RefFrame {
    ordinal: u64,
    byte_start: u64,
    byte_end: u64,
    raw_sha256: Sha256Digest,
}

struct Reference {
    frames: Vec<RefFrame>,
    records: u64,
    blank_lines: u64,
    blank_bytes: u64,
    byte_len: u64,
    sealed_sha256: Sha256Digest,
    framing_sha256: Sha256Digest,
    framing_bytes: Vec<u8>,
}

impl Reference {
    fn new() -> Self {
        Self {
            frames: Vec::new(),
            records: 0,
            blank_lines: 0,
            blank_bytes: 0,
            byte_len: 0,
            sealed_sha256: Sha256Digest::of(b""),
            framing_sha256: Sha256Digest::of(b""),
            framing_bytes: b"cass.source-framing/1".to_vec(),
        }
    }

    fn line(&mut self, ordinal: u64, raw: &[u8], start: u64, blank_eligible: bool) {
        if blank_eligible && raw.iter().all(|byte| matches!(*byte, b' ' | b'\t' | b'\r' | b'\n')) {
            self.blank_lines += 1;
            self.blank_bytes += raw.len() as u64;
            return;
        }
        self.records += 1;
        let end = start + raw.len() as u64;
        let sha = Sha256Digest::of(raw);
        let leaf = format!("[\"{ordinal}\",\"\",\"{start}\",\"{end}\",\"{}\"]", sha.hex())
            .into_bytes();
        self.framing_bytes
            .extend_from_slice(&(leaf.len() as u64).to_be_bytes());
        self.framing_bytes.extend_from_slice(&leaf);
        self.frames.push(RefFrame { ordinal, byte_start: start, byte_end: end, raw_sha256: sha });
    }
}

/// The reference framing, computed over the whole input at once.
fn reference_framing(input: &[u8], format: SourceFormat) -> Reference {
    let mut reference = Reference::new();
    match format {
        SourceFormat::JsonDocument => reference.line(1, input, 0, false),
        SourceFormat::Jsonl => {
            let mut ordinal = 0u64;
            let mut pos = 0usize;
            while pos < input.len() {
                ordinal += 1;
                let start = pos as u64;
                match input[pos..].iter().position(|byte| *byte == b'\n') {
                    Some(offset) => {
                        let after = pos + offset + 1;
                        let line = &input[pos..after];
                        let terminator =
                            if line.len() >= 2 && line[line.len() - 2] == b'\r' { 2 } else { 1 };
                        reference.line(ordinal, &line[..line.len() - terminator], start, true);
                        pos = after;
                    }
                    None => {
                        reference.line(ordinal, &input[pos..], start, true);
                        pos = input.len();
                    }
                }
            }
        }
    }
    reference.byte_len = input.len() as u64;
    reference.sealed_sha256 = Sha256Digest::of(input);
    reference.framing_sha256 = Sha256Digest::of(&reference.framing_bytes);
    reference
}

// =============================================================================
// Readers
// =============================================================================

/// A `BufRead` over bytes handed out in fixed-size chunks, so every chunk
/// boundary is exercised as a boundary.
struct ChunkedSource {
    data: Vec<u8>,
    pos: usize,
    chunk: usize,
}

impl ChunkedSource {
    fn new(data: Vec<u8>, chunk: usize) -> Self {
        Self { data, pos: 0, chunk }
    }
}

impl BufRead for ChunkedSource {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        let end = (self.pos + self.chunk).min(self.data.len());
        Ok(&self.data[self.pos..end])
    }

    fn consume(&mut self, amount: usize) {
        self.pos = (self.pos + amount).min(self.data.len());
    }
}

impl Read for ChunkedSource {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let written = {
            let chunk = self.fill_buf()?;
            let written = chunk.len().min(buf.len());
            buf[..written].copy_from_slice(&chunk[..written]);
            written
        };
        self.consume(written);
        Ok(written)
    }
}

/// A `BufRead` that can inject `Interrupted` responses, a hard read error at a
/// chosen offset, or both.
struct ScriptedSource {
    data: Vec<u8>,
    pos: usize,
    chunk: usize,
    fail_at: Option<usize>,
    fail_kind: io::ErrorKind,
    interrupts_pending: usize,
    scratch: Vec<u8>,
}

impl ScriptedSource {
    fn plain(data: Vec<u8>, chunk: usize) -> Self {
        Self { data, pos: 0, chunk, fail_at: None, fail_kind: io::ErrorKind::Other, interrupts_pending: 0, scratch: Vec::new() }
    }

    fn failing(data: Vec<u8>, chunk: usize, fail_at: usize, fail_kind: io::ErrorKind) -> Self {
        Self { data, pos: 0, chunk, fail_at: Some(fail_at), fail_kind, interrupts_pending: 0, scratch: Vec::new() }
    }

    fn interrupting(data: Vec<u8>, chunk: usize, interrupts: usize) -> Self {
        Self { data, pos: 0, chunk, fail_at: None, fail_kind: io::ErrorKind::Other, interrupts_pending: interrupts, scratch: Vec::new() }
    }
}

impl BufRead for ScriptedSource {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        if self.interrupts_pending > 0 {
            self.interrupts_pending -= 1;
            return Err(io::Error::new(io::ErrorKind::Interrupted, "synthetic interruption"));
        }
        if self.fail_at == Some(self.pos) {
            return Err(io::Error::new(self.fail_kind, "synthetic read failure"));
        }
        self.scratch.clear();
        let end = (self.pos + self.chunk).min(self.data.len());
        self.scratch.extend_from_slice(&self.data[self.pos..end]);
        Ok(&self.scratch)
    }

    fn consume(&mut self, amount: usize) {
        self.pos = (self.pos + amount).min(self.data.len());
    }
}

impl Read for ScriptedSource {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let written = {
            let chunk = self.fill_buf()?;
            let written = chunk.len().min(buf.len());
            buf[..written].copy_from_slice(&chunk[..written]);
            written
        };
        self.consume(written);
        Ok(written)
    }
}

/// A `BufRead` that produces its bytes on demand and keeps none of them, so a
/// 32 MiB record never exists anywhere as a buffer.
struct GeneratedInput {
    byte: u8,
    total: u64,
    produced: u64,
    last: Option<u8>,
    chunk: usize,
    chunks: Vec<usize>,
    scratch: Vec<u8>,
}

impl GeneratedInput {
    fn jsonl(record_len: u64, chunk: usize) -> Self {
        Self { byte: b'a', total: record_len + 1, produced: 0, last: Some(b'\n'), chunk, chunks: Vec::new(), scratch: Vec::new() }
    }

    fn document(total: u64, chunk: usize) -> Self {
        Self { byte: b'{', total, produced: 0, last: None, chunk, chunks: Vec::new(), scratch: Vec::new() }
    }
}

impl BufRead for GeneratedInput {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        self.scratch.clear();
        let remaining = self.total - self.produced;
        let size = remaining.min(self.chunk as u64) as usize;
        self.chunks.push(size);
        for index in 0..size {
            let offset = self.produced + index as u64;
            let byte = if self.last.is_some() && offset + 1 == self.total {
                self.last.expect("checked above")
            } else {
                self.byte
            };
            self.scratch.push(byte);
        }
        Ok(&self.scratch)
    }

    fn consume(&mut self, amount: usize) {
        self.produced = (self.produced + amount as u64).min(self.total);
    }
}

impl Read for GeneratedInput {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let written = {
            let chunk = self.fill_buf()?;
            let written = chunk.len().min(buf.len());
            buf[..written].copy_from_slice(&chunk[..written]);
            written
        };
        self.consume(written);
        Ok(written)
    }
}

// =============================================================================
// Collection and assertion helpers
// =============================================================================

fn drain<R: BufRead>(mut scan: FramingStream<R>) -> (Vec<FramedSourceRecord>, FramingSummary) {
    let mut frames = Vec::new();
    while !scan.is_done() {
        frames.extend(scan.next_page(usize::MAX).expect("the scan must not fail"));
    }
    (frames, scan.finish())
}

fn drain_chunked(input: &[u8], format: SourceFormat, chunk: usize) -> (Vec<FramedSourceRecord>, FramingSummary) {
    drain(FramingStream::new(ChunkedSource::new(input.to_vec(), chunk), format))
}

fn drain_slice(input: &[u8], format: SourceFormat) -> (Vec<FramedSourceRecord>, FramingSummary) {
    let mut scan = FramingScan::new(input, format);
    let mut frames = Vec::new();
    while !scan.is_done() {
        frames.extend(scan.next_page(usize::MAX).expect("the slice scan must not fail"));
    }
    (frames, scan.finish())
}

/// Every page the bounded pager yields, with a hard iteration bound so a
/// regression fails loudly instead of hanging.
fn drain_pages<R: BufRead>(
    mut scan: FramingStream<R>,
    max_records: usize,
    target_bytes: u64,
) -> Vec<Vec<FramedSourceRecord>> {
    let mut pages = Vec::new();
    for _ in 0..100_000 {
        if scan.is_done() {
            return pages;
        }
        pages.push(scan.next_page_bounded(max_records, target_bytes).expect("a bounded page"));
    }
    panic!("the bounded pager never reached the end of its input");
}

fn assert_frames(label: &str, got: &[FramedSourceRecord], want: &[RefFrame]) {
    assert_eq!(got.len(), want.len(), "{label}: frame count");
    for (index, (got, want)) in got.iter().zip(want).enumerate() {
        assert_eq!(got.locator().ordinal, want.ordinal, "{label}: frame {index} ordinal");
        assert_eq!(got.locator().record_pointer, "", "{label}: frame {index} pointer");
        assert_eq!(got.locator().byte_start, want.byte_start, "{label}: frame {index} byte_start");
        assert_eq!(got.locator().byte_end, want.byte_end, "{label}: frame {index} byte_end");
        assert_eq!(got.raw_sha256(), &want.raw_sha256, "{label}: frame {index} raw digest");
    }
}

fn assert_summary(label: &str, got: &FramingSummary, want: &Reference) {
    assert_eq!(got.byte_len, want.byte_len, "{label}: byte_len");
    assert_eq!(got.sealed_sha256, want.sealed_sha256, "{label}: sealed digest");
    assert_eq!(got.records, want.records, "{label}: records");
    assert_eq!(got.blank_lines, want.blank_lines, "{label}: blank lines");
    assert_eq!(got.blank_bytes, want.blank_bytes, "{label}: blank bytes");
    assert_eq!(got.framing_sha256, want.framing_sha256, "{label}: framing digest");
    assert!(got.complete, "{label}: the scan must be complete");
}

fn assert_every_frame_once_in_order(pages: &[Vec<FramedSourceRecord>], want: &[RefFrame]) {
    let flat: Vec<&FramedSourceRecord> = pages.iter().flatten().collect();
    assert_eq!(flat.len(), want.len(), "the pages must carry every frame exactly once");
    for (index, (got, want)) in flat.iter().zip(want).enumerate() {
        assert_eq!(got.locator().ordinal, want.ordinal, "concatenated frame {index} ordinal");
        assert_eq!(got.locator().byte_start, want.byte_start, "concatenated frame {index} start");
        assert_eq!(got.locator().byte_end, want.byte_end, "concatenated frame {index} end");
        assert_eq!(got.raw_sha256(), &want.raw_sha256, "concatenated frame {index} digest");
    }
}

fn assert_pages_within_targets(pages: &[Vec<FramedSourceRecord>], max_records: usize, target_bytes: u64) {
    for (index, page) in pages.iter().enumerate() {
        let bytes: u64 = page
            .iter()
            .map(|frame| frame.locator().byte_end - frame.locator().byte_start)
            .sum();
        if page.len() == 1 && bytes > target_bytes {
            // A record larger than the byte target occupies its own page.
            continue;
        }
        assert!(page.len() <= max_records, "page {index} exceeds the record target");
        assert!(bytes <= target_bytes, "page {index} exceeds the byte target");
    }
}

fn first_error<R: BufRead>(scan: &mut FramingStream<R>) -> SourceInstallError {
    for _ in 0..1_000_000 {
        assert!(!scan.is_done(), "the scan finished instead of failing");
        match scan.next_page(usize::MAX) {
            Ok(page) => assert!(!page.is_empty(), "a page was empty before the input ended"),
            Err(err) => return err,
        }
    }
    panic!("the scan kept returning pages after the input ended");
}

/// The digest of `len` repetitions of `byte`, computed in bounded blocks.
fn generated_digest(byte: u8, len: u64) -> Sha256Digest {
    let block = vec![byte; 8192];
    let mut hasher = Sha256::new();
    let mut remaining = len;
    while remaining > 0 {
        let take = remaining.min(block.len() as u64) as usize;
        hasher.update(&block[..take]);
        remaining -= take as u64;
    }
    let bytes: [u8; 32] = hasher.finalize().into();
    Sha256Digest::from_slice(&bytes).expect("a sha256 finalises to 32 bytes")
}

#[cfg(target_os = "linux")]
fn resident_set_kib() -> Option<u64> {
    let text = std::fs::read_to_string("/proc/self/statm").ok()?;
    let pages: u64 = text.split_whitespace().nth(1)?.parse().ok()?;
    Some(pages * 4)
}

#[cfg(not(target_os = "linux"))]
fn resident_set_kib() -> Option<u64> {
    None
}

// =============================================================================
// Fixtures
// =============================================================================

/// JSONL inputs covering every framing shape §17.2 names.
fn jsonl_fixtures() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("lf", b"{\"n\":1}\n{\"n\":2}\n".to_vec()),
        ("crlf", b"{\"n\":1}\r\n{\"n\":2}\r\n".to_vec()),
        ("last line without a terminator", b"{\"n\":1}\n{\"n\":2}".to_vec()),
        ("bare cr inside a line", b"{\"n\":1}\r{\"n\":2}\n".to_vec()),
        ("trailing bare cr", b"{\"n\":1}\r".to_vec()),
        ("only a bare cr", b"\r".to_vec()),
        ("mixed cr and crlf", b"a\r\r\nb\r\rc\n".to_vec()),
        ("blank lines", b" \n\t\n\r\n  \t\r\n\t \r\n".to_vec()),
        ("blank lines consume ordinals", b"a\n\n\nb\n".to_vec()),
        ("unicode whitespace stays a record", "\u{00a0}\n\u{3000}\n\u{2028}\n".as_bytes().to_vec()),
        ("invalid utf-8 stays a record", vec![0xff, 0xfe, b'\n', 0x80, b'\n', 0xc3]),
        ("empty", Vec::new()),
        ("only a newline", b"\n".to_vec()),
        ("empty crlf lines", b"\r\n\r\n".to_vec()),
        ("every byte value", (0u8..=255).collect()),
    ]
}

// =============================================================================
// V1 — the stream frames the same bytes the same way as an independent reference
// =============================================================================

#[test]
fn stream_frames_match_an_independent_reference_on_jsonl_shapes() {
    for (label, bytes) in jsonl_fixtures() {
        let reference = reference_framing(&bytes, SourceFormat::Jsonl);
        let (frames, summary) = drain(FramingStream::new(Cursor::new(bytes.as_slice()), SourceFormat::Jsonl));
        assert_frames(label, &frames, &reference.frames);
        assert_summary(label, &summary, &reference);
        for chunk in [1usize, 2, 3, 7, 64, 4096] {
            let (frames, summary) = drain_chunked(&bytes, SourceFormat::Jsonl, chunk);
            let chunked = format!("{label}/chunk={chunk}");
            assert_frames(&chunked, &frames, &reference.frames);
            assert_summary(&chunked, &summary, &reference);
        }
    }
}

#[test]
fn stream_frames_match_an_independent_reference_on_json_document_shapes() {
    let fixtures: Vec<(&str, Vec<u8>)> = vec![
        ("object", b"{\n  \"n\": 1\n}".to_vec()),
        ("empty document", Vec::new()),
        ("whitespace only", b"\n\r\n\t".to_vec()),
        ("invalid utf-8", vec![0x80, 0x0a, 0xff]),
        ("crlf document", b"{\"a\":1}\r\n{\"b\":2}\r\n".to_vec()),
    ];
    for (label, bytes) in fixtures {
        let reference = reference_framing(&bytes, SourceFormat::JsonDocument);
        let (frames, summary) = drain(FramingStream::new(Cursor::new(bytes.as_slice()), SourceFormat::JsonDocument));
        assert_frames(label, &frames, &reference.frames);
        assert_summary(label, &summary, &reference);
        for chunk in [1usize, 3, 4096] {
            let (frames, summary) = drain_chunked(&bytes, SourceFormat::JsonDocument, chunk);
            let chunked = format!("{label}/chunk={chunk}");
            assert_frames(&chunked, &frames, &reference.frames);
            assert_summary(&chunked, &summary, &reference);
        }
    }
}

#[test]
fn a_crlf_split_across_a_chunk_boundary_is_still_one_terminator() {
    // The carriage return is the last byte of one read window and the line feed
    // is the first byte of the next.
    let mut bytes = vec![b'a'; 65535];
    bytes.extend_from_slice(b"\r\nsecond\r\n");
    let reference = reference_framing(&bytes, SourceFormat::Jsonl);
    assert_eq!(reference.frames.len(), 2);
    assert_eq!(reference.frames[0].byte_start, 0);
    assert_eq!(reference.frames[0].byte_end, 65535);
    for chunk in [65536usize, 65535, 32768, 5, 1] {
        let (frames, summary) = drain_chunked(&bytes, SourceFormat::Jsonl, chunk);
        let label = format!("window={chunk}");
        assert_frames(&label, &frames, &reference.frames);
        assert_summary(&label, &summary, &reference);
    }
}

#[test]
fn the_slice_entry_reports_the_same_frames_and_summary_as_the_stream() {
    for (label, bytes) in jsonl_fixtures() {
        let reference = reference_framing(&bytes, SourceFormat::Jsonl);
        let (slice_frames, slice_summary) = drain_slice(&bytes, SourceFormat::Jsonl);
        assert_frames(&format!("slice/{label}"), &slice_frames, &reference.frames);
        assert_summary(&format!("slice/{label}"), &slice_summary, &reference);
    }
}

// =============================================================================
// V2 — dual-target paging
// =============================================================================

/// `records` JSONL lines of exactly `record_len` raw bytes each.
fn generated_jsonl(records: usize, record_len: usize) -> Vec<u8> {
    let mut out = Vec::new();
    for index in 0..records {
        let mut line = format!("{{\"i\":{index}}}").into_bytes();
        assert!(line.len() <= record_len, "the line does not fit the fixture's width");
        line.resize(record_len, b' ');
        out.extend_from_slice(&line);
        out.push(b'\n');
    }
    out
}

#[test]
fn bounded_pages_split_exactly_at_the_record_target() {
    let bytes = generated_jsonl(200, 16);
    let reference = reference_framing(&bytes, SourceFormat::Jsonl);
    let pages = drain_pages(FramingStream::new(Cursor::new(bytes.as_slice()), SourceFormat::Jsonl), 64, u64::MAX);
    assert_eq!(pages.iter().map(Vec::len).collect::<Vec<_>>(), vec![64, 64, 64, 8]);
    assert_every_frame_once_in_order(&pages, &reference.frames);
    assert_pages_within_targets(&pages, 64, u64::MAX);

    // Sixty-five records make two pages, not one.
    let bytes = generated_jsonl(65, 16);
    let reference = reference_framing(&bytes, SourceFormat::Jsonl);
    let pages = drain_pages(FramingStream::new(Cursor::new(bytes.as_slice()), SourceFormat::Jsonl), 64, u64::MAX);
    assert_eq!(pages.iter().map(Vec::len).collect::<Vec<_>>(), vec![64, 1]);
    assert_every_frame_once_in_order(&pages, &reference.frames);
}

#[test]
fn bounded_pages_honor_the_byte_target_inclusively_at_its_edge() {
    let record = 16u64;
    let bytes = generated_jsonl(20, record as usize);
    let reference = reference_framing(&bytes, SourceFormat::Jsonl);

    // Exactly five records: the fifth still fits, so it stays on the page.
    let pages = drain_pages(FramingStream::new(Cursor::new(bytes.as_slice()), SourceFormat::Jsonl), 64, 5 * record);
    assert_eq!(pages[0].len(), 5);
    assert_eq!(pages[1].len(), 5);
    assert_every_frame_once_in_order(&pages, &reference.frames);

    // One byte short: the fifth would exceed the target, so it opens the next page.
    let pages = drain_pages(FramingStream::new(Cursor::new(bytes.as_slice()), SourceFormat::Jsonl), 64, 5 * record - 1);
    assert_eq!(pages[0].len(), 4);

    // One byte over: five still fit and the sixth does not.
    let pages = drain_pages(FramingStream::new(Cursor::new(bytes.as_slice()), SourceFormat::Jsonl), 64, 5 * record + 1);
    assert_eq!(pages[0].len(), 5);
    assert_pages_within_targets(&pages, 64, 5 * record + 1);
}

#[test]
fn bounded_pages_give_an_oversized_record_its_own_page() {
    const OVERSIZED: u64 = 8 * 1024 * 1024 + 1;
    let mut bytes = generated_jsonl(4, 16);
    bytes.extend_from_slice(&vec![b'x'; OVERSIZED as usize]);
    bytes.push(b'\n');
    bytes.extend_from_slice(&generated_jsonl(4, 16));
    let reference = reference_framing(&bytes, SourceFormat::Jsonl);

    let target = FRAMING_DEFAULT_TARGET_BYTES;
    let pages = drain_pages(FramingStream::new(Cursor::new(bytes.as_slice()), SourceFormat::Jsonl), FRAMING_DEFAULT_MAX_RECORDS, target);
    assert_eq!(pages.iter().map(Vec::len).collect::<Vec<_>>(), vec![4, 1, 4]);
    let oversized = &pages[1][0];
    assert_eq!(oversized.locator().byte_end - oversized.locator().byte_start, OVERSIZED);
    assert_every_frame_once_in_order(&pages, &reference.frames);
    assert_pages_within_targets(&pages, FRAMING_DEFAULT_MAX_RECORDS, target);
}

#[test]
fn bounded_pages_deliver_every_frame_once_in_order_past_blank_lines() {
    let mut bytes = Vec::new();
    for index in 0..130 {
        bytes.extend_from_slice(format!("{{\"i\":{index}}}\n").as_bytes());
        bytes.extend_from_slice(b"\n \t\n");
    }
    let reference = reference_framing(&bytes, SourceFormat::Jsonl);
    // Each round is one record line, then an empty line and a spaces-tabs line:
    // two blank lines that consume an ordinal each and no byte budget.
    assert_eq!(reference.records, 130);
    assert_eq!(reference.blank_lines, 260);

    let pages = drain_pages(FramingStream::new(Cursor::new(bytes.as_slice()), SourceFormat::Jsonl), 64, 1_000_000);
    // Blank lines take no record slot and no byte budget.
    assert_eq!(pages.iter().map(Vec::len).collect::<Vec<_>>(), vec![64, 64, 2]);
    assert_every_frame_once_in_order(&pages, &reference.frames);
}

#[test]
fn bounded_pages_refuse_a_zero_target_without_consuming_anything() {
    let bytes = generated_jsonl(4, 16);
    let mut scan = FramingStream::new(Cursor::new(bytes.as_slice()), SourceFormat::Jsonl);

    let err = scan.next_page_bounded(0, FRAMING_DEFAULT_TARGET_BYTES).expect_err("a zero record target");
    assert!(matches!(err, SourceInstallError::Staging { .. }), "{err}");
    let err = scan.next_page_bounded(FRAMING_DEFAULT_MAX_RECORDS, 0).expect_err("a zero byte target");
    assert!(matches!(err, SourceInstallError::Staging { .. }), "{err}");

    // The refusals consumed nothing: the input is still intact.
    assert!(!scan.is_done());
    let page = scan.next_page_bounded(FRAMING_DEFAULT_MAX_RECORDS, FRAMING_DEFAULT_TARGET_BYTES).expect("a page");
    assert_eq!(page.len(), 4);
    assert!(scan.is_done());
}

#[test]
fn the_defaulted_pager_uses_the_frozen_defaults() {
    assert_eq!(FRAMING_DEFAULT_MAX_RECORDS, 64);
    assert_eq!(FRAMING_DEFAULT_TARGET_BYTES, 8_388_608);

    let bytes = generated_jsonl(130, 16);
    let mut scan = FramingStream::new(Cursor::new(bytes.as_slice()), SourceFormat::Jsonl);
    let mut sizes = Vec::new();
    while !scan.is_done() {
        sizes.push(scan.next_page_default().expect("a default page").len());
    }
    assert_eq!(sizes, vec![64, 64, 2]);
}

// =============================================================================
// V3 — bounded consumption of a record far larger than any buffer
// =============================================================================

#[test]
fn streaming_scan_of_a_32_mib_record_stays_bounded() {
    const RECORD: u64 = 32 * 1024 * 1024;
    const CHUNK: usize = 4096;
    let mut source = GeneratedInput::jsonl(RECORD, CHUNK);

    let started = Instant::now();
    let (frames, summary) = drain(FramingStream::new(&mut source, SourceFormat::Jsonl));
    let elapsed = started.elapsed();

    assert_eq!(frames.len(), 1);
    let frame = &frames[0];
    assert_eq!(frame.locator().ordinal, 1);
    assert_eq!(frame.locator().record_pointer, "");
    assert_eq!((frame.locator().byte_start, frame.locator().byte_end), (0, RECORD));
    assert_eq!(*frame.raw_sha256(), generated_digest(b'a', RECORD));
    assert_eq!(summary.byte_len, RECORD + 1);
    assert_eq!(summary.records, 1);
    assert_eq!(summary.blank_lines, 0);
    assert!(summary.complete);

    // The engine never asked its reader for more than one bounded chunk, and it
    // asked many times, so the record was never held as a single buffer.
    let largest = source.chunks.iter().copied().max().expect("the reader was polled");
    assert!(largest <= CHUNK, "the largest read request was {largest} bytes");
    assert!(source.chunks.len() >= (RECORD as usize / CHUNK) - 1, "the input was not consumed incrementally");
    eprintln!(
        "V3 jsonl: record={RECORD} bytes, chunk={CHUNK}, reads={}, largest={largest}, wall={:?}, rss_kib={:?}",
        source.chunks.len(),
        elapsed,
        resident_set_kib()
    );
}

#[test]
fn streaming_scan_of_a_32_mib_document_stays_bounded() {
    const DOCUMENT: u64 = 32 * 1024 * 1024;
    const CHUNK: usize = 4096;
    let mut source = GeneratedInput::document(DOCUMENT, CHUNK);

    let started = Instant::now();
    let (frames, summary) = drain(FramingStream::new(&mut source, SourceFormat::JsonDocument));
    let elapsed = started.elapsed();

    assert_eq!(frames.len(), 1);
    assert_eq!((frames[0].locator().byte_start, frames[0].locator().byte_end), (0, DOCUMENT));
    assert_eq!(*frames[0].raw_sha256(), generated_digest(b'{', DOCUMENT));
    assert_eq!(summary.byte_len, DOCUMENT);
    assert_eq!(summary.records, 1);
    assert_eq!(summary.blank_lines, 0);
    assert!(summary.complete);

    let largest = source.chunks.iter().copied().max().expect("the reader was polled");
    assert!(largest <= CHUNK, "the largest read request was {largest} bytes");
    eprintln!(
        "V3 document: bytes={DOCUMENT}, chunk={CHUNK}, reads={}, largest={largest}, wall={:?}, rss_kib={:?}",
        source.chunks.len(),
        elapsed,
        resident_set_kib()
    );
}

// =============================================================================
// V4 — injected read failures
// =============================================================================

#[test]
fn injected_read_failures_are_structured_and_never_complete() {
    let data = b"{\"n\":1}\n{\"n\":2}\n{\"n\":3}\r\nlast".to_vec();
    assert_eq!(data.len(), 29);
    // The reader hands out four bytes at a time, so these offsets are real
    // chunk boundaries: the first read, mid-record, between the carriage return
    // and the line feed of the CRLF, and four bytes before the end. (A chunk
    // ends early whenever it contains a terminator, which is why the last
    // boundary the scan asks at is 25 and not 28.)
    for (label, fail_at) in [("first read", 0usize), ("mid record", 4), ("between cr and lf", 24), ("before the end", 25)] {
        let source = ScriptedSource::failing(data.clone(), 4, fail_at, io::ErrorKind::Other);
        let mut scan = FramingStream::new(source, SourceFormat::Jsonl);
        let err = first_error(&mut scan);
        assert!(
            matches!(err, SourceInstallError::Io { kind: io::ErrorKind::Other, stage: "framing-read" }),
            "{label}: {err}"
        );
        let text = err.to_string();
        assert!(text.contains("framing-read"), "{label}: {text}");
        assert!(!text.contains("\"n\""), "{label}: the error must not carry input bytes: {text}");
        assert!(!scan.finish().complete, "{label}: a failed scan must not report completion");
    }
}

#[test]
fn interrupted_reads_are_retried_not_reported() {
    let data = b"{\"n\":1}\n{\"n\":2}\n".to_vec();
    let reference = reference_framing(&data, SourceFormat::Jsonl);
    let source = ScriptedSource::interrupting(data.clone(), 3, 3);
    let (frames, summary) = drain(FramingStream::new(source, SourceFormat::Jsonl));
    assert_frames("interrupted", &frames, &reference.frames);
    assert_summary("interrupted", &summary, &reference);
}

#[test]
fn eof_is_told_apart_from_a_read_error() {
    let data = b"{\"n\":1}\n".to_vec();

    // A quiet end of input is a successful, complete scan.
    let (_, summary) = drain(FramingStream::new(ScriptedSource::plain(data.clone(), 4), SourceFormat::Jsonl));
    assert!(summary.complete);
    assert_eq!(summary.records, 1);

    // A failure at the very same position is not an end of input.
    let mut scan = FramingStream::new(ScriptedSource::failing(data, 4, 0, io::ErrorKind::ConnectionReset), SourceFormat::Jsonl);
    let err = first_error(&mut scan);
    assert!(matches!(err, SourceInstallError::Io { kind: io::ErrorKind::ConnectionReset, .. }), "{err}");
    let summary = scan.finish();
    assert!(!summary.complete);
    assert_eq!(summary.records, 0);
}

// =============================================================================
// V5 — the verifier's file-stream entry
// =============================================================================

fn builtin_four_arrays() -> ExcludedContextPaths {
    toml::from_str(include_str!("../config/excluded_context_paths.toml")).expect("the built-in configuration parses")
}

fn safety_config() -> SourceSafetyConfig {
    SourceSafetyConfig {
        code_version: "test/1".to_string(),
        desensitization_enabled: true,
        config_source_identity: "config/excluded_context_paths.toml".to_string(),
        fixed_config_bytes: include_bytes!("../config/excluded_context_paths.toml").to_vec(),
        effective_four_arrays: builtin_four_arrays(),
    }
}

const CONTEXT_JSON: &[u8] = br#"{"connector":"claude","schema":"cass.source-parser-context/1"}"#;

fn declaration_for(sealed: &[u8]) -> SourceInputDeclaration {
    let context = LosslessSourceValue::parse(CONTEXT_JSON).expect("context json");
    let context_hex = context_digest(&context).expect("context digest").hex();
    let sealed_hex = Sha256Digest::of(sealed).hex();
    SourceInputDeclaration {
        identity_tuple: vec![
            Some("cass.source-input/2".to_string()),
            Some("ns".to_string()),
            Some("local".to_string()),
            Some("claude".to_string()),
            Some("root".to_string()),
            Some("relative.jsonl".to_string()),
            Some("user".to_string()),
            None,
            None,
            None,
            None,
            Some(context_hex),
            Some(sealed_hex),
            Some("normalizer/1".to_string()),
            Some("safety-contract/1".to_string()),
        ],
        identity_namespace: "ns".to_string(),
        source_id: "local".to_string(),
        connector: "claude".to_string(),
        origin_kind: None,
        origin_host: None,
        origin_source_version: None,
        role: Some("user".to_string()),
        platform: None,
        root_id: "root".to_string(),
        relative_locator: "relative.jsonl".to_string(),
        discovery: LosslessSourceValue::parse(br#"{"a":1}"#).expect("json"),
        parser_context: context,
        sealed_ref: LosslessSourceValue::parse(br#"{"c":3}"#).expect("json"),
        format: SourceFormat::Jsonl,
        normalizer_id: "normalizer/1".to_string(),
        safety_contract_id: "safety-contract/1".to_string(),
    }
}

#[test]
fn the_verify_reader_entry_matches_verify_field_for_field() {
    let sealed = b"{\"n\":1}\n\n{\"n\":2}\r\nx".to_vec();
    let (slice_input, slice_summary) =
        VerifiedSourceInput::verify(declaration_for(&sealed), &sealed, &safety_config()).expect("verify");
    let (reader_input, reader_summary) =
        VerifiedSourceInput::verify_reader(declaration_for(&sealed), Cursor::new(sealed.clone()), &safety_config())
            .expect("verify_reader");

    assert_eq!(slice_input.input_key(), reader_input.input_key());
    assert_eq!(slice_input.identity_tuple(), reader_input.identity_tuple());
    assert_eq!(slice_input.expected_records(), reader_input.expected_records());
    assert_eq!(slice_input.expected_blank_lines(), reader_input.expected_blank_lines());

    // The manifest header — the bounded, versioned artefact persisted as
    // `expected_manifest_bin` — is byte-for-byte the same, and so is its digest.
    assert_eq!(slice_input.manifest(), reader_input.manifest());
    assert_eq!(
        encode_expected_manifest_header(slice_input.manifest(), slice_input.safety_identity()),
        encode_expected_manifest_header(reader_input.manifest(), reader_input.safety_identity())
    );
    assert_eq!(
        expected_manifest_digest(slice_input.manifest(), slice_input.safety_identity()),
        expected_manifest_digest(reader_input.manifest(), reader_input.safety_identity())
    );
    assert_eq!(slice_input.safety_identity(), reader_input.safety_identity());

    // Every summary field agrees.
    assert_eq!(slice_summary, reader_summary);

    // A chunked reader forces different internal boundaries and still agrees.
    let (chunked_input, chunked_summary) = VerifiedSourceInput::verify_reader(
        declaration_for(&sealed),
        ChunkedSource::new(sealed.clone(), 3),
        &safety_config(),
    )
    .expect("verify_reader over a chunked reader");
    assert_eq!(chunked_input.manifest(), slice_input.manifest());
    assert_eq!(chunked_input.safety_identity(), slice_input.safety_identity());
    assert_eq!(chunked_summary, slice_summary);
}

#[test]
fn the_verify_reader_entry_refuses_bad_identity_safety_and_io() {
    let sealed = b"{\"n\":1}\n".to_vec();

    // A declaration whose identity tuple names other bytes than the reader gave.
    let mut wrong = declaration_for(&sealed);
    wrong.identity_tuple[12] = Some(Sha256Digest::of(b"other").hex());
    let err = VerifiedSourceInput::verify_reader(wrong, Cursor::new(sealed.clone()), &safety_config())
        .expect_err("a mismatched sealed digest must be refused");
    assert!(matches!(err, SourceInstallError::Conflict { .. }), "{err}");

    // Desensitisation off: both entries refuse.
    let mut off = safety_config();
    off.desensitization_enabled = false;
    let err = VerifiedSourceInput::verify_reader(declaration_for(&sealed), Cursor::new(sealed.clone()), &off)
        .expect_err("desensitisation off must be refused");
    assert!(matches!(err, SourceInstallError::Activation { .. }), "{err}");
    let err = VerifiedSourceInput::verify(declaration_for(&sealed), &sealed, &off)
        .expect_err("desensitisation off must be refused");
    assert!(matches!(err, SourceInstallError::Activation { .. }), "{err}");

    // A fixed configuration copy that is not TOML, and one that parses but
    // disagrees with the effective arrays.
    let mut broken = safety_config();
    broken.fixed_config_bytes = b"this is not toml [".to_vec();
    let err = VerifiedSourceInput::verify_reader(declaration_for(&sealed), Cursor::new(sealed.clone()), &broken)
        .expect_err("unparseable configuration must be refused");
    assert!(matches!(err, SourceInstallError::Conflict { .. }), "{err}");

    let mut disagreeing = safety_config();
    disagreeing.fixed_config_bytes = b"workspace_scoped_files = [\"other.md\"]\n".to_vec();
    let err = VerifiedSourceInput::verify_reader(declaration_for(&sealed), Cursor::new(sealed.clone()), &disagreeing)
        .expect_err("a configuration that disagrees with the effective arrays must be refused");
    assert!(matches!(err, SourceInstallError::Conflict { .. }), "{err}");

    // A read failure can never be promoted into a verified input.
    let err = VerifiedSourceInput::verify_reader(
        declaration_for(&sealed),
        ScriptedSource::failing(sealed.clone(), 4, 0, io::ErrorKind::Other),
        &safety_config(),
    )
    .expect_err("a read failure must not produce a verified input");
    assert!(matches!(err, SourceInstallError::Io { .. }), "{err}");
}

// =============================================================================
// V1 (rework): the same bytes, read from a real file instead of a slice
// =============================================================================

/// Write one synthetic fixture into the private temporary directory.
fn write_fixture(dir: &Path, name: &str, bytes: &[u8]) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, bytes).expect("the synthetic fixture must be writable");
    path
}

/// Frame one real file through a `BufReader` of the given capacity.
///
/// Every call opens the file itself, so each capacity reaches the engine
/// through a freshly opened file descriptor rather than a replayed cursor.
fn drain_real_file(
    path: &Path,
    capacity: usize,
    format: SourceFormat,
) -> (Vec<FramedSourceRecord>, FramingSummary) {
    let file = File::open(path).expect("the synthetic fixture must be readable");
    let reader = BufReader::with_capacity(capacity, file);
    drain(FramingStream::new(reader, format))
}

fn assert_frames_equal(label: &str, got: &[FramedSourceRecord], want: &[FramedSourceRecord]) {
    assert_eq!(got.len(), want.len(), "{label}: frame count");
    for (index, (got, want)) in got.iter().zip(want).enumerate() {
        assert_eq!(got.locator(), want.locator(), "{label}: frame {index} locator");
        assert_eq!(got.raw_sha256(), want.raw_sha256(), "{label}: frame {index} raw digest");
    }
}

#[test]
fn a_real_file_frames_the_same_bytes_as_the_reference_and_the_in_memory_path() {
    let dir = TempDir::new().expect("a private temporary directory");
    let fixtures: Vec<(&str, Vec<u8>)> = vec![
        ("crlf.jsonl", b"{\"n\":1}\r\n{\"n\":2}\r\n".to_vec()),
        ("no-final-lf.jsonl", b"{\"n\":1}\n{\"n\":2}".to_vec()),
        ("blanks.jsonl", b"a\n\n \t\n\r\nb\n".to_vec()),
        ("mixed.jsonl", b"a\r\n\r\nb\nc\rd\n".to_vec()),
    ];
    for (name, bytes) in fixtures {
        let path = write_fixture(dir.path(), name, &bytes);
        let reference = reference_framing(&bytes, SourceFormat::Jsonl);
        let (memory_frames, memory_summary) =
            drain(FramingStream::new(Cursor::new(bytes.as_slice()), SourceFormat::Jsonl));

        // A capacity of one byte puts every carriage return and line feed on
        // its own read; 4096 is the more ordinary buffered case.
        for capacity in [1usize, 4096] {
            let label = format!("{name}/bufreader={capacity}");
            let (frames, summary) = drain_real_file(&path, capacity, SourceFormat::Jsonl);
            assert_frames(&label, &frames, &reference.frames);
            assert_summary(&label, &summary, &reference);
            assert_frames_equal(&format!("{label}/vs-memory"), &frames, &memory_frames);
            assert_eq!(summary, memory_summary, "{label}: summary against the in-memory path");
        }
    }
}

#[test]
fn a_real_file_document_and_an_empty_file_keep_the_original_format_behaviour() {
    let dir = TempDir::new().expect("a private temporary directory");

    // A JSON document is one frame covering the whole file, carriage returns
    // and line feeds included.
    let document = b"{\"a\":1}\r\n{\"b\":2}\n".to_vec();
    let document_path = write_fixture(dir.path(), "document.json", &document);
    let reference = reference_framing(&document, SourceFormat::JsonDocument);
    for capacity in [1usize, 4096] {
        let label = format!("document/bufreader={capacity}");
        let (frames, summary) = drain_real_file(&document_path, capacity, SourceFormat::JsonDocument);
        assert_frames(&label, &frames, &reference.frames);
        assert_summary(&label, &summary, &reference);
    }

    // An empty JSONL file has no physical line at all.
    let empty = write_fixture(dir.path(), "empty.jsonl", b"");
    for capacity in [1usize, 4096] {
        let (frames, summary) = drain_real_file(&empty, capacity, SourceFormat::Jsonl);
        assert!(frames.is_empty(), "an empty JSONL file yields no record");
        assert_eq!(summary.records, 0);
        assert_eq!(summary.blank_lines, 0);
        assert_eq!(summary.byte_len, 0);
        assert!(summary.complete);
    }

    // An empty document is still one empty frame, as the slice path reports.
    let (frames, summary) = drain_real_file(&empty, 1, SourceFormat::JsonDocument);
    assert_eq!(frames.len(), 1);
    assert_eq!(frames[0].locator().ordinal, 1);
    assert_eq!((frames[0].locator().byte_start, frames[0].locator().byte_end), (0, 0));
    assert_eq!(*frames[0].raw_sha256(), Sha256Digest::of(b""));
    assert_eq!(summary.records, 1);
    assert_eq!(summary.byte_len, 0);
    assert!(summary.complete);

    // A blank-only JSONL file is zero records and nothing but blank lines.
    let blanks = write_fixture(dir.path(), "blank-only.jsonl", b"\n \t\n\r\n");
    let (frames, summary) = drain_real_file(&blanks, 1, SourceFormat::Jsonl);
    assert!(frames.is_empty(), "a blank-only JSONL file yields no record");
    assert_eq!(summary.blank_lines, 3);
    assert_eq!(summary.records, 0);
    assert!(summary.complete);
}

#[test]
fn verify_reader_over_a_real_file_matches_verify_and_the_manifest_header() {
    let dir = TempDir::new().expect("a private temporary directory");
    let bytes = b"{\"n\":1}\r\n\r\n{\"n\":2}\n{\"n\":3}".to_vec();
    let path = write_fixture(dir.path(), "sealed.jsonl", &bytes);

    let (memory_input, memory_summary) =
        VerifiedSourceInput::verify(declaration_for(&bytes), &bytes, &safety_config()).expect("verify");
    assert_eq!(memory_summary.records, 3);
    assert_eq!(memory_summary.blank_lines, 1);

    for capacity in [1usize, 4096] {
        let label = format!("real-file/bufreader={capacity}");
        // The file is opened here, consumed, and closed at the end of the
        // iteration; the next capacity opens it again through the same entry.
        let file = File::open(&path).expect("the fixture must be readable");
        let reader = BufReader::with_capacity(capacity, file);
        let (input, summary) =
            VerifiedSourceInput::verify_reader(declaration_for(&bytes), reader, &safety_config())
                .expect("verify_reader over a real file");

        assert_eq!(input.input_key(), memory_input.input_key(), "{label}: input key");
        assert_eq!(input.identity_tuple(), memory_input.identity_tuple(), "{label}: identity tuple");
        assert_eq!(input.manifest(), memory_input.manifest(), "{label}: manifest");
        assert_eq!(input.safety_identity(), memory_input.safety_identity(), "{label}: safety identity");
        assert_eq!(
            encode_expected_manifest_header(input.manifest(), input.safety_identity()),
            encode_expected_manifest_header(memory_input.manifest(), memory_input.safety_identity()),
            "{label}: manifest header bytes"
        );
        assert_eq!(
            expected_manifest_digest(input.manifest(), input.safety_identity()),
            expected_manifest_digest(memory_input.manifest(), memory_input.safety_identity()),
            "{label}: manifest header digest"
        );
        assert_eq!(summary, memory_summary, "{label}: summary");
    }
}
