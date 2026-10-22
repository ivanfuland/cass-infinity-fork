//! Direct subprocess execution of the companion CASS binary, plus the fixed
//! result and error mapping.
//!
//! One [`Runner`] is shared by every SDK session, and it owns the one
//! [`Admission`] pool for the whole service. It never uses a shell: each
//! argument is one argv element, `stdin` is closed, inherited `CASS_*`
//! variables are removed for the child, and `CASS_DATA_DIR` is set to the
//! configured directory.

use std::ffi::OsString;
use std::path::PathBuf;
use std::process::{ExitStatus, Stdio};
use std::sync::Arc;
use std::time::Duration;

use quick_xml::events::Event;
use quick_xml::{Reader, XmlVersion};
use serde_json::Value;
use tokio::io::AsyncReadExt;
use tokio::process::{Child, ChildStderr, ChildStdout, Command};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

use crate::admission::{Admission, AdmissionOutcome, Permit, Waiter};
use crate::config::Config;
use crate::tools::{FixedProfiles, RecallTool, ToolCall};

/// The fixed chunk size used to read both pipes. It never depends on the
/// configured budget, so a large budget does not pre-allocate a large buffer.
const READ_CHUNK_BYTES: usize = 8 * 1024;

/// A tool-level failure, rendered as the only content of an `isError` result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ToolError {
    pub code: &'static str,
    pub message: String,
    pub cli_exit_code: Option<i32>,
}

pub const INVALID_ARGUMENT: &str = "invalid_argument";
pub const IDENTITY_UNAVAILABLE: &str = "identity_unavailable";
pub const STALE_REFERENCE: &str = "stale_reference";
pub const MODEL_UNAVAILABLE: &str = "model_unavailable";
pub const INVALID_RECALL: &str = "invalid_recall";
pub const CASS_EXIT: &str = "cass_exit";
pub const RESULT_TOO_LARGE: &str = "result_too_large";
pub const BUSY: &str = "busy";
pub const CANCELLED: &str = "cancelled";
pub const TIMEOUT: &str = "deadline_exceeded";

impl ToolError {
    pub fn result_too_large(message: impl Into<String>) -> Self {
        Self {
            code: RESULT_TOO_LARGE,
            message: message.into(),
            cli_exit_code: None,
        }
    }

    /// The SDK token was cancelled before this request's result could be
    /// published. The SDK may terminate such a request without any tool result
    /// (C4); the internal terminal state and the child reaping are unaffected.
    pub fn cancelled() -> Self {
        Self {
            code: CANCELLED,
            message: "the request was cancelled before its result was published".to_string(),
            cli_exit_code: None,
        }
    }

    /// The fixed total deadline elapsed before this request's result could be
    /// published.
    pub fn timeout() -> Self {
        Self {
            code: TIMEOUT,
            message: "the request deadline elapsed before its result was published".to_string(),
            cli_exit_code: None,
        }
    }

    /// The pool and its bounded queue are both full. No child is created.
    pub fn busy(message: impl Into<String>) -> Self {
        Self {
            code: BUSY,
            message: message.into(),
            cli_exit_code: None,
        }
    }

    pub fn invalid_argument(message: impl Into<String>) -> Self {
        Self {
            code: INVALID_ARGUMENT,
            message: message.into(),
            cli_exit_code: None,
        }
    }

    pub fn invalid_recall(message: impl Into<String>) -> Self {
        Self {
            code: INVALID_RECALL,
            message: message.into(),
            cli_exit_code: None,
        }
    }

    /// The JSON text of the single top-level `error` object. It carries only
    /// the fixed code, a short message naming the rule that failed, and the
    /// real CLI exit status when one exists.
    pub fn to_json(&self) -> String {
        self.render(true, true)
    }

    /// The same error body with the optional fields removed in the fixed
    /// order: the message first, then the CLI exit status. The code, the
    /// `isError` flag, and the single text block are always kept.
    pub fn render(&self, include_message: bool, include_exit: bool) -> String {
        let mut error = serde_json::Map::new();
        error.insert("code".to_string(), Value::String(self.code.to_string()));
        if include_message {
            error.insert("message".to_string(), Value::String(self.message.clone()));
        }
        if include_exit && let Some(code) = self.cli_exit_code {
            error.insert("cli_exit_code".to_string(), Value::from(code));
        }
        serde_json::json!({ "error": Value::Object(error) }).to_string()
    }
}

/// The one lifecycle control for a request.
///
/// The token is the SDK's own `RequestContext.ct` (a standard
/// [`CancellationToken`]), and the deadline is fixed once, from the instant the
/// handler received the call. The same value travels through admission, the
/// waiting queue, the supervised child and the final publication; it is never
/// recomputed on a dequeue, a hand-over, a retry or a session change.
#[derive(Clone, Debug)]
pub(crate) struct RequestControl {
    ct: CancellationToken,
    deadline: Instant,
}

/// The reason a request must not publish a success, in the fixed order:
/// explicit cancellation first, then the total deadline. (C10)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Overdue {
    Cancelled,
    TimedOut,
}

impl RequestControl {
    fn new(ct: CancellationToken, received: Instant, timeout: Duration) -> Self {
        Self {
            ct,
            // `checked_add` can only fail for a duration no fixed timeout can
            // reach; such a request must fail closed, at once, rather than run
            // without a bound.
            deadline: received.checked_add(timeout).unwrap_or(received),
        }
    }

    /// The first event that is already observable at this decision point.
    /// Cancellation outranks the deadline; both outrank an overflow, a non-zero
    /// exit, a format error and a success.
    fn overdue(&self) -> Option<Overdue> {
        if self.ct.is_cancelled() {
            return Some(Overdue::Cancelled);
        }
        if Instant::now() >= self.deadline {
            return Some(Overdue::TimedOut);
        }
        None
    }

    /// The failure a caller must publish instead of a pending success. Every
    /// decision point that could publish a success calls this at its own last
    /// synchronous moment.
    pub(crate) fn observed_failure(&self) -> Option<ToolError> {
        self.overdue().map(Overdue::into_error)
    }

    /// The absolute deadline fixed at the receipt of the call. Only the
    /// paused-clock units read it, to prove that a queue delay or a hand-over
    /// never moves it.
    #[cfg(test)]
    fn deadline(&self) -> Instant {
        self.deadline
    }
}

impl Overdue {
    fn into_error(self) -> ToolError {
        match self {
            Self::Cancelled => ToolError::cancelled(),
            Self::TimedOut => ToolError::timeout(),
        }
    }

    fn into_supervised(self) -> Supervised {
        match self {
            Self::Cancelled => Supervised::Cancelled,
            Self::TimedOut => Supervised::TimedOut,
        }
    }
}

/// The fixed startup values every call reuses, plus the one shared pool.
#[derive(Debug)]
pub struct Runner {
    cass_bin: PathBuf,
    data_dir: PathBuf,
    api_config: PathBuf,
    embedding_profile: String,
    rerank_profile: String,
    max_output_bytes: usize,
    terminate_grace: Duration,
    request_timeout: Duration,
    admission: Arc<Admission>,
}

impl Runner {
    pub fn new(config: &Config) -> Self {
        Self {
            cass_bin: config.cass_bin.clone(),
            data_dir: config.data_dir.clone(),
            api_config: config.api_config.clone(),
            embedding_profile: config.embedding_profile.clone(),
            rerank_profile: config.rerank_profile.clone(),
            max_output_bytes: config.max_output_bytes,
            terminate_grace: Duration::from_millis(config.terminate_grace_ms),
            request_timeout: Duration::from_millis(config.request_timeout_ms),
            admission: Admission::new(config.max_concurrent, config.max_queued),
        }
    }

    /// Fix the one lifecycle control for a call, from the instant the handler
    /// received it. The deadline is absolute from that instant.
    pub(crate) fn control(&self, ct: CancellationToken, received: Instant) -> RequestControl {
        RequestControl::new(ct, received, self.request_timeout)
    }

    /// Run one validated call. On success the returned string is the
    /// unmodified CLI stdout, already proven to be a legal C04 envelope for
    /// this tool. On failure it is a fixed tool error.
    ///
    /// Every request asks the one service-wide pool first: it either takes a
    /// slot, is registered in the bounded queue in arrival order, or is refused
    /// with `busy` before any child exists. One supervising task owns the
    /// child, both pipes, the combined byte count, the `wait` and the permit;
    /// the caller only awaits its result. Dropping the caller's future
    /// therefore never drops the child, its reaping duty, or an active slot.
    ///
    /// `control` is the one lifecycle value for the whole request: the same
    /// token and the same absolute deadline are used before admission, while
    /// waiting, while the child runs, and at the final publication.
    pub async fn run(
        &self,
        tool: RecallTool,
        call: &ToolCall,
        control: RequestControl,
    ) -> Result<String, ToolError> {
        let profiles = FixedProfiles {
            api_config: &self.api_config,
            embedding_profile: &self.embedding_profile,
            rerank_profile: &self.rerank_profile,
        };
        let argv = call.argv(&profiles);

        // A valid request is checked before it can take a queue position or
        // start a child.
        if let Some(error) = control.observed_failure() {
            return Err(error);
        }

        let permit = match self.admission.enter() {
            AdmissionOutcome::Running(permit) => permit,
            AdmissionOutcome::Queued(waiter) => wait_for_slot(&control, waiter).await?,
            AdmissionOutcome::Busy => {
                return Err(ToolError::busy(
                    "the execution pool and its waiting queue are both full",
                ));
            }
        };

        // Between the grant and the spawn the same control is checked again: an
        // already cancelled or expired request returns the slot without
        // creating a child.
        if let Some(error) = control.observed_failure() {
            drop(permit);
            return Err(error);
        }

        self.run_admitted(tool, argv, permit, control).await
    }

    /// Run one call that already owns a slot. The permit travels with the
    /// child: a failed spawn or a failed pipe setup drops it here, and once a
    /// child exists it belongs to the supervising task until `wait` returns.
    async fn run_admitted(
        &self,
        tool: RecallTool,
        argv: Vec<OsString>,
        permit: Permit,
        control: RequestControl,
    ) -> Result<String, ToolError> {
        let mut command = Command::new(&self.cass_bin);
        command
            .args(argv.iter().map(OsString::as_os_str))
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        // Remove inherited CASS_* values from the child only. The parent
        // process environment is untouched.
        for (key, _) in std::env::vars_os() {
            if key.to_string_lossy().starts_with("CASS_") {
                command.env_remove(key);
            }
        }
        command.env("CASS_DATA_DIR", &self.data_dir);

        let mut child = command
            .spawn()
            .map_err(|_| cass_exit("the companion CASS binary could not be started", None))?;

        let (Some(stdout), Some(stderr)) = (child.stdout.take(), child.stderr.take()) else {
            reap(&mut child, self.terminate_grace).await;
            return Err(cass_exit(
                "the companion CASS binary output could not be captured",
                None,
            ));
        };

        let supervised = tokio::spawn(supervise_holding(
            permit,
            control,
            child,
            stdout,
            stderr,
            self.max_output_bytes,
            self.terminate_grace,
        ))
        .await
        .map_err(|_| cass_exit("the companion CASS binary could not be supervised", None))?;

        let (stdout, stderr, status) = match supervised {
            Supervised::Captured {
                stdout,
                stderr,
                status,
            } => (stdout, stderr, status),
            Supervised::TooLarge => {
                return Err(ToolError::result_too_large(
                    "the companion binary output exceeded the configured byte budget",
                ));
            }
            Supervised::ReadFailed => {
                return Err(cass_exit(
                    "the companion binary output could not be read",
                    None,
                ));
            }
            // Both were already decided inside the supervising task, after its
            // own child was terminated and waited for.
            Supervised::Cancelled => return Err(ToolError::cancelled()),
            Supervised::TimedOut => return Err(ToolError::timeout()),
        };

        if !status.success() {
            let code = status.code();
            return Err(classify_exit(&stderr, code));
        }

        let stdout = std::str::from_utf8(&stdout)
            .map_err(|_| ToolError::invalid_recall("CLI stdout is not valid UTF-8"))?;
        decode_recall(stdout, tool)?;
        Ok(stdout.to_string())
    }
}

/// What one supervised exchange produced. A too-large or unreadable child is
/// always reaped before this value is returned.
enum Supervised {
    Captured {
        stdout: Vec<u8>,
        stderr: Vec<u8>,
        status: ExitStatus,
    },
    TooLarge,
    ReadFailed,
    /// The SDK token was cancelled while this request still owned the child.
    Cancelled,
    /// The fixed total deadline elapsed while this request still owned the
    /// child.
    TimedOut,
}

/// Wait for the queue position to be granted, giving the already-observable
/// cancellation and deadline priority over the grant.
///
/// All three branches can be ready in the same observation; `biased` picks the
/// cancellation, then the deadline, then the grant. When a later branch loses,
/// its future is dropped, which returns the queue position — or an
/// already-granted but unclaimed slot — exactly once through the existing
/// [`Waiter`] cleanup. The FIFO order itself is unchanged.
async fn wait_for_slot(control: &RequestControl, waiter: Waiter) -> Result<Permit, ToolError> {
    tokio::select! {
        biased;
        _ = control.ct.cancelled() => Err(ToolError::cancelled()),
        _ = tokio::time::sleep_until(control.deadline) => Err(ToolError::timeout()),
        permit = waiter.wait() => Ok(permit),
    }
}

/// Own the admission slot for exactly as long as this task owns the child.
///
/// The permit is moved into the same task that holds the child and its `wait`,
/// so it is released only after [`supervise`] returns — which it does only
/// after `wait` reported. Dropping the caller's future detaches this task and
/// cannot free the slot while the child is still running or being reaped.
async fn supervise_holding(
    permit: Permit,
    control: RequestControl,
    child: Child,
    stdout: ChildStdout,
    stderr: ChildStderr,
    budget: usize,
    grace: Duration,
) -> Supervised {
    let outcome = supervise(child, stdout, stderr, budget, grace, &control).await;
    drop(permit);
    outcome
}

/// Own the child until both pipes reach EOF and `wait` reports. Every byte
/// stored on either stream counts against the same budget; the first chunk
/// that would cross it stops both reads and moves straight to reaping. Each
/// read requests at most the remaining budget plus one probe byte, so a small
/// remaining budget never consumes a full chunk beyond it. A non-zero exit
/// observed in the same window never overrides the overflow.
///
/// Cancellation and the total deadline are observed in the same loop, with the
/// fixed priority `cancel > deadline > overflow > exit > format > success`.
/// Once a failure is decided it is never rewritten by a later event: the
/// reaping below already belongs to that one terminal state.
async fn supervise(
    mut child: Child,
    mut stdout: ChildStdout,
    mut stderr: ChildStderr,
    budget: usize,
    grace: Duration,
    control: &RequestControl,
) -> Supervised {
    let mut captured_stdout = Vec::new();
    let mut captured_stderr = Vec::new();
    let mut stdout_buffer = [0u8; READ_CHUNK_BYTES];
    let mut stderr_buffer = [0u8; READ_CHUNK_BYTES];
    let mut total = 0usize;
    let mut status: Option<ExitStatus> = None;
    let mut stdout_open = true;
    let mut stderr_open = true;
    let mut failure: Option<Supervised> = None;

    while stdout_open || stderr_open || status.is_none() {
        // `total <= budget` always holds. The extra byte is the only probe
        // allowed past the budget; the small buffer is reused, not resized.
        let want = (budget - total).saturating_add(1).min(READ_CHUNK_BYTES);
        tokio::select! {
            biased;
            // The first two branches give cancellation and the deadline the
            // fixed priority over every other event in the same observation.
            _ = control.ct.cancelled() => {
                failure = Some(Supervised::Cancelled);
                break;
            }
            _ = tokio::time::sleep_until(control.deadline) => {
                failure = Some(Supervised::TimedOut);
                break;
            }
            read = stdout.read(&mut stdout_buffer[..want]), if stdout_open => {
                match read {
                    Ok(0) => stdout_open = false,
                    Ok(n) => match reserve(budget, total, n) {
                        Some(next) => {
                            captured_stdout.extend_from_slice(&stdout_buffer[..n]);
                            total = next;
                        }
                        None => {
                            failure = Some(Supervised::TooLarge);
                            break;
                        }
                    },
                    Err(_) => {
                        failure = Some(Supervised::ReadFailed);
                        break;
                    }
                }
            }
            read = stderr.read(&mut stderr_buffer[..want]), if stderr_open => {
                match read {
                    Ok(0) => stderr_open = false,
                    Ok(n) => match reserve(budget, total, n) {
                        Some(next) => {
                            captured_stderr.extend_from_slice(&stderr_buffer[..n]);
                            total = next;
                        }
                        None => {
                            failure = Some(Supervised::TooLarge);
                            break;
                        }
                    },
                    Err(_) => {
                        failure = Some(Supervised::ReadFailed);
                        break;
                    }
                }
            }
            waited = child.wait(), if status.is_none() => {
                match waited {
                    Ok(observed) => status = Some(observed),
                    Err(_) => {
                        failure = Some(Supervised::ReadFailed);
                        break;
                    }
                }
            }
        }
    }

    // Close the read ends first so a flooding child cannot keep the pipes
    // alive, then reap whatever is still running.
    drop(stdout);
    drop(stderr);

    if let Some(failure) = failure {
        reap(&mut child, grace).await;
        return failure;
    }

    // Nothing is determined yet: this is the supervisor's last decision point.
    // A cancellation or an elapsed deadline that is already observable here
    // replaces the pending success; `wait` still has to report before the
    // permit is dropped.
    if let Some(overdue) = control.overdue() {
        reap(&mut child, grace).await;
        return overdue.into_supervised();
    }

    match status {
        Some(status) => Supervised::Captured {
            stdout: captured_stdout,
            stderr: captured_stderr,
            status,
        },
        None => {
            reap(&mut child, grace).await;
            Supervised::ReadFailed
        }
    }
}

/// Admit `n` bytes to the stored total, or signal that this chunk would cross
/// the budget. No partial chunk is ever stored.
fn reserve(budget: usize, total: usize, n: usize) -> Option<usize> {
    let remaining = budget - total;
    (n <= remaining).then_some(total + n)
}

/// Terminate only this request's own child: SIGTERM first, then a forced kill
/// after the configured grace, and `wait` before returning. A child that
/// already exited is simply waited for; nothing is killed by name or port.
async fn reap(child: &mut Child, grace: Duration) {
    if matches!(child.try_wait(), Ok(Some(_))) {
        return;
    }
    if let Some(pid) = child.id() {
        unsafe {
            libc::kill(pid as libc::pid_t, libc::SIGTERM);
        }
    }
    match tokio::time::timeout(grace, child.wait()).await {
        Ok(Ok(_)) => {}
        _ => {
            let _ = child.start_kill();
            let _ = child.wait().await;
        }
    }
}

fn cass_exit(message: &str, cli_exit_code: Option<i32>) -> ToolError {
    ToolError {
        code: CASS_EXIT,
        message: message.to_string(),
        cli_exit_code,
    }
}

/// Classify a non-zero CLI exit from the complete JSON error envelope on
/// stderr. Only `error.kind` is read; stdout, stderr text, and the query are
/// never echoed to the caller.
fn classify_exit(stderr: &[u8], cli_exit_code: Option<i32>) -> ToolError {
    let Some(kind) = stderr_envelope_kind(stderr) else {
        return cass_exit(
            "the companion CASS binary exited unsuccessfully",
            cli_exit_code,
        );
    };
    let (code, message) = match kind.as_str() {
        "usage" => (
            INVALID_ARGUMENT,
            "the companion CLI rejected the call arguments",
        ),
        "identity_unavailable" => (
            IDENTITY_UNAVAILABLE,
            "the hit could not be matched to one indexed message",
        ),
        "stale_reference" => (
            STALE_REFERENCE,
            "the indexed message no longer has the expected content digest",
        ),
        "model_unavailable" => (
            MODEL_UNAVAILABLE,
            "the requested model search path was not applied",
        ),
        "recall_invalid" => (
            INVALID_RECALL,
            "the companion CLI could not form a legal recall result",
        ),
        _ => {
            return cass_exit(
                "the companion CASS binary exited unsuccessfully",
                cli_exit_code,
            );
        }
    };
    ToolError {
        code,
        message: message.to_string(),
        cli_exit_code,
    }
}

/// Read `error.kind` from a complete JSON error envelope. A partial object, a
/// missing `error` object, or any non-string kind yields `None`.
fn stderr_envelope_kind(stderr: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(stderr).ok()?.trim();
    let value: Value = serde_json::from_str(text).ok()?;
    let kind = value
        .get("error")
        .and_then(Value::as_object)?
        .get("kind")?
        .as_str()?;
    Some(kind.to_string())
}

/// Parse the entire C04 envelope, then its JSON payload, then the payload
/// shape. Any deviation is `invalid_recall`; no partial body is forwarded.
fn decode_recall(input: &str, expected: RecallTool) -> Result<Value, ToolError> {
    let invalid = || ToolError::invalid_recall("CLI stdout is not a legal recall envelope");
    let mut reader = Reader::from_str(input);
    let mut state = 0; // before root, inside root, after root
    let mut json = String::new();
    loop {
        match reader.read_event().map_err(|_| invalid())? {
            Event::Start(root) if state == 0 && root.name().as_ref() == "cass_recall" => {
                let mut version = None;
                let mut tool = None;
                for attribute in root.attributes() {
                    let attribute = attribute.map_err(|_| invalid())?;
                    let value = attribute
                        .normalized_value(XmlVersion::Implicit1_0)
                        .map_err(|_| invalid())?
                        .into_owned();
                    match attribute.key.as_ref() {
                        "version" if version.is_none() => version = Some(value),
                        "tool" if tool.is_none() => tool = Some(value),
                        _ => return Err(invalid()),
                    }
                }
                if version.as_deref() != Some("1") || tool.as_deref() != Some(expected.name()) {
                    return Err(invalid());
                }
                state = 1;
            }
            Event::Text(text) => {
                let text = text.as_ref();
                if state == 1 {
                    json.push_str(text);
                } else if !text
                    .bytes()
                    .all(|b| matches!(b, b' ' | b'\t' | b'\r' | b'\n'))
                {
                    return Err(invalid());
                }
            }
            Event::GeneralRef(reference) if state == 1 => {
                if let Some(ch) = reference.resolve_char_ref().map_err(|_| invalid())? {
                    json.push(ch);
                } else {
                    let name = reference.as_ref();
                    json.push_str(match name {
                        "amp" => "&",
                        "lt" => "<",
                        "gt" => ">",
                        "quot" => "\"",
                        "apos" => "'",
                        _ => return Err(invalid()),
                    });
                }
            }
            Event::End(root) if state == 1 && root.name().as_ref() == "cass_recall" => state = 2,
            Event::Eof if state == 2 => break,
            _ => return Err(invalid()),
        }
    }
    let value: Value = serde_json::from_str(&json).map_err(|_| invalid())?;
    if !expected.accepts(&value) {
        return Err(invalid());
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use std::os::fd::AsFd;

    /// The combined read path may consume at most one probe byte beyond the
    /// budget, even when a single read could take far more. The duplicate read
    /// ends stay open across `supervise`, so what it left unread is measurable.
    #[tokio::test]
    async fn read_probe_consumes_at_most_budget_plus_one() {
        const WRITTEN: usize = 4096;
        const BUDGET: usize = 125;

        let dir = std::env::temp_dir().join(format!(
            "cass-mcp-read-probe-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("create probe dir");
        let ready = dir.join("ready");
        let chunk = "W".repeat(1024);
        let script = format!(
            "printf '%s' '{chunk}{chunk}{chunk}{chunk}'\n\
             printf '%s' '{chunk}{chunk}{chunk}{chunk}' >&2\n\
             : > '{ready}'\n\
             exec sleep 30\n",
            ready = ready.display(),
        );

        let mut child = Command::new("/bin/sh")
            .arg("-c")
            .arg(script)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .expect("spawn probing child");
        let mut ready_seen = false;
        for _ in 0..1000 {
            if ready.exists() {
                ready_seen = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(ready_seen, "probe child never finished writing");

        let stdout = child.stdout.take().expect("piped stdout");
        let stderr = child.stderr.take().expect("piped stderr");
        let stdout_probe = stdout.as_fd().try_clone_to_owned().expect("dup stdout");
        let stderr_probe = stderr.as_fd().try_clone_to_owned().expect("dup stderr");

        let control = RequestControl::new(
            CancellationToken::new(),
            Instant::now(),
            Duration::from_secs(60),
        );
        let outcome = supervise(
            child,
            stdout,
            stderr,
            BUDGET,
            Duration::from_millis(200),
            &control,
        )
        .await;
        assert!(
            matches!(outcome, Supervised::TooLarge),
            "the probe must classify the over-budget stream"
        );

        let mut stdout_left = Vec::new();
        std::fs::File::from(stdout_probe)
            .read_to_end(&mut stdout_left)
            .expect("read leftover stdout");
        let mut stderr_left = Vec::new();
        std::fs::File::from(stderr_probe)
            .read_to_end(&mut stderr_left)
            .expect("read leftover stderr");
        let consumed = (WRITTEN - stdout_left.len()) + (WRITTEN - stderr_left.len());
        println!("consumed={consumed} allowed={}", BUDGET + 1);

        assert!(
            consumed <= BUDGET + 1,
            "consumed {consumed} bytes; at most {} are allowed",
            BUDGET + 1
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Dropping the future that awaits the supervising task must not release
    /// the slot. The permit lives in the task that owns the child until `wait`
    /// returned, so an abandoned HTTP request can never free a slot while its
    /// child still runs.
    #[tokio::test]
    async fn dropping_the_outer_await_keeps_the_slot_until_the_child_is_waited() {
        use std::future::Future;
        use std::pin::Pin;
        use std::task::{Context, Poll, Waker};

        fn poll_once<F: Future>(future: Pin<&mut F>) -> Poll<F::Output> {
            let waker = Waker::noop();
            let mut context = Context::from_waker(waker);
            future.poll(&mut context)
        }

        let dir = std::env::temp_dir().join(format!(
            "cass-mcp-t14-own-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("create sandbox");
        let ready = dir.join("ready");
        let release = dir.join("release");
        let script = format!(
            "printf 'READY\\n' > '{ready}'\n\
             while [ ! -f '{release}' ]; do sleep 0.02; done\n\
             exit 0\n",
            ready = ready.display(),
            release = release.display(),
        );
        let mut child = Command::new("/bin/sh")
            .arg("-c")
            .arg(script)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .expect("spawn controlled child");
        let pid = child.id().expect("child pid");
        let stdout = child.stdout.take().expect("piped stdout");
        let stderr = child.stderr.take().expect("piped stderr");

        let admission = Admission::new(1, 1);
        let permit = match admission.enter() {
            AdmissionOutcome::Running(permit) => permit,
            _ => panic!("the first request must take the free slot"),
        };

        let control = RequestControl::new(
            CancellationToken::new(),
            Instant::now(),
            Duration::from_secs(60),
        );
        let handle = tokio::spawn(supervise_holding(
            permit,
            control,
            child,
            stdout,
            stderr,
            1024,
            Duration::from_millis(200),
        ));
        for _ in 0..1000 {
            if ready.exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(ready.exists(), "the controlled child never started");

        // Abandon the outer await, exactly like a dropped HTTP request future.
        drop(handle);

        // The slot is still taken: the next request may queue, never run.
        let waiter = match admission.enter() {
            AdmissionOutcome::Queued(waiter) => waiter,
            AdmissionOutcome::Running(_) => {
                panic!("dropping the outer await released an active slot")
            }
            AdmissionOutcome::Busy => panic!("a queue position was available"),
        };
        let mut waiting = Box::pin(waiter.wait());
        assert!(
            poll_once(waiting.as_mut()).is_pending(),
            "the slot must stay taken while the child runs"
        );

        // Only after the child exits and is waited may the slot come back.
        std::fs::write(&release, b"go").expect("release the controlled child");
        let permit = tokio::time::timeout(Duration::from_secs(10), waiting)
            .await
            .expect("the slot must be released once the child was waited");
        assert!(
            !std::path::Path::new("/proc").join(pid.to_string()).exists(),
            "the child must be waited before the slot is released"
        );
        drop(permit);
        assert_eq!(admission.counters(), (0, 0));
        let _ = std::fs::remove_dir_all(&dir);
    }

    // -----------------------------------------------------------------------
    // Ticket 15: the cancellation and deadline decision paths.
    //
    // These use a paused clock and the standard cancellation token, and they
    // call the production helpers (`RequestControl::observed_failure`,
    // `wait_for_slot`, `supervise`, `supervise_holding`) instead of a mirror
    // implementation. The end-to-end HTTP cases prove the same behaviour with
    // real sockets and real processes.
    // -----------------------------------------------------------------------

    /// Poll once with a waker that does nothing. Every step of the protocol is
    /// decided under the state lock or by the mock clock, so a single poll is
    /// enough to observe "pending" or "ready" without sleeping.
    fn poll_once<F: std::future::Future>(
        future: std::pin::Pin<&mut F>,
    ) -> std::task::Poll<F::Output> {
        let waker = std::task::Waker::noop();
        let mut context = std::task::Context::from_waker(waker);
        future.poll(&mut context)
    }

    fn take_running(outcome: AdmissionOutcome) -> Permit {
        match outcome {
            AdmissionOutcome::Running(permit) => permit,
            _ => panic!("expected an execution slot"),
        }
    }

    fn take_queued(outcome: AdmissionOutcome) -> Waiter {
        match outcome {
            AdmissionOutcome::Queued(waiter) => waiter,
            _ => panic!("expected a queue position"),
        }
    }

    /// Let the timer driver process every timer that is due. Each zero-length
    /// sleep is one more timer at the current instant, so awaiting it also
    /// processes the earlier ones.
    async fn drive_timers() {
        for _ in 0..4 {
            tokio::time::sleep(Duration::ZERO).await;
        }
    }

    /// Cancellation outranks the deadline, and both outrank a success that is
    /// only pending. Every candidate is already ready in the same observation.
    #[tokio::test]
    async fn cancellation_outranks_the_deadline_and_a_pending_success() {
        tokio::time::pause();
        let start = Instant::now();
        let token = CancellationToken::new();

        // Cancel and deadline both ready: the cancellation is chosen.
        let both = RequestControl::new(token.clone(), start, Duration::ZERO);
        token.cancel();
        assert_eq!(
            both.observed_failure().expect("a decided failure").code,
            CANCELLED
        );

        // Deadline only: the deadline is chosen, never a pending success.
        let expired = RequestControl::new(CancellationToken::new(), start, Duration::ZERO);
        assert_eq!(
            expired.observed_failure().expect("a decided failure").code,
            TIMEOUT
        );

        // Neither: a success may still be published.
        let pending =
            RequestControl::new(CancellationToken::new(), start, Duration::from_millis(100));
        assert!(pending.observed_failure().is_none());
    }

    /// A grant that is already ready loses to an elapsed deadline, and to a
    /// cancellation; the dropped waiter returns the slot exactly once.
    #[tokio::test]
    async fn a_grant_that_is_already_ready_loses_to_the_deadline_and_to_cancellation() {
        tokio::time::pause();

        // Deadline against a ready grant.
        let start = Instant::now();
        let admission = Admission::new(1, 1);
        let holder = take_running(admission.enter());
        let waiter = take_queued(admission.enter());
        let control =
            RequestControl::new(CancellationToken::new(), start, Duration::from_millis(100));
        let mut waiting = Box::pin(wait_for_slot(&control, waiter));
        assert!(poll_once(waiting.as_mut()).is_pending());
        drop(holder);
        assert_eq!(
            admission.counters(),
            (1, 0),
            "the slot is already handed to the waiter"
        );
        tokio::time::advance(Duration::from_millis(100)).await;
        // The registered sleep only becomes ready once the timer driver
        // processed it, so give the driver one pass before the next poll.
        drive_timers().await;
        match poll_once(waiting.as_mut()) {
            std::task::Poll::Ready(Err(error)) => assert_eq!(error.code, TIMEOUT),
            _ => panic!("the elapsed deadline must win over an already granted slot"),
        }
        assert_eq!(
            admission.counters(),
            (0, 0),
            "the unclaimed slot must be returned exactly once"
        );

        // Cancellation against a ready grant and an elapsed deadline.
        let start = Instant::now();
        let admission = Admission::new(1, 1);
        let holder = take_running(admission.enter());
        let waiter = take_queued(admission.enter());
        let token = CancellationToken::new();
        let control = RequestControl::new(token.clone(), start, Duration::from_millis(100));
        let mut waiting = Box::pin(wait_for_slot(&control, waiter));
        assert!(poll_once(waiting.as_mut()).is_pending());
        drop(holder);
        tokio::time::advance(Duration::from_millis(100)).await;
        token.cancel();
        match poll_once(waiting.as_mut()) {
            std::task::Poll::Ready(Err(error)) => assert_eq!(error.code, CANCELLED),
            _ => panic!("the cancellation must win over both the grant and the deadline"),
        }
        assert_eq!(
            admission.counters(),
            (0, 0),
            "a cancelled hand-over must not leak the slot or the queue position"
        );
    }

    /// A request that spends most of its budget waiting still carries the
    /// original absolute deadline into the supervision. The grant does not
    /// start a fresh budget.
    #[tokio::test]
    async fn a_queue_delay_does_not_reset_the_absolute_deadline() {
        tokio::time::pause();
        let start = Instant::now();
        let admission = Admission::new(1, 1);
        let holder = take_running(admission.enter());
        let waiter = take_queued(admission.enter());
        let control =
            RequestControl::new(CancellationToken::new(), start, Duration::from_millis(100));

        // 90 of the 100 ms are spent waiting before the grant exists.
        tokio::time::advance(Duration::from_millis(90)).await;
        drop(holder);
        let mut waiting = Box::pin(wait_for_slot(&control, waiter));
        let permit = match poll_once(waiting.as_mut()) {
            std::task::Poll::Ready(Ok(permit)) => permit,
            _ => panic!("the grant must be taken while the original deadline still holds"),
        };
        assert_eq!(
            control.deadline(),
            start + Duration::from_millis(100),
            "the grant must not have moved the deadline to the hand-over instant"
        );
        assert!(
            control.observed_failure().is_none(),
            "90 ms must still be inside the original deadline"
        );

        // Only ten of the original hundred milliseconds are left.
        tokio::time::advance(Duration::from_millis(9)).await;
        assert!(
            control.observed_failure().is_none(),
            "99 ms must still be inside the original deadline"
        );
        tokio::time::advance(Duration::from_millis(1)).await;
        assert_eq!(
            control.observed_failure().expect("a decided failure").code,
            TIMEOUT,
            "the grant must not have reset the deadline"
        );
        drop(permit);
        assert_eq!(admission.counters(), (0, 0));
    }

    /// A success that has not been published yet cannot be published after a
    /// cancellation or the deadline was observed, and the first observed
    /// reason does not change afterwards.
    #[tokio::test]
    async fn an_unpublished_success_yields_to_cancellation_and_to_the_deadline() {
        tokio::time::pause();
        let start = Instant::now();

        // Inside the budget: the pending success may be published.
        let control =
            RequestControl::new(CancellationToken::new(), start, Duration::from_millis(100));
        tokio::time::advance(Duration::from_millis(90)).await;
        assert!(control.observed_failure().is_none());

        // The deadline is observed before the publication.
        tokio::time::advance(Duration::from_millis(10)).await;
        assert_eq!(
            control.observed_failure().expect("a decided failure").code,
            TIMEOUT
        );

        // A cancellation is observed first and keeps its reason even after the
        // deadline passes.
        let start = Instant::now();
        let token = CancellationToken::new();
        let cancelled = RequestControl::new(token.clone(), start, Duration::from_millis(100));
        token.cancel();
        assert_eq!(
            cancelled
                .observed_failure()
                .expect("a decided failure")
                .code,
            CANCELLED
        );
        tokio::time::advance(Duration::from_secs(60)).await;
        assert_eq!(
            cancelled
                .observed_failure()
                .expect("a decided failure")
                .code,
            CANCELLED,
            "the first observed reason must not be rewritten"
        );
    }

    /// A failure that was already decided is never rewritten by a later
    /// cancellation, and its permit is still held until `wait` returns.
    #[tokio::test]
    async fn a_determined_overflow_is_not_rewritten_by_a_late_cancellation() {
        use std::path::Path;

        let dir = std::env::temp_dir().join(format!(
            "cass-mcp-t15-late-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("create sandbox");
        let term = dir.join("term");
        let chunk = "W".repeat(1024);
        let script = format!(
            "term='{term}'\n\
             trap 'printf t > \"$term\"' TERM\n\
             printf '%s' '{chunk}{chunk}{chunk}{chunk}'\n\
             while :; do sleep 0.02; done\n",
            term = term.display(),
        );
        let mut child = Command::new("/bin/sh")
            .arg("-c")
            .arg(script)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .expect("spawn flooding child");
        let pid = child.id().expect("child pid");
        let stdout = child.stdout.take().expect("piped stdout");
        let stderr = child.stderr.take().expect("piped stderr");

        let admission = Admission::new(1, 1);
        let permit = take_running(admission.enter());
        let token = CancellationToken::new();
        let control = RequestControl::new(token.clone(), Instant::now(), Duration::from_secs(60));
        let handle = tokio::spawn(supervise_holding(
            permit,
            control,
            child,
            stdout,
            stderr,
            1024,
            Duration::from_millis(1000),
        ));

        // The overflow is decided first; the reaping SIGTERM arrives next and
        // the child ignores it, so it is still alive inside the grace.
        let mut term_seen = false;
        for _ in 0..2000 {
            if term.exists() {
                term_seen = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert!(term_seen, "the child never observed the reaping SIGTERM");
        assert_eq!(
            admission.counters(),
            (1, 0),
            "the permit must still be held while the reaping child is alive"
        );
        assert!(
            Path::new("/proc").join(pid.to_string()).exists(),
            "the child must still be alive inside the forced-kill grace"
        );

        token.cancel();
        let outcome = tokio::time::timeout(Duration::from_secs(10), handle)
            .await
            .expect("the supervisor must finish")
            .expect("the supervising task");
        assert!(
            matches!(outcome, Supervised::TooLarge),
            "the late cancellation must not rewrite the decided overflow"
        );
        assert_eq!(
            admission.counters(),
            (0, 0),
            "the permit is released exactly once, after the wait"
        );
        assert!(
            !Path::new("/proc").join(pid.to_string()).exists(),
            "the child must be waited before the permit is released"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
