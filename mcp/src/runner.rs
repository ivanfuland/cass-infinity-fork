//! Direct subprocess execution of the companion CASS binary, plus the fixed
//! result and error mapping.
//!
//! One [`Runner`] is shared by every SDK session. It never uses a shell: each
//! argument is one argv element, `stdin` is closed, inherited `CASS_*`
//! variables are removed for the child, and `CASS_DATA_DIR` is set to the
//! configured directory.

use std::ffi::OsString;
use std::path::PathBuf;
use std::process::{ExitStatus, Stdio};
use std::time::Duration;

use quick_xml::events::Event;
use quick_xml::{Reader, XmlVersion};
use serde_json::Value;
use tokio::io::AsyncReadExt;
use tokio::process::{Child, ChildStderr, ChildStdout, Command};

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

impl ToolError {
    pub fn result_too_large(message: impl Into<String>) -> Self {
        Self {
            code: RESULT_TOO_LARGE,
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

/// The fixed startup values every call reuses.
#[derive(Debug)]
pub struct Runner {
    cass_bin: PathBuf,
    data_dir: PathBuf,
    api_config: PathBuf,
    embedding_profile: String,
    rerank_profile: String,
    max_output_bytes: usize,
    terminate_grace: Duration,
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
        }
    }

    /// Run one validated call. On success the returned string is the
    /// unmodified CLI stdout, already proven to be a legal C04 envelope for
    /// this tool. On failure it is a fixed tool error.
    ///
    /// One supervising task owns the child, both pipes, the combined byte
    /// count, and the `wait`; the caller only awaits its result. Dropping the
    /// caller's future therefore never drops the child or its reaping duty.
    pub async fn run(&self, tool: RecallTool, call: &ToolCall) -> Result<String, ToolError> {
        let profiles = FixedProfiles {
            api_config: &self.api_config,
            embedding_profile: &self.embedding_profile,
            rerank_profile: &self.rerank_profile,
        };
        let argv = call.argv(&profiles);

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

        let supervised = tokio::spawn(supervise(
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
}

/// Own the child until both pipes reach EOF and `wait` reports. Every byte
/// stored on either stream counts against the same budget; the first chunk
/// that would cross it stops both reads and moves straight to reaping. A
/// non-zero exit observed in the same window never overrides the overflow.
async fn supervise(
    mut child: Child,
    mut stdout: ChildStdout,
    mut stderr: ChildStderr,
    budget: usize,
    grace: Duration,
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
        tokio::select! {
            biased;
            read = stdout.read(&mut stdout_buffer), if stdout_open => {
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
            read = stderr.read(&mut stderr_buffer), if stderr_open => {
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
