//! Direct subprocess execution of the companion CASS binary, plus the fixed
//! result and error mapping.
//!
//! One [`Runner`] is shared by every SDK session. It never uses a shell: each
//! argument is one argv element, `stdin` is closed, inherited `CASS_*`
//! variables are removed for the child, and `CASS_DATA_DIR` is set to the
//! configured directory.

use std::ffi::OsString;
use std::path::PathBuf;
use std::process::Stdio;

use quick_xml::events::Event;
use quick_xml::{Reader, XmlVersion};
use serde_json::Value;
use tokio::process::Command;

use crate::config::Config;
use crate::tools::{FixedProfiles, RecallTool, ToolCall};

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

impl ToolError {
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
        let mut error = serde_json::Map::new();
        error.insert("code".to_string(), Value::String(self.code.to_string()));
        error.insert("message".to_string(), Value::String(self.message.clone()));
        if let Some(code) = self.cli_exit_code {
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
}

impl Runner {
    pub fn new(config: &Config) -> Self {
        Self {
            cass_bin: config.cass_bin.clone(),
            data_dir: config.data_dir.clone(),
            api_config: config.api_config.clone(),
            embedding_profile: config.embedding_profile.clone(),
            rerank_profile: config.rerank_profile.clone(),
        }
    }

    /// Run one validated call. On success the returned string is the
    /// unmodified CLI stdout, already proven to be a legal C04 envelope for
    /// this tool. On failure it is a fixed tool error.
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

        let output = command
            .output()
            .await
            .map_err(|_| cass_exit("the companion CASS binary could not be started", None))?;

        if !output.status.success() {
            let code = output.status.code();
            return Err(classify_exit(&output.stderr, code));
        }

        let stdout = std::str::from_utf8(&output.stdout)
            .map_err(|_| ToolError::invalid_recall("CLI stdout is not valid UTF-8"))?;
        decode_recall(stdout, tool)?;
        Ok(stdout.to_string())
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
