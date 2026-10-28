//! The single CLI recall envelope shared by direct calls and MCP forwarding.
use quick_xml::{Reader, events::Event};
use serde_json::Value;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecallTool {
    Search,
    Expand,
    Sessions,
    Timeline,
}

impl RecallTool {
    pub fn name(self) -> &'static str {
        match self {
            Self::Search => "cass_search",
            Self::Expand => "cass_expand",
            Self::Sessions => "cass_sessions",
            Self::Timeline => "cass_timeline",
        }
    }

    /// Crate-visible so the v2 recall judgment reuses the same shape check;
    /// the codec's own semantics and output are unchanged.
    pub(crate) fn accepts(self, value: &Value) -> bool {
        let objects = |v: &Value| v.as_array().is_some_and(|a| a.iter().all(Value::is_object));
        match self {
            Self::Search => value.get("hits").is_some_and(objects),
            Self::Expand => objects(value),
            Self::Sessions => value.get("sessions").is_some_and(objects),
            Self::Timeline => {
                value.get("range").is_some_and(Value::is_object)
                    && value.get("total_sessions").is_some_and(Value::is_u64)
                    && (value.get("groups").is_some_and(Value::is_object)
                        || value.get("sessions").is_some_and(objects))
            }
        }
    }
}

#[derive(Debug, thiserror::Error)]
#[error("invalid recall output: {0}")]
pub struct RecallError(&'static str);

pub fn encode(tool: RecallTool, value: &Value) -> Result<String, RecallError> {
    if !tool.accepts(value) {
        return Err(RecallError("result shape does not match tool"));
    }
    let json = serde_json::to_string(value).map_err(|_| RecallError("JSON encoding failed"))?;
    let text = quick_xml::escape::escape(&json);
    Ok(format!(
        "<cass_recall version=\"1\" tool=\"{}\">{text}</cass_recall>",
        tool.name()
    ))
}

/// Parse the entire document. Never extract a matching tag from mixed output.
pub fn decode(input: &str, expected: RecallTool) -> Result<Value, RecallError> {
    decode_with_original_json(input, expected).map(|(value, _)| value)
}

/// The same parse as [`decode`], plus the exact JSON text that was parsed.
///
/// The lossless copy proof needs the original number spelling and the original
/// member list; re-serializing the parsed `Value` would lose both. The public
/// [`decode`] keeps its own signature, acceptance order and duplicate-key
/// behavior (the last duplicate wins, as before).
pub(crate) fn decode_with_original_json(
    input: &str,
    expected: RecallTool,
) -> Result<(Value, String), RecallError> {
    let json = extract_json(input, expected)?;
    let value = serde_json::from_str(&json).map_err(|_| RecallError("invalid JSON"))?;
    if !expected.accepts(&value) {
        return Err(RecallError("result shape does not match tool"));
    }
    Ok((value, json))
}

/// The single root element and its body text, with the expected tool checked.
fn extract_json(input: &str, expected: RecallTool) -> Result<String, RecallError> {
    let mut reader = Reader::from_str(input);
    let mut state = 0; // before root, inside root, after root
    let mut json = String::new();
    loop {
        match reader
            .read_event()
            .map_err(|_| RecallError("malformed XML"))?
        {
            Event::Start(root) if state == 0 && root.name().as_ref() == "cass_recall" => {
                let mut version = None;
                let mut tool = None;
                for attribute in root.attributes() {
                    let attribute =
                        attribute.map_err(|_| RecallError("invalid root attributes"))?;
                    let value = attribute
                        .normalized_value(quick_xml::XmlVersion::Implicit1_0)
                        .map_err(|_| RecallError("invalid attribute value"))?
                        .into_owned();
                    match attribute.key.as_ref() {
                        "version" if version.is_none() => version = Some(value),
                        "tool" if tool.is_none() => tool = Some(value),
                        _ => return Err(RecallError("unknown or duplicate root attribute")),
                    }
                }
                if version.as_deref() != Some("1") || tool.as_deref() != Some(expected.name()) {
                    return Err(RecallError("unsupported version or wrong tool"));
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
                    return Err(RecallError("text outside root"));
                }
            }
            Event::GeneralRef(reference) if state == 1 => {
                if let Some(ch) = reference
                    .resolve_char_ref()
                    .map_err(|_| RecallError("invalid character reference"))?
                {
                    json.push(ch);
                } else {
                    let name = reference.as_ref();
                    json.push_str(match name {
                        "amp" => "&",
                        "lt" => "<",
                        "gt" => ">",
                        "quot" => "\"",
                        "apos" => "'",
                        _ => return Err(RecallError("undeclared entity")),
                    });
                }
            }
            Event::End(root) if state == 1 && root.name().as_ref() == "cass_recall" => state = 2,
            Event::Eof if state == 2 => break,
            _ => return Err(RecallError("expected one text-only recall root")),
        }
    }
    Ok(json)
}
