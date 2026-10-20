//! Strict byte-level decoder for `cass.restore-source-contexts/1` declarations.
//!
//! Declarations decoded here are unverified. This module does not read the file
//! system, database, or environment, does not discover roots, does not match a
//! manifest or support whitelist, and does not select, hash, or write anything.

use std::collections::HashSet;
use std::fmt;

use franken_agent_detection as fad;
use serde::de::Deserializer;
use serde::de::Error as _;
use serde::{Deserialize, Serialize};

/// The only schema string accepted by this decoder.
#[cfg_attr(not(test), allow(dead_code))]
const RESTORE_SOURCE_CONTEXTS_SCHEMA: &str = "cass.restore-source-contexts/1";

/// Root of a restore source-context declaration file.
///
/// The value keeps declaration order and every declared string verbatim.
#[cfg_attr(not(test), allow(dead_code))]
#[derive(Clone, Serialize, PartialEq, Eq)]
pub(crate) struct RestoreSourceContexts {
    pub(crate) schema: String,
    pub(crate) inputs: Vec<RestoreSourceContextDeclaration>,
}

/// One source input declaration. This is not a verified source input.
#[cfg_attr(not(test), allow(dead_code))]
#[derive(Clone, Serialize, PartialEq, Eq)]
pub(crate) struct RestoreSourceContextDeclaration {
    pub(crate) manifest_id: String,
    pub(crate) identity_namespace: String,
    pub(crate) connector: String,
    pub(crate) scan_root: String,
    pub(crate) relative_locator: String,
    pub(crate) role: fad::SourceInputRole,
    pub(crate) origin: RestoreSourceContextOrigin,
    pub(crate) platform: Option<fad::types::Platform>,
    pub(crate) workspace_rewrites: Vec<fad::types::PathMapping>,
}

/// Origin of one source input declaration.
#[cfg_attr(not(test), allow(dead_code))]
#[derive(Clone, Serialize, PartialEq, Eq)]
pub(crate) struct RestoreSourceContextOrigin {
    pub(crate) source_id: String,
    pub(crate) kind: fad::types::SourceKind,
    pub(crate) host: Option<String>,
    pub(crate) source_version: Option<String>,
}

/// Decode failure with no material field.
#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RestoreSourceContextDecodeError {
    Invalid,
    Ambiguous,
}

impl fmt::Display for RestoreSourceContextDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Invalid => "source_restore_context_invalid",
            Self::Ambiguous => "source_restore_context_ambiguous",
        })
    }
}

impl std::error::Error for RestoreSourceContextDecodeError {}

impl<'de> Deserialize<'de> for RestoreSourceContexts {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = WireRoot::deserialize(deserializer)
            .map_err(|_| D::Error::custom("source_restore_context_invalid"))?;
        validate_wire_root(wire).map_err(|error| D::Error::custom(error.to_string()))
    }
}

impl<'de> Deserialize<'de> for RestoreSourceContextDeclaration {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        WireDeclaration::deserialize(deserializer)
            .map(RestoreSourceContextDeclaration::from)
            .map_err(|_| D::Error::custom("source_restore_context_invalid"))
    }
}

impl<'de> Deserialize<'de> for RestoreSourceContextOrigin {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        WireOrigin::deserialize(deserializer)
            .map(RestoreSourceContextOrigin::from)
            .map_err(|_| D::Error::custom("source_restore_context_invalid"))
    }
}

/// Strictly decode one declaration file.
///
/// Order is fixed: complete strict JSON decode, then exact schema, then duplicate
/// `manifest_id` detection on the decoded declarations.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn decode_restore_source_contexts(
    bytes: &[u8],
) -> Result<RestoreSourceContexts, RestoreSourceContextDecodeError> {
    let wire: WireRoot =
        serde_json::from_slice(bytes).map_err(|_| RestoreSourceContextDecodeError::Invalid)?;
    validate_wire_root(wire)
}

/// Shared root validator for the decode function and the direct root entry.
#[cfg_attr(not(test), allow(dead_code))]
fn validate_wire_root(
    wire: WireRoot,
) -> Result<RestoreSourceContexts, RestoreSourceContextDecodeError> {
    if wire.schema != RESTORE_SOURCE_CONTEXTS_SCHEMA {
        return Err(RestoreSourceContextDecodeError::Invalid);
    }
    {
        let mut seen: HashSet<&str> = HashSet::with_capacity(wire.inputs.len());
        for input in &wire.inputs {
            if !seen.insert(input.manifest_id.as_str()) {
                return Err(RestoreSourceContextDecodeError::Ambiguous);
            }
        }
    }
    Ok(RestoreSourceContexts {
        schema: wire.schema,
        inputs: wire
            .inputs
            .into_iter()
            .map(RestoreSourceContextDeclaration::from)
            .collect(),
    })
}

/// Present-or-null decoder. A missing key is a missing-field error; `null` is `None`.
#[cfg_attr(not(test), allow(dead_code))]
fn required_nullable<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireRoot {
    schema: String,
    inputs: Vec<WireDeclaration>,
}

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireDeclaration {
    manifest_id: String,
    identity_namespace: String,
    connector: String,
    scan_root: String,
    relative_locator: String,
    role: fad::SourceInputRole,
    origin: WireOrigin,
    #[serde(deserialize_with = "required_nullable")]
    platform: Option<fad::types::Platform>,
    workspace_rewrites: Vec<WireRewrite>,
}

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireOrigin {
    source_id: String,
    kind: fad::types::SourceKind,
    #[serde(deserialize_with = "required_nullable")]
    host: Option<String>,
    #[serde(deserialize_with = "required_nullable")]
    source_version: Option<String>,
}

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireRewrite {
    from: String,
    to: String,
    agents: Option<Vec<String>>,
}

impl From<WireDeclaration> for RestoreSourceContextDeclaration {
    fn from(wire: WireDeclaration) -> Self {
        Self {
            manifest_id: wire.manifest_id,
            identity_namespace: wire.identity_namespace,
            connector: wire.connector,
            scan_root: wire.scan_root,
            relative_locator: wire.relative_locator,
            role: wire.role,
            origin: wire.origin.into(),
            platform: wire.platform,
            workspace_rewrites: wire
                .workspace_rewrites
                .into_iter()
                .map(fad::types::PathMapping::from)
                .collect(),
        }
    }
}

impl From<WireOrigin> for RestoreSourceContextOrigin {
    fn from(wire: WireOrigin) -> Self {
        Self {
            source_id: wire.source_id,
            kind: wire.kind,
            host: wire.host,
            source_version: wire.source_version,
        }
    }
}

impl From<WireRewrite> for fad::types::PathMapping {
    fn from(wire: WireRewrite) -> Self {
        Self {
            from: wire.from,
            to: wire.to,
            agents: wire.agents,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    const FIXTURES_JSON: &str = r##"{
  "schema": "cass.controller.context-decoder-fixtures/1",
  "base_commit": "0c7ce5bf0c2d7badd2b631f9a2a094340727a014",
  "note": "Expected values are controller-declared JSON semantics; agents null/missing normalize to absent on Serialize. Raw duplicate objects stay raw. These declarations are not bound material.",
  "counts": {
    "d1_valid_roundtrip": 4,
    "d2_shape_is_not_binding": 4,
    "d3_missing_and_unknown": 35,
    "d4_duplicate_and_priority": 8,
    "d5_invalid_types_and_privacy": 13
  },
  "cases": [
    {
      "test": "d1_valid_roundtrip",
      "case": "local_nulls",
      "expected": "ok",
      "direct_scope": "root",
      "raw_utf8": "{\"schema\":\"cass.restore-source-contexts/1\",\"inputs\":[{\"manifest_id\":\"manifest-z\",\"identity_namespace\":\"S42_PRIVATE_NAMESPACE\",\"connector\":\"claude_code\",\"scan_root\":\"/synthetic/S42_PRIVATE_PATH/root\",\"relative_locator\":\"session.jsonl\",\"role\":\"primary_session_log\",\"origin\":{\"source_id\":\"local\",\"kind\":\"local\",\"host\":null,\"source_version\":null},\"platform\":null,\"workspace_rewrites\":[{\"from\":\"/synthetic/from\",\"to\":\"/synthetic/to\"}]},{\"manifest_id\":\"manifest-a\",\"identity_namespace\":\"S42_PRIVATE_NAMESPACE\",\"connector\":\"claude_code\",\"scan_root\":\"/synthetic/S42_PRIVATE_PATH/root\",\"relative_locator\":\"session.jsonl\",\"role\":\"primary_session_log\",\"origin\":{\"source_id\":\"local\",\"kind\":\"local\",\"host\":null,\"source_version\":null},\"platform\":null,\"workspace_rewrites\":[{\"from\":\"/synthetic/from\",\"to\":\"/synthetic/to\"}]},{\"manifest_id\":\"manifest-A\",\"identity_namespace\":\"S42_PRIVATE_NAMESPACE\",\"connector\":\"claude_code\",\"scan_root\":\"/synthetic/S42_PRIVATE_PATH/root\",\"relative_locator\":\"session.jsonl\",\"role\":\"primary_session_log\",\"origin\":{\"source_id\":\"local\",\"kind\":\"local\",\"host\":null,\"source_version\":null},\"platform\":null,\"workspace_rewrites\":[{\"from\":\"/synthetic/from\",\"to\":\"/synthetic/to\"}]},{\"manifest_id\":\"manifest-a \",\"identity_namespace\":\"S42_PRIVATE_NAMESPACE\",\"connector\":\"claude_code\",\"scan_root\":\"/synthetic/S42_PRIVATE_PATH/root\",\"relative_locator\":\"session.jsonl\",\"role\":\"primary_session_log\",\"origin\":{\"source_id\":\"local\",\"kind\":\"local\",\"host\":null,\"source_version\":null},\"platform\":null,\"workspace_rewrites\":[{\"from\":\"/synthetic/from\",\"to\":\"/synthetic/to\"}]}]}",
      "expected_value": {
        "schema": "cass.restore-source-contexts/1",
        "inputs": [
          {
            "manifest_id": "manifest-z",
            "identity_namespace": "S42_PRIVATE_NAMESPACE",
            "connector": "claude_code",
            "scan_root": "/synthetic/S42_PRIVATE_PATH/root",
            "relative_locator": "session.jsonl",
            "role": "primary_session_log",
            "origin": {
              "source_id": "local",
              "kind": "local",
              "host": null,
              "source_version": null
            },
            "platform": null,
            "workspace_rewrites": [
              {
                "from": "/synthetic/from",
                "to": "/synthetic/to"
              }
            ]
          },
          {
            "manifest_id": "manifest-a",
            "identity_namespace": "S42_PRIVATE_NAMESPACE",
            "connector": "claude_code",
            "scan_root": "/synthetic/S42_PRIVATE_PATH/root",
            "relative_locator": "session.jsonl",
            "role": "primary_session_log",
            "origin": {
              "source_id": "local",
              "kind": "local",
              "host": null,
              "source_version": null
            },
            "platform": null,
            "workspace_rewrites": [
              {
                "from": "/synthetic/from",
                "to": "/synthetic/to"
              }
            ]
          },
          {
            "manifest_id": "manifest-A",
            "identity_namespace": "S42_PRIVATE_NAMESPACE",
            "connector": "claude_code",
            "scan_root": "/synthetic/S42_PRIVATE_PATH/root",
            "relative_locator": "session.jsonl",
            "role": "primary_session_log",
            "origin": {
              "source_id": "local",
              "kind": "local",
              "host": null,
              "source_version": null
            },
            "platform": null,
            "workspace_rewrites": [
              {
                "from": "/synthetic/from",
                "to": "/synthetic/to"
              }
            ]
          },
          {
            "manifest_id": "manifest-a ",
            "identity_namespace": "S42_PRIVATE_NAMESPACE",
            "connector": "claude_code",
            "scan_root": "/synthetic/S42_PRIVATE_PATH/root",
            "relative_locator": "session.jsonl",
            "role": "primary_session_log",
            "origin": {
              "source_id": "local",
              "kind": "local",
              "host": null,
              "source_version": null
            },
            "platform": null,
            "workspace_rewrites": [
              {
                "from": "/synthetic/from",
                "to": "/synthetic/to"
              }
            ]
          }
        ]
      }
    },
    {
      "test": "d1_valid_roundtrip",
      "case": "ssh_full",
      "expected": "ok",
      "direct_scope": "root",
      "raw_utf8": "{\"schema\":\"cass.restore-source-contexts/1\",\"inputs\":[{\"manifest_id\":\"manifest-ssh\",\"identity_namespace\":\"S42_PRIVATE_NAMESPACE\",\"connector\":\"claude_code\",\"scan_root\":\"/synthetic/S42_PRIVATE_PATH/root\",\"relative_locator\":\"session.jsonl\",\"role\":\"metadata_sidecar\",\"origin\":{\"source_id\":\"ssh-work\",\"kind\":\"ssh\",\"host\":\"S42_PRIVATE_REMOTE_HOST\",\"source_version\":\"v42\"},\"platform\":\"windows\",\"workspace_rewrites\":[{\"from\":\"/synthetic/from\",\"to\":\"/synthetic/to\"}]}]}",
      "expected_value": {
        "schema": "cass.restore-source-contexts/1",
        "inputs": [
          {
            "manifest_id": "manifest-ssh",
            "identity_namespace": "S42_PRIVATE_NAMESPACE",
            "connector": "claude_code",
            "scan_root": "/synthetic/S42_PRIVATE_PATH/root",
            "relative_locator": "session.jsonl",
            "role": "metadata_sidecar",
            "origin": {
              "source_id": "ssh-work",
              "kind": "ssh",
              "host": "S42_PRIVATE_REMOTE_HOST",
              "source_version": "v42"
            },
            "platform": "windows",
            "workspace_rewrites": [
              {
                "from": "/synthetic/from",
                "to": "/synthetic/to"
              }
            ]
          }
        ]
      }
    },
    {
      "test": "d1_valid_roundtrip",
      "case": "empty_inputs",
      "expected": "ok",
      "direct_scope": "root",
      "raw_utf8": "{\"schema\":\"cass.restore-source-contexts/1\",\"inputs\":[]}",
      "expected_value": {
        "schema": "cass.restore-source-contexts/1",
        "inputs": []
      }
    },
    {
      "test": "d1_valid_roundtrip",
      "case": "rewrite_agents",
      "expected": "ok",
      "direct_scope": "root",
      "raw_utf8": "{\"schema\":\"cass.restore-source-contexts/1\",\"inputs\":[{\"manifest_id\":\"rewrite-linux\",\"identity_namespace\":\"S42_PRIVATE_NAMESPACE\",\"connector\":\"claude_code\",\"scan_root\":\"/synthetic/S42_PRIVATE_PATH/root\",\"relative_locator\":\"session.jsonl\",\"role\":\"primary_session_log\",\"origin\":{\"source_id\":\"local\",\"kind\":\"local\",\"host\":null,\"source_version\":null},\"platform\":\"linux\",\"workspace_rewrites\":[{\"from\":\" /synthetic/0 \",\"to\":\"/out/0\"},{\"from\":\"/synthetic/1\",\"to\":\"/out/1\",\"agents\":null},{\"from\":\"/synthetic/2\",\"to\":\"/out/2\",\"agents\":[]},{\"from\":\"/synthetic/3\",\"to\":\"/out/3\",\"agents\":[\"b\",\"a\",\"b\"]}]},{\"manifest_id\":\"rewrite-macos\",\"identity_namespace\":\"S42_PRIVATE_NAMESPACE\",\"connector\":\"claude_code\",\"scan_root\":\"/synthetic/S42_PRIVATE_PATH/root\",\"relative_locator\":\"session.jsonl\",\"role\":\"primary_session_log\",\"origin\":{\"source_id\":\"local\",\"kind\":\"local\",\"host\":null,\"source_version\":null},\"platform\":\"macos\",\"workspace_rewrites\":[{\"from\":\" /synthetic/0 \",\"to\":\"/out/0\"},{\"from\":\"/synthetic/1\",\"to\":\"/out/1\",\"agents\":null},{\"from\":\"/synthetic/2\",\"to\":\"/out/2\",\"agents\":[]},{\"from\":\"/synthetic/3\",\"to\":\"/out/3\",\"agents\":[\"b\",\"a\",\"b\"]}]}]}",
      "expected_value": {
        "schema": "cass.restore-source-contexts/1",
        "inputs": [
          {
            "manifest_id": "rewrite-linux",
            "identity_namespace": "S42_PRIVATE_NAMESPACE",
            "connector": "claude_code",
            "scan_root": "/synthetic/S42_PRIVATE_PATH/root",
            "relative_locator": "session.jsonl",
            "role": "primary_session_log",
            "origin": {
              "source_id": "local",
              "kind": "local",
              "host": null,
              "source_version": null
            },
            "platform": "linux",
            "workspace_rewrites": [
              {
                "from": " /synthetic/0 ",
                "to": "/out/0"
              },
              {
                "from": "/synthetic/1",
                "to": "/out/1"
              },
              {
                "from": "/synthetic/2",
                "to": "/out/2",
                "agents": []
              },
              {
                "from": "/synthetic/3",
                "to": "/out/3",
                "agents": [
                  "b",
                  "a",
                  "b"
                ]
              }
            ]
          },
          {
            "manifest_id": "rewrite-macos",
            "identity_namespace": "S42_PRIVATE_NAMESPACE",
            "connector": "claude_code",
            "scan_root": "/synthetic/S42_PRIVATE_PATH/root",
            "relative_locator": "session.jsonl",
            "role": "primary_session_log",
            "origin": {
              "source_id": "local",
              "kind": "local",
              "host": null,
              "source_version": null
            },
            "platform": "macos",
            "workspace_rewrites": [
              {
                "from": " /synthetic/0 ",
                "to": "/out/0"
              },
              {
                "from": "/synthetic/1",
                "to": "/out/1"
              },
              {
                "from": "/synthetic/2",
                "to": "/out/2",
                "agents": []
              },
              {
                "from": "/synthetic/3",
                "to": "/out/3",
                "agents": [
                  "b",
                  "a",
                  "b"
                ]
              }
            ]
          }
        ]
      }
    },
    {
      "test": "d2_shape_is_not_binding",
      "case": "unknown_manifest",
      "expected": "ok",
      "direct_scope": "root",
      "raw_utf8": "{\"schema\":\"cass.restore-source-contexts/1\",\"inputs\":[{\"manifest_id\":\"not-catalogued\",\"identity_namespace\":\"S42_PRIVATE_NAMESPACE\",\"connector\":\"future_connector\",\"scan_root\":\"/synthetic/S42_PRIVATE_PATH/root\",\"relative_locator\":\"session.jsonl\",\"role\":\"primary_session_log\",\"origin\":{\"source_id\":\"local\",\"kind\":\"local\",\"host\":null,\"source_version\":null},\"platform\":null,\"workspace_rewrites\":[{\"from\":\"/synthetic/from\",\"to\":\"/synthetic/to\"}]}]}",
      "expected_value": {
        "schema": "cass.restore-source-contexts/1",
        "inputs": [
          {
            "manifest_id": "not-catalogued",
            "identity_namespace": "S42_PRIVATE_NAMESPACE",
            "connector": "future_connector",
            "scan_root": "/synthetic/S42_PRIVATE_PATH/root",
            "relative_locator": "session.jsonl",
            "role": "primary_session_log",
            "origin": {
              "source_id": "local",
              "kind": "local",
              "host": null,
              "source_version": null
            },
            "platform": null,
            "workspace_rewrites": [
              {
                "from": "/synthetic/from",
                "to": "/synthetic/to"
              }
            ]
          }
        ]
      }
    },
    {
      "test": "d2_shape_is_not_binding",
      "case": "opaque_strings",
      "expected": "ok",
      "direct_scope": "root",
      "raw_utf8": "{\"schema\":\"cass.restore-source-contexts/1\",\"inputs\":[{\"manifest_id\":\" \",\"identity_namespace\":\"\",\"connector\":\" future_connector \",\"scan_root\":\" root \",\"relative_locator\":\" path \",\"role\":\"primary_session_log\",\"origin\":{\"source_id\":\"\",\"kind\":\"local\",\"host\":\" host \",\"source_version\":\" version \"},\"platform\":null,\"workspace_rewrites\":[{\"from\":\"\",\"to\":\" to \",\"agents\":[\" b \",\"a\"]}]}]}",
      "expected_value": {
        "schema": "cass.restore-source-contexts/1",
        "inputs": [
          {
            "manifest_id": " ",
            "identity_namespace": "",
            "connector": " future_connector ",
            "scan_root": " root ",
            "relative_locator": " path ",
            "role": "primary_session_log",
            "origin": {
              "source_id": "",
              "kind": "local",
              "host": " host ",
              "source_version": " version "
            },
            "platform": null,
            "workspace_rewrites": [
              {
                "from": "",
                "to": " to ",
                "agents": [
                  " b ",
                  "a"
                ]
              }
            ]
          }
        ]
      }
    },
    {
      "test": "d2_shape_is_not_binding",
      "case": "trace_role",
      "expected": "ok",
      "direct_scope": "root",
      "raw_utf8": "{\"schema\":\"cass.restore-source-contexts/1\",\"inputs\":[{\"manifest_id\":\"manifest-base\",\"identity_namespace\":\"S42_PRIVATE_NAMESPACE\",\"connector\":\"claude_code\",\"scan_root\":\"/synthetic/S42_PRIVATE_PATH/root\",\"relative_locator\":\"session.jsonl\",\"role\":\"trace\",\"origin\":{\"source_id\":\"local\",\"kind\":\"local\",\"host\":null,\"source_version\":null},\"platform\":null,\"workspace_rewrites\":[{\"from\":\"/synthetic/from\",\"to\":\"/synthetic/to\"}]}]}",
      "expected_value": {
        "schema": "cass.restore-source-contexts/1",
        "inputs": [
          {
            "manifest_id": "manifest-base",
            "identity_namespace": "S42_PRIVATE_NAMESPACE",
            "connector": "claude_code",
            "scan_root": "/synthetic/S42_PRIVATE_PATH/root",
            "relative_locator": "session.jsonl",
            "role": "trace",
            "origin": {
              "source_id": "local",
              "kind": "local",
              "host": null,
              "source_version": null
            },
            "platform": null,
            "workspace_rewrites": [
              {
                "from": "/synthetic/from",
                "to": "/synthetic/to"
              }
            ]
          }
        ]
      }
    },
    {
      "test": "d2_shape_is_not_binding",
      "case": "relative_root",
      "expected": "ok",
      "direct_scope": "root",
      "raw_utf8": "{\"schema\":\"cass.restore-source-contexts/1\",\"inputs\":[{\"manifest_id\":\"manifest-base\",\"identity_namespace\":\"S42_PRIVATE_NAMESPACE\",\"connector\":\"claude_code\",\"scan_root\":\"../S42_PRIVATE_relative\",\"relative_locator\":\"../session.jsonl\",\"role\":\"primary_session_log\",\"origin\":{\"source_id\":\"local\",\"kind\":\"local\",\"host\":null,\"source_version\":null},\"platform\":null,\"workspace_rewrites\":[{\"from\":\"/synthetic/from\",\"to\":\"/synthetic/to\"}]}]}",
      "expected_value": {
        "schema": "cass.restore-source-contexts/1",
        "inputs": [
          {
            "manifest_id": "manifest-base",
            "identity_namespace": "S42_PRIVATE_NAMESPACE",
            "connector": "claude_code",
            "scan_root": "../S42_PRIVATE_relative",
            "relative_locator": "../session.jsonl",
            "role": "primary_session_log",
            "origin": {
              "source_id": "local",
              "kind": "local",
              "host": null,
              "source_version": null
            },
            "platform": null,
            "workspace_rewrites": [
              {
                "from": "/synthetic/from",
                "to": "/synthetic/to"
              }
            ]
          }
        ]
      }
    },
    {
      "test": "d3_missing_and_unknown",
      "case": "missing_root_schema",
      "expected": "invalid",
      "direct_scope": "root",
      "raw_utf8": "{\"inputs\":[{\"manifest_id\":\"manifest-base\",\"identity_namespace\":\"S42_PRIVATE_NAMESPACE\",\"connector\":\"claude_code\",\"scan_root\":\"/synthetic/S42_PRIVATE_PATH/root\",\"relative_locator\":\"session.jsonl\",\"role\":\"primary_session_log\",\"origin\":{\"source_id\":\"local\",\"kind\":\"local\",\"host\":null,\"source_version\":null},\"platform\":null,\"workspace_rewrites\":[{\"from\":\"/synthetic/from\",\"to\":\"/synthetic/to\"}]}]}"
    },
    {
      "test": "d3_missing_and_unknown",
      "case": "missing_root_inputs",
      "expected": "invalid",
      "direct_scope": "root",
      "raw_utf8": "{\"schema\":\"cass.restore-source-contexts/1\"}"
    },
    {
      "test": "d3_missing_and_unknown",
      "case": "missing_input_manifest_id",
      "expected": "invalid",
      "direct_scope": "input",
      "raw_utf8": "{\"schema\":\"cass.restore-source-contexts/1\",\"inputs\":[{\"identity_namespace\":\"S42_PRIVATE_NAMESPACE\",\"connector\":\"claude_code\",\"scan_root\":\"/synthetic/S42_PRIVATE_PATH/root\",\"relative_locator\":\"session.jsonl\",\"role\":\"primary_session_log\",\"origin\":{\"source_id\":\"local\",\"kind\":\"local\",\"host\":null,\"source_version\":null},\"platform\":null,\"workspace_rewrites\":[{\"from\":\"/synthetic/from\",\"to\":\"/synthetic/to\"}]}]}",
      "direct_input_utf8": "{\"identity_namespace\":\"S42_PRIVATE_NAMESPACE\",\"connector\":\"claude_code\",\"scan_root\":\"/synthetic/S42_PRIVATE_PATH/root\",\"relative_locator\":\"session.jsonl\",\"role\":\"primary_session_log\",\"origin\":{\"source_id\":\"local\",\"kind\":\"local\",\"host\":null,\"source_version\":null},\"platform\":null,\"workspace_rewrites\":[{\"from\":\"/synthetic/from\",\"to\":\"/synthetic/to\"}]}"
    },
    {
      "test": "d3_missing_and_unknown",
      "case": "missing_input_identity_namespace",
      "expected": "invalid",
      "direct_scope": "input",
      "raw_utf8": "{\"schema\":\"cass.restore-source-contexts/1\",\"inputs\":[{\"manifest_id\":\"manifest-base\",\"connector\":\"claude_code\",\"scan_root\":\"/synthetic/S42_PRIVATE_PATH/root\",\"relative_locator\":\"session.jsonl\",\"role\":\"primary_session_log\",\"origin\":{\"source_id\":\"local\",\"kind\":\"local\",\"host\":null,\"source_version\":null},\"platform\":null,\"workspace_rewrites\":[{\"from\":\"/synthetic/from\",\"to\":\"/synthetic/to\"}]}]}",
      "direct_input_utf8": "{\"manifest_id\":\"manifest-base\",\"connector\":\"claude_code\",\"scan_root\":\"/synthetic/S42_PRIVATE_PATH/root\",\"relative_locator\":\"session.jsonl\",\"role\":\"primary_session_log\",\"origin\":{\"source_id\":\"local\",\"kind\":\"local\",\"host\":null,\"source_version\":null},\"platform\":null,\"workspace_rewrites\":[{\"from\":\"/synthetic/from\",\"to\":\"/synthetic/to\"}]}"
    },
    {
      "test": "d3_missing_and_unknown",
      "case": "missing_input_connector",
      "expected": "invalid",
      "direct_scope": "input",
      "raw_utf8": "{\"schema\":\"cass.restore-source-contexts/1\",\"inputs\":[{\"manifest_id\":\"manifest-base\",\"identity_namespace\":\"S42_PRIVATE_NAMESPACE\",\"scan_root\":\"/synthetic/S42_PRIVATE_PATH/root\",\"relative_locator\":\"session.jsonl\",\"role\":\"primary_session_log\",\"origin\":{\"source_id\":\"local\",\"kind\":\"local\",\"host\":null,\"source_version\":null},\"platform\":null,\"workspace_rewrites\":[{\"from\":\"/synthetic/from\",\"to\":\"/synthetic/to\"}]}]}",
      "direct_input_utf8": "{\"manifest_id\":\"manifest-base\",\"identity_namespace\":\"S42_PRIVATE_NAMESPACE\",\"scan_root\":\"/synthetic/S42_PRIVATE_PATH/root\",\"relative_locator\":\"session.jsonl\",\"role\":\"primary_session_log\",\"origin\":{\"source_id\":\"local\",\"kind\":\"local\",\"host\":null,\"source_version\":null},\"platform\":null,\"workspace_rewrites\":[{\"from\":\"/synthetic/from\",\"to\":\"/synthetic/to\"}]}"
    },
    {
      "test": "d3_missing_and_unknown",
      "case": "missing_input_scan_root",
      "expected": "invalid",
      "direct_scope": "input",
      "raw_utf8": "{\"schema\":\"cass.restore-source-contexts/1\",\"inputs\":[{\"manifest_id\":\"manifest-base\",\"identity_namespace\":\"S42_PRIVATE_NAMESPACE\",\"connector\":\"claude_code\",\"relative_locator\":\"session.jsonl\",\"role\":\"primary_session_log\",\"origin\":{\"source_id\":\"local\",\"kind\":\"local\",\"host\":null,\"source_version\":null},\"platform\":null,\"workspace_rewrites\":[{\"from\":\"/synthetic/from\",\"to\":\"/synthetic/to\"}]}]}",
      "direct_input_utf8": "{\"manifest_id\":\"manifest-base\",\"identity_namespace\":\"S42_PRIVATE_NAMESPACE\",\"connector\":\"claude_code\",\"relative_locator\":\"session.jsonl\",\"role\":\"primary_session_log\",\"origin\":{\"source_id\":\"local\",\"kind\":\"local\",\"host\":null,\"source_version\":null},\"platform\":null,\"workspace_rewrites\":[{\"from\":\"/synthetic/from\",\"to\":\"/synthetic/to\"}]}"
    },
    {
      "test": "d3_missing_and_unknown",
      "case": "missing_input_relative_locator",
      "expected": "invalid",
      "direct_scope": "input",
      "raw_utf8": "{\"schema\":\"cass.restore-source-contexts/1\",\"inputs\":[{\"manifest_id\":\"manifest-base\",\"identity_namespace\":\"S42_PRIVATE_NAMESPACE\",\"connector\":\"claude_code\",\"scan_root\":\"/synthetic/S42_PRIVATE_PATH/root\",\"role\":\"primary_session_log\",\"origin\":{\"source_id\":\"local\",\"kind\":\"local\",\"host\":null,\"source_version\":null},\"platform\":null,\"workspace_rewrites\":[{\"from\":\"/synthetic/from\",\"to\":\"/synthetic/to\"}]}]}",
      "direct_input_utf8": "{\"manifest_id\":\"manifest-base\",\"identity_namespace\":\"S42_PRIVATE_NAMESPACE\",\"connector\":\"claude_code\",\"scan_root\":\"/synthetic/S42_PRIVATE_PATH/root\",\"role\":\"primary_session_log\",\"origin\":{\"source_id\":\"local\",\"kind\":\"local\",\"host\":null,\"source_version\":null},\"platform\":null,\"workspace_rewrites\":[{\"from\":\"/synthetic/from\",\"to\":\"/synthetic/to\"}]}"
    },
    {
      "test": "d3_missing_and_unknown",
      "case": "missing_input_role",
      "expected": "invalid",
      "direct_scope": "input",
      "raw_utf8": "{\"schema\":\"cass.restore-source-contexts/1\",\"inputs\":[{\"manifest_id\":\"manifest-base\",\"identity_namespace\":\"S42_PRIVATE_NAMESPACE\",\"connector\":\"claude_code\",\"scan_root\":\"/synthetic/S42_PRIVATE_PATH/root\",\"relative_locator\":\"session.jsonl\",\"origin\":{\"source_id\":\"local\",\"kind\":\"local\",\"host\":null,\"source_version\":null},\"platform\":null,\"workspace_rewrites\":[{\"from\":\"/synthetic/from\",\"to\":\"/synthetic/to\"}]}]}",
      "direct_input_utf8": "{\"manifest_id\":\"manifest-base\",\"identity_namespace\":\"S42_PRIVATE_NAMESPACE\",\"connector\":\"claude_code\",\"scan_root\":\"/synthetic/S42_PRIVATE_PATH/root\",\"relative_locator\":\"session.jsonl\",\"origin\":{\"source_id\":\"local\",\"kind\":\"local\",\"host\":null,\"source_version\":null},\"platform\":null,\"workspace_rewrites\":[{\"from\":\"/synthetic/from\",\"to\":\"/synthetic/to\"}]}"
    },
    {
      "test": "d3_missing_and_unknown",
      "case": "missing_input_origin",
      "expected": "invalid",
      "direct_scope": "input",
      "raw_utf8": "{\"schema\":\"cass.restore-source-contexts/1\",\"inputs\":[{\"manifest_id\":\"manifest-base\",\"identity_namespace\":\"S42_PRIVATE_NAMESPACE\",\"connector\":\"claude_code\",\"scan_root\":\"/synthetic/S42_PRIVATE_PATH/root\",\"relative_locator\":\"session.jsonl\",\"role\":\"primary_session_log\",\"platform\":null,\"workspace_rewrites\":[{\"from\":\"/synthetic/from\",\"to\":\"/synthetic/to\"}]}]}",
      "direct_input_utf8": "{\"manifest_id\":\"manifest-base\",\"identity_namespace\":\"S42_PRIVATE_NAMESPACE\",\"connector\":\"claude_code\",\"scan_root\":\"/synthetic/S42_PRIVATE_PATH/root\",\"relative_locator\":\"session.jsonl\",\"role\":\"primary_session_log\",\"platform\":null,\"workspace_rewrites\":[{\"from\":\"/synthetic/from\",\"to\":\"/synthetic/to\"}]}"
    },
    {
      "test": "d3_missing_and_unknown",
      "case": "missing_input_platform",
      "expected": "invalid",
      "direct_scope": "input",
      "raw_utf8": "{\"schema\":\"cass.restore-source-contexts/1\",\"inputs\":[{\"manifest_id\":\"manifest-base\",\"identity_namespace\":\"S42_PRIVATE_NAMESPACE\",\"connector\":\"claude_code\",\"scan_root\":\"/synthetic/S42_PRIVATE_PATH/root\",\"relative_locator\":\"session.jsonl\",\"role\":\"primary_session_log\",\"origin\":{\"source_id\":\"local\",\"kind\":\"local\",\"host\":null,\"source_version\":null},\"workspace_rewrites\":[{\"from\":\"/synthetic/from\",\"to\":\"/synthetic/to\"}]}]}",
      "direct_input_utf8": "{\"manifest_id\":\"manifest-base\",\"identity_namespace\":\"S42_PRIVATE_NAMESPACE\",\"connector\":\"claude_code\",\"scan_root\":\"/synthetic/S42_PRIVATE_PATH/root\",\"relative_locator\":\"session.jsonl\",\"role\":\"primary_session_log\",\"origin\":{\"source_id\":\"local\",\"kind\":\"local\",\"host\":null,\"source_version\":null},\"workspace_rewrites\":[{\"from\":\"/synthetic/from\",\"to\":\"/synthetic/to\"}]}"
    },
    {
      "test": "d3_missing_and_unknown",
      "case": "missing_input_workspace_rewrites",
      "expected": "invalid",
      "direct_scope": "input",
      "raw_utf8": "{\"schema\":\"cass.restore-source-contexts/1\",\"inputs\":[{\"manifest_id\":\"manifest-base\",\"identity_namespace\":\"S42_PRIVATE_NAMESPACE\",\"connector\":\"claude_code\",\"scan_root\":\"/synthetic/S42_PRIVATE_PATH/root\",\"relative_locator\":\"session.jsonl\",\"role\":\"primary_session_log\",\"origin\":{\"source_id\":\"local\",\"kind\":\"local\",\"host\":null,\"source_version\":null},\"platform\":null}]}",
      "direct_input_utf8": "{\"manifest_id\":\"manifest-base\",\"identity_namespace\":\"S42_PRIVATE_NAMESPACE\",\"connector\":\"claude_code\",\"scan_root\":\"/synthetic/S42_PRIVATE_PATH/root\",\"relative_locator\":\"session.jsonl\",\"role\":\"primary_session_log\",\"origin\":{\"source_id\":\"local\",\"kind\":\"local\",\"host\":null,\"source_version\":null},\"platform\":null}"
    },
    {
      "test": "d3_missing_and_unknown",
      "case": "missing_origin_source_id",
      "expected": "invalid",
      "direct_scope": "origin",
      "raw_utf8": "{\"schema\":\"cass.restore-source-contexts/1\",\"inputs\":[{\"manifest_id\":\"manifest-base\",\"identity_namespace\":\"S42_PRIVATE_NAMESPACE\",\"connector\":\"claude_code\",\"scan_root\":\"/synthetic/S42_PRIVATE_PATH/root\",\"relative_locator\":\"session.jsonl\",\"role\":\"primary_session_log\",\"origin\":{\"kind\":\"local\",\"host\":null,\"source_version\":null},\"platform\":null,\"workspace_rewrites\":[{\"from\":\"/synthetic/from\",\"to\":\"/synthetic/to\"}]}]}",
      "direct_input_utf8": "{\"manifest_id\":\"manifest-base\",\"identity_namespace\":\"S42_PRIVATE_NAMESPACE\",\"connector\":\"claude_code\",\"scan_root\":\"/synthetic/S42_PRIVATE_PATH/root\",\"relative_locator\":\"session.jsonl\",\"role\":\"primary_session_log\",\"origin\":{\"kind\":\"local\",\"host\":null,\"source_version\":null},\"platform\":null,\"workspace_rewrites\":[{\"from\":\"/synthetic/from\",\"to\":\"/synthetic/to\"}]}",
      "direct_origin_utf8": "{\"kind\":\"local\",\"host\":null,\"source_version\":null}"
    },
    {
      "test": "d3_missing_and_unknown",
      "case": "missing_origin_kind",
      "expected": "invalid",
      "direct_scope": "origin",
      "raw_utf8": "{\"schema\":\"cass.restore-source-contexts/1\",\"inputs\":[{\"manifest_id\":\"manifest-base\",\"identity_namespace\":\"S42_PRIVATE_NAMESPACE\",\"connector\":\"claude_code\",\"scan_root\":\"/synthetic/S42_PRIVATE_PATH/root\",\"relative_locator\":\"session.jsonl\",\"role\":\"primary_session_log\",\"origin\":{\"source_id\":\"local\",\"host\":null,\"source_version\":null},\"platform\":null,\"workspace_rewrites\":[{\"from\":\"/synthetic/from\",\"to\":\"/synthetic/to\"}]}]}",
      "direct_input_utf8": "{\"manifest_id\":\"manifest-base\",\"identity_namespace\":\"S42_PRIVATE_NAMESPACE\",\"connector\":\"claude_code\",\"scan_root\":\"/synthetic/S42_PRIVATE_PATH/root\",\"relative_locator\":\"session.jsonl\",\"role\":\"primary_session_log\",\"origin\":{\"source_id\":\"local\",\"host\":null,\"source_version\":null},\"platform\":null,\"workspace_rewrites\":[{\"from\":\"/synthetic/from\",\"to\":\"/synthetic/to\"}]}",
      "direct_origin_utf8": "{\"source_id\":\"local\",\"host\":null,\"source_version\":null}"
    },
    {
      "test": "d3_missing_and_unknown",
      "case": "missing_origin_host",
      "expected": "invalid",
      "direct_scope": "origin",
      "raw_utf8": "{\"schema\":\"cass.restore-source-contexts/1\",\"inputs\":[{\"manifest_id\":\"manifest-base\",\"identity_namespace\":\"S42_PRIVATE_NAMESPACE\",\"connector\":\"claude_code\",\"scan_root\":\"/synthetic/S42_PRIVATE_PATH/root\",\"relative_locator\":\"session.jsonl\",\"role\":\"primary_session_log\",\"origin\":{\"source_id\":\"local\",\"kind\":\"local\",\"source_version\":null},\"platform\":null,\"workspace_rewrites\":[{\"from\":\"/synthetic/from\",\"to\":\"/synthetic/to\"}]}]}",
      "direct_input_utf8": "{\"manifest_id\":\"manifest-base\",\"identity_namespace\":\"S42_PRIVATE_NAMESPACE\",\"connector\":\"claude_code\",\"scan_root\":\"/synthetic/S42_PRIVATE_PATH/root\",\"relative_locator\":\"session.jsonl\",\"role\":\"primary_session_log\",\"origin\":{\"source_id\":\"local\",\"kind\":\"local\",\"source_version\":null},\"platform\":null,\"workspace_rewrites\":[{\"from\":\"/synthetic/from\",\"to\":\"/synthetic/to\"}]}",
      "direct_origin_utf8": "{\"source_id\":\"local\",\"kind\":\"local\",\"source_version\":null}"
    },
    {
      "test": "d3_missing_and_unknown",
      "case": "missing_origin_source_version",
      "expected": "invalid",
      "direct_scope": "origin",
      "raw_utf8": "{\"schema\":\"cass.restore-source-contexts/1\",\"inputs\":[{\"manifest_id\":\"manifest-base\",\"identity_namespace\":\"S42_PRIVATE_NAMESPACE\",\"connector\":\"claude_code\",\"scan_root\":\"/synthetic/S42_PRIVATE_PATH/root\",\"relative_locator\":\"session.jsonl\",\"role\":\"primary_session_log\",\"origin\":{\"source_id\":\"local\",\"kind\":\"local\",\"host\":null},\"platform\":null,\"workspace_rewrites\":[{\"from\":\"/synthetic/from\",\"to\":\"/synthetic/to\"}]}]}",
      "direct_input_utf8": "{\"manifest_id\":\"manifest-base\",\"identity_namespace\":\"S42_PRIVATE_NAMESPACE\",\"connector\":\"claude_code\",\"scan_root\":\"/synthetic/S42_PRIVATE_PATH/root\",\"relative_locator\":\"session.jsonl\",\"role\":\"primary_session_log\",\"origin\":{\"source_id\":\"local\",\"kind\":\"local\",\"host\":null},\"platform\":null,\"workspace_rewrites\":[{\"from\":\"/synthetic/from\",\"to\":\"/synthetic/to\"}]}",
      "direct_origin_utf8": "{\"source_id\":\"local\",\"kind\":\"local\",\"host\":null}"
    },
    {
      "test": "d3_missing_and_unknown",
      "case": "missing_rewrite_from",
      "expected": "invalid",
      "direct_scope": "rewrite",
      "raw_utf8": "{\"schema\":\"cass.restore-source-contexts/1\",\"inputs\":[{\"manifest_id\":\"manifest-base\",\"identity_namespace\":\"S42_PRIVATE_NAMESPACE\",\"connector\":\"claude_code\",\"scan_root\":\"/synthetic/S42_PRIVATE_PATH/root\",\"relative_locator\":\"session.jsonl\",\"role\":\"primary_session_log\",\"origin\":{\"source_id\":\"local\",\"kind\":\"local\",\"host\":null,\"source_version\":null},\"platform\":null,\"workspace_rewrites\":[{\"to\":\"/synthetic/to\"}]}]}",
      "direct_input_utf8": "{\"manifest_id\":\"manifest-base\",\"identity_namespace\":\"S42_PRIVATE_NAMESPACE\",\"connector\":\"claude_code\",\"scan_root\":\"/synthetic/S42_PRIVATE_PATH/root\",\"relative_locator\":\"session.jsonl\",\"role\":\"primary_session_log\",\"origin\":{\"source_id\":\"local\",\"kind\":\"local\",\"host\":null,\"source_version\":null},\"platform\":null,\"workspace_rewrites\":[{\"to\":\"/synthetic/to\"}]}"
    },
    {
      "test": "d3_missing_and_unknown",
      "case": "missing_rewrite_to",
      "expected": "invalid",
      "direct_scope": "rewrite",
      "raw_utf8": "{\"schema\":\"cass.restore-source-contexts/1\",\"inputs\":[{\"manifest_id\":\"manifest-base\",\"identity_namespace\":\"S42_PRIVATE_NAMESPACE\",\"connector\":\"claude_code\",\"scan_root\":\"/synthetic/S42_PRIVATE_PATH/root\",\"relative_locator\":\"session.jsonl\",\"role\":\"primary_session_log\",\"origin\":{\"source_id\":\"local\",\"kind\":\"local\",\"host\":null,\"source_version\":null},\"platform\":null,\"workspace_rewrites\":[{\"from\":\"/synthetic/from\"}]}]}",
      "direct_input_utf8": "{\"manifest_id\":\"manifest-base\",\"identity_namespace\":\"S42_PRIVATE_NAMESPACE\",\"connector\":\"claude_code\",\"scan_root\":\"/synthetic/S42_PRIVATE_PATH/root\",\"relative_locator\":\"session.jsonl\",\"role\":\"primary_session_log\",\"origin\":{\"source_id\":\"local\",\"kind\":\"local\",\"host\":null,\"source_version\":null},\"platform\":null,\"workspace_rewrites\":[{\"from\":\"/synthetic/from\"}]}"
    },
    {
      "test": "d3_missing_and_unknown",
      "case": "null_root_schema",
      "expected": "invalid",
      "direct_scope": "root",
      "raw_utf8": "{\"schema\":null,\"inputs\":[{\"manifest_id\":\"manifest-base\",\"identity_namespace\":\"S42_PRIVATE_NAMESPACE\",\"connector\":\"claude_code\",\"scan_root\":\"/synthetic/S42_PRIVATE_PATH/root\",\"relative_locator\":\"session.jsonl\",\"role\":\"primary_session_log\",\"origin\":{\"source_id\":\"local\",\"kind\":\"local\",\"host\":null,\"source_version\":null},\"platform\":null,\"workspace_rewrites\":[{\"from\":\"/synthetic/from\",\"to\":\"/synthetic/to\"}]}]}"
    },
    {
      "test": "d3_missing_and_unknown",
      "case": "null_root_inputs",
      "expected": "invalid",
      "direct_scope": "root",
      "raw_utf8": "{\"schema\":\"cass.restore-source-contexts/1\",\"inputs\":null}"
    },
    {
      "test": "d3_missing_and_unknown",
      "case": "null_input_manifest_id",
      "expected": "invalid",
      "direct_scope": "input",
      "raw_utf8": "{\"schema\":\"cass.restore-source-contexts/1\",\"inputs\":[{\"manifest_id\":null,\"identity_namespace\":\"S42_PRIVATE_NAMESPACE\",\"connector\":\"claude_code\",\"scan_root\":\"/synthetic/S42_PRIVATE_PATH/root\",\"relative_locator\":\"session.jsonl\",\"role\":\"primary_session_log\",\"origin\":{\"source_id\":\"local\",\"kind\":\"local\",\"host\":null,\"source_version\":null},\"platform\":null,\"workspace_rewrites\":[{\"from\":\"/synthetic/from\",\"to\":\"/synthetic/to\"}]}]}",
      "direct_input_utf8": "{\"manifest_id\":null,\"identity_namespace\":\"S42_PRIVATE_NAMESPACE\",\"connector\":\"claude_code\",\"scan_root\":\"/synthetic/S42_PRIVATE_PATH/root\",\"relative_locator\":\"session.jsonl\",\"role\":\"primary_session_log\",\"origin\":{\"source_id\":\"local\",\"kind\":\"local\",\"host\":null,\"source_version\":null},\"platform\":null,\"workspace_rewrites\":[{\"from\":\"/synthetic/from\",\"to\":\"/synthetic/to\"}]}"
    },
    {
      "test": "d3_missing_and_unknown",
      "case": "null_input_identity_namespace",
      "expected": "invalid",
      "direct_scope": "input",
      "raw_utf8": "{\"schema\":\"cass.restore-source-contexts/1\",\"inputs\":[{\"manifest_id\":\"manifest-base\",\"identity_namespace\":null,\"connector\":\"claude_code\",\"scan_root\":\"/synthetic/S42_PRIVATE_PATH/root\",\"relative_locator\":\"session.jsonl\",\"role\":\"primary_session_log\",\"origin\":{\"source_id\":\"local\",\"kind\":\"local\",\"host\":null,\"source_version\":null},\"platform\":null,\"workspace_rewrites\":[{\"from\":\"/synthetic/from\",\"to\":\"/synthetic/to\"}]}]}",
      "direct_input_utf8": "{\"manifest_id\":\"manifest-base\",\"identity_namespace\":null,\"connector\":\"claude_code\",\"scan_root\":\"/synthetic/S42_PRIVATE_PATH/root\",\"relative_locator\":\"session.jsonl\",\"role\":\"primary_session_log\",\"origin\":{\"source_id\":\"local\",\"kind\":\"local\",\"host\":null,\"source_version\":null},\"platform\":null,\"workspace_rewrites\":[{\"from\":\"/synthetic/from\",\"to\":\"/synthetic/to\"}]}"
    },
    {
      "test": "d3_missing_and_unknown",
      "case": "null_input_connector",
      "expected": "invalid",
      "direct_scope": "input",
      "raw_utf8": "{\"schema\":\"cass.restore-source-contexts/1\",\"inputs\":[{\"manifest_id\":\"manifest-base\",\"identity_namespace\":\"S42_PRIVATE_NAMESPACE\",\"connector\":null,\"scan_root\":\"/synthetic/S42_PRIVATE_PATH/root\",\"relative_locator\":\"session.jsonl\",\"role\":\"primary_session_log\",\"origin\":{\"source_id\":\"local\",\"kind\":\"local\",\"host\":null,\"source_version\":null},\"platform\":null,\"workspace_rewrites\":[{\"from\":\"/synthetic/from\",\"to\":\"/synthetic/to\"}]}]}",
      "direct_input_utf8": "{\"manifest_id\":\"manifest-base\",\"identity_namespace\":\"S42_PRIVATE_NAMESPACE\",\"connector\":null,\"scan_root\":\"/synthetic/S42_PRIVATE_PATH/root\",\"relative_locator\":\"session.jsonl\",\"role\":\"primary_session_log\",\"origin\":{\"source_id\":\"local\",\"kind\":\"local\",\"host\":null,\"source_version\":null},\"platform\":null,\"workspace_rewrites\":[{\"from\":\"/synthetic/from\",\"to\":\"/synthetic/to\"}]}"
    },
    {
      "test": "d3_missing_and_unknown",
      "case": "null_input_scan_root",
      "expected": "invalid",
      "direct_scope": "input",
      "raw_utf8": "{\"schema\":\"cass.restore-source-contexts/1\",\"inputs\":[{\"manifest_id\":\"manifest-base\",\"identity_namespace\":\"S42_PRIVATE_NAMESPACE\",\"connector\":\"claude_code\",\"scan_root\":null,\"relative_locator\":\"session.jsonl\",\"role\":\"primary_session_log\",\"origin\":{\"source_id\":\"local\",\"kind\":\"local\",\"host\":null,\"source_version\":null},\"platform\":null,\"workspace_rewrites\":[{\"from\":\"/synthetic/from\",\"to\":\"/synthetic/to\"}]}]}",
      "direct_input_utf8": "{\"manifest_id\":\"manifest-base\",\"identity_namespace\":\"S42_PRIVATE_NAMESPACE\",\"connector\":\"claude_code\",\"scan_root\":null,\"relative_locator\":\"session.jsonl\",\"role\":\"primary_session_log\",\"origin\":{\"source_id\":\"local\",\"kind\":\"local\",\"host\":null,\"source_version\":null},\"platform\":null,\"workspace_rewrites\":[{\"from\":\"/synthetic/from\",\"to\":\"/synthetic/to\"}]}"
    },
    {
      "test": "d3_missing_and_unknown",
      "case": "null_input_relative_locator",
      "expected": "invalid",
      "direct_scope": "input",
      "raw_utf8": "{\"schema\":\"cass.restore-source-contexts/1\",\"inputs\":[{\"manifest_id\":\"manifest-base\",\"identity_namespace\":\"S42_PRIVATE_NAMESPACE\",\"connector\":\"claude_code\",\"scan_root\":\"/synthetic/S42_PRIVATE_PATH/root\",\"relative_locator\":null,\"role\":\"primary_session_log\",\"origin\":{\"source_id\":\"local\",\"kind\":\"local\",\"host\":null,\"source_version\":null},\"platform\":null,\"workspace_rewrites\":[{\"from\":\"/synthetic/from\",\"to\":\"/synthetic/to\"}]}]}",
      "direct_input_utf8": "{\"manifest_id\":\"manifest-base\",\"identity_namespace\":\"S42_PRIVATE_NAMESPACE\",\"connector\":\"claude_code\",\"scan_root\":\"/synthetic/S42_PRIVATE_PATH/root\",\"relative_locator\":null,\"role\":\"primary_session_log\",\"origin\":{\"source_id\":\"local\",\"kind\":\"local\",\"host\":null,\"source_version\":null},\"platform\":null,\"workspace_rewrites\":[{\"from\":\"/synthetic/from\",\"to\":\"/synthetic/to\"}]}"
    },
    {
      "test": "d3_missing_and_unknown",
      "case": "null_input_role",
      "expected": "invalid",
      "direct_scope": "input",
      "raw_utf8": "{\"schema\":\"cass.restore-source-contexts/1\",\"inputs\":[{\"manifest_id\":\"manifest-base\",\"identity_namespace\":\"S42_PRIVATE_NAMESPACE\",\"connector\":\"claude_code\",\"scan_root\":\"/synthetic/S42_PRIVATE_PATH/root\",\"relative_locator\":\"session.jsonl\",\"role\":null,\"origin\":{\"source_id\":\"local\",\"kind\":\"local\",\"host\":null,\"source_version\":null},\"platform\":null,\"workspace_rewrites\":[{\"from\":\"/synthetic/from\",\"to\":\"/synthetic/to\"}]}]}",
      "direct_input_utf8": "{\"manifest_id\":\"manifest-base\",\"identity_namespace\":\"S42_PRIVATE_NAMESPACE\",\"connector\":\"claude_code\",\"scan_root\":\"/synthetic/S42_PRIVATE_PATH/root\",\"relative_locator\":\"session.jsonl\",\"role\":null,\"origin\":{\"source_id\":\"local\",\"kind\":\"local\",\"host\":null,\"source_version\":null},\"platform\":null,\"workspace_rewrites\":[{\"from\":\"/synthetic/from\",\"to\":\"/synthetic/to\"}]}"
    },
    {
      "test": "d3_missing_and_unknown",
      "case": "null_input_origin",
      "expected": "invalid",
      "direct_scope": "input",
      "raw_utf8": "{\"schema\":\"cass.restore-source-contexts/1\",\"inputs\":[{\"manifest_id\":\"manifest-base\",\"identity_namespace\":\"S42_PRIVATE_NAMESPACE\",\"connector\":\"claude_code\",\"scan_root\":\"/synthetic/S42_PRIVATE_PATH/root\",\"relative_locator\":\"session.jsonl\",\"role\":\"primary_session_log\",\"origin\":null,\"platform\":null,\"workspace_rewrites\":[{\"from\":\"/synthetic/from\",\"to\":\"/synthetic/to\"}]}]}",
      "direct_input_utf8": "{\"manifest_id\":\"manifest-base\",\"identity_namespace\":\"S42_PRIVATE_NAMESPACE\",\"connector\":\"claude_code\",\"scan_root\":\"/synthetic/S42_PRIVATE_PATH/root\",\"relative_locator\":\"session.jsonl\",\"role\":\"primary_session_log\",\"origin\":null,\"platform\":null,\"workspace_rewrites\":[{\"from\":\"/synthetic/from\",\"to\":\"/synthetic/to\"}]}"
    },
    {
      "test": "d3_missing_and_unknown",
      "case": "null_input_workspace_rewrites",
      "expected": "invalid",
      "direct_scope": "input",
      "raw_utf8": "{\"schema\":\"cass.restore-source-contexts/1\",\"inputs\":[{\"manifest_id\":\"manifest-base\",\"identity_namespace\":\"S42_PRIVATE_NAMESPACE\",\"connector\":\"claude_code\",\"scan_root\":\"/synthetic/S42_PRIVATE_PATH/root\",\"relative_locator\":\"session.jsonl\",\"role\":\"primary_session_log\",\"origin\":{\"source_id\":\"local\",\"kind\":\"local\",\"host\":null,\"source_version\":null},\"platform\":null,\"workspace_rewrites\":null}]}",
      "direct_input_utf8": "{\"manifest_id\":\"manifest-base\",\"identity_namespace\":\"S42_PRIVATE_NAMESPACE\",\"connector\":\"claude_code\",\"scan_root\":\"/synthetic/S42_PRIVATE_PATH/root\",\"relative_locator\":\"session.jsonl\",\"role\":\"primary_session_log\",\"origin\":{\"source_id\":\"local\",\"kind\":\"local\",\"host\":null,\"source_version\":null},\"platform\":null,\"workspace_rewrites\":null}"
    },
    {
      "test": "d3_missing_and_unknown",
      "case": "null_origin_source_id",
      "expected": "invalid",
      "direct_scope": "origin",
      "raw_utf8": "{\"schema\":\"cass.restore-source-contexts/1\",\"inputs\":[{\"manifest_id\":\"manifest-base\",\"identity_namespace\":\"S42_PRIVATE_NAMESPACE\",\"connector\":\"claude_code\",\"scan_root\":\"/synthetic/S42_PRIVATE_PATH/root\",\"relative_locator\":\"session.jsonl\",\"role\":\"primary_session_log\",\"origin\":{\"source_id\":null,\"kind\":\"local\",\"host\":null,\"source_version\":null},\"platform\":null,\"workspace_rewrites\":[{\"from\":\"/synthetic/from\",\"to\":\"/synthetic/to\"}]}]}",
      "direct_input_utf8": "{\"manifest_id\":\"manifest-base\",\"identity_namespace\":\"S42_PRIVATE_NAMESPACE\",\"connector\":\"claude_code\",\"scan_root\":\"/synthetic/S42_PRIVATE_PATH/root\",\"relative_locator\":\"session.jsonl\",\"role\":\"primary_session_log\",\"origin\":{\"source_id\":null,\"kind\":\"local\",\"host\":null,\"source_version\":null},\"platform\":null,\"workspace_rewrites\":[{\"from\":\"/synthetic/from\",\"to\":\"/synthetic/to\"}]}",
      "direct_origin_utf8": "{\"source_id\":null,\"kind\":\"local\",\"host\":null,\"source_version\":null}"
    },
    {
      "test": "d3_missing_and_unknown",
      "case": "null_origin_kind",
      "expected": "invalid",
      "direct_scope": "origin",
      "raw_utf8": "{\"schema\":\"cass.restore-source-contexts/1\",\"inputs\":[{\"manifest_id\":\"manifest-base\",\"identity_namespace\":\"S42_PRIVATE_NAMESPACE\",\"connector\":\"claude_code\",\"scan_root\":\"/synthetic/S42_PRIVATE_PATH/root\",\"relative_locator\":\"session.jsonl\",\"role\":\"primary_session_log\",\"origin\":{\"source_id\":\"local\",\"kind\":null,\"host\":null,\"source_version\":null},\"platform\":null,\"workspace_rewrites\":[{\"from\":\"/synthetic/from\",\"to\":\"/synthetic/to\"}]}]}",
      "direct_input_utf8": "{\"manifest_id\":\"manifest-base\",\"identity_namespace\":\"S42_PRIVATE_NAMESPACE\",\"connector\":\"claude_code\",\"scan_root\":\"/synthetic/S42_PRIVATE_PATH/root\",\"relative_locator\":\"session.jsonl\",\"role\":\"primary_session_log\",\"origin\":{\"source_id\":\"local\",\"kind\":null,\"host\":null,\"source_version\":null},\"platform\":null,\"workspace_rewrites\":[{\"from\":\"/synthetic/from\",\"to\":\"/synthetic/to\"}]}",
      "direct_origin_utf8": "{\"source_id\":\"local\",\"kind\":null,\"host\":null,\"source_version\":null}"
    },
    {
      "test": "d3_missing_and_unknown",
      "case": "null_rewrite_from",
      "expected": "invalid",
      "direct_scope": "rewrite",
      "raw_utf8": "{\"schema\":\"cass.restore-source-contexts/1\",\"inputs\":[{\"manifest_id\":\"manifest-base\",\"identity_namespace\":\"S42_PRIVATE_NAMESPACE\",\"connector\":\"claude_code\",\"scan_root\":\"/synthetic/S42_PRIVATE_PATH/root\",\"relative_locator\":\"session.jsonl\",\"role\":\"primary_session_log\",\"origin\":{\"source_id\":\"local\",\"kind\":\"local\",\"host\":null,\"source_version\":null},\"platform\":null,\"workspace_rewrites\":[{\"from\":null,\"to\":\"/synthetic/to\"}]}]}",
      "direct_input_utf8": "{\"manifest_id\":\"manifest-base\",\"identity_namespace\":\"S42_PRIVATE_NAMESPACE\",\"connector\":\"claude_code\",\"scan_root\":\"/synthetic/S42_PRIVATE_PATH/root\",\"relative_locator\":\"session.jsonl\",\"role\":\"primary_session_log\",\"origin\":{\"source_id\":\"local\",\"kind\":\"local\",\"host\":null,\"source_version\":null},\"platform\":null,\"workspace_rewrites\":[{\"from\":null,\"to\":\"/synthetic/to\"}]}"
    },
    {
      "test": "d3_missing_and_unknown",
      "case": "null_rewrite_to",
      "expected": "invalid",
      "direct_scope": "rewrite",
      "raw_utf8": "{\"schema\":\"cass.restore-source-contexts/1\",\"inputs\":[{\"manifest_id\":\"manifest-base\",\"identity_namespace\":\"S42_PRIVATE_NAMESPACE\",\"connector\":\"claude_code\",\"scan_root\":\"/synthetic/S42_PRIVATE_PATH/root\",\"relative_locator\":\"session.jsonl\",\"role\":\"primary_session_log\",\"origin\":{\"source_id\":\"local\",\"kind\":\"local\",\"host\":null,\"source_version\":null},\"platform\":null,\"workspace_rewrites\":[{\"from\":\"/synthetic/from\",\"to\":null}]}]}",
      "direct_input_utf8": "{\"manifest_id\":\"manifest-base\",\"identity_namespace\":\"S42_PRIVATE_NAMESPACE\",\"connector\":\"claude_code\",\"scan_root\":\"/synthetic/S42_PRIVATE_PATH/root\",\"relative_locator\":\"session.jsonl\",\"role\":\"primary_session_log\",\"origin\":{\"source_id\":\"local\",\"kind\":\"local\",\"host\":null,\"source_version\":null},\"platform\":null,\"workspace_rewrites\":[{\"from\":\"/synthetic/from\",\"to\":null}]}"
    },
    {
      "test": "d3_missing_and_unknown",
      "case": "unknown_root",
      "expected": "invalid",
      "direct_scope": "root",
      "raw_utf8": "{\"schema\":\"cass.restore-source-contexts/1\",\"inputs\":[{\"manifest_id\":\"manifest-base\",\"identity_namespace\":\"S42_PRIVATE_NAMESPACE\",\"connector\":\"claude_code\",\"scan_root\":\"/synthetic/S42_PRIVATE_PATH/root\",\"relative_locator\":\"session.jsonl\",\"role\":\"primary_session_log\",\"origin\":{\"source_id\":\"local\",\"kind\":\"local\",\"host\":null,\"source_version\":null},\"platform\":null,\"workspace_rewrites\":[{\"from\":\"/synthetic/from\",\"to\":\"/synthetic/to\"}]}],\"S42_PRIVATE_UNKNOWN_KEY\":\"S42_PRIVATE_VALUE\"}"
    },
    {
      "test": "d3_missing_and_unknown",
      "case": "unknown_input",
      "expected": "invalid",
      "direct_scope": "input",
      "raw_utf8": "{\"schema\":\"cass.restore-source-contexts/1\",\"inputs\":[{\"manifest_id\":\"manifest-base\",\"identity_namespace\":\"S42_PRIVATE_NAMESPACE\",\"connector\":\"claude_code\",\"scan_root\":\"/synthetic/S42_PRIVATE_PATH/root\",\"relative_locator\":\"session.jsonl\",\"role\":\"primary_session_log\",\"origin\":{\"source_id\":\"local\",\"kind\":\"local\",\"host\":null,\"source_version\":null},\"platform\":null,\"workspace_rewrites\":[{\"from\":\"/synthetic/from\",\"to\":\"/synthetic/to\"}],\"S42_PRIVATE_UNKNOWN_KEY\":\"S42_PRIVATE_VALUE\"}]}",
      "direct_input_utf8": "{\"manifest_id\":\"manifest-base\",\"identity_namespace\":\"S42_PRIVATE_NAMESPACE\",\"connector\":\"claude_code\",\"scan_root\":\"/synthetic/S42_PRIVATE_PATH/root\",\"relative_locator\":\"session.jsonl\",\"role\":\"primary_session_log\",\"origin\":{\"source_id\":\"local\",\"kind\":\"local\",\"host\":null,\"source_version\":null},\"platform\":null,\"workspace_rewrites\":[{\"from\":\"/synthetic/from\",\"to\":\"/synthetic/to\"}],\"S42_PRIVATE_UNKNOWN_KEY\":\"S42_PRIVATE_VALUE\"}"
    },
    {
      "test": "d3_missing_and_unknown",
      "case": "unknown_origin",
      "expected": "invalid",
      "direct_scope": "origin",
      "raw_utf8": "{\"schema\":\"cass.restore-source-contexts/1\",\"inputs\":[{\"manifest_id\":\"manifest-base\",\"identity_namespace\":\"S42_PRIVATE_NAMESPACE\",\"connector\":\"claude_code\",\"scan_root\":\"/synthetic/S42_PRIVATE_PATH/root\",\"relative_locator\":\"session.jsonl\",\"role\":\"primary_session_log\",\"origin\":{\"source_id\":\"local\",\"kind\":\"local\",\"host\":null,\"source_version\":null,\"S42_PRIVATE_UNKNOWN_KEY\":\"S42_PRIVATE_VALUE\"},\"platform\":null,\"workspace_rewrites\":[{\"from\":\"/synthetic/from\",\"to\":\"/synthetic/to\"}]}]}",
      "direct_input_utf8": "{\"manifest_id\":\"manifest-base\",\"identity_namespace\":\"S42_PRIVATE_NAMESPACE\",\"connector\":\"claude_code\",\"scan_root\":\"/synthetic/S42_PRIVATE_PATH/root\",\"relative_locator\":\"session.jsonl\",\"role\":\"primary_session_log\",\"origin\":{\"source_id\":\"local\",\"kind\":\"local\",\"host\":null,\"source_version\":null,\"S42_PRIVATE_UNKNOWN_KEY\":\"S42_PRIVATE_VALUE\"},\"platform\":null,\"workspace_rewrites\":[{\"from\":\"/synthetic/from\",\"to\":\"/synthetic/to\"}]}",
      "direct_origin_utf8": "{\"source_id\":\"local\",\"kind\":\"local\",\"host\":null,\"source_version\":null,\"S42_PRIVATE_UNKNOWN_KEY\":\"S42_PRIVATE_VALUE\"}"
    },
    {
      "test": "d3_missing_and_unknown",
      "case": "unknown_rewrite",
      "expected": "invalid",
      "direct_scope": "rewrite",
      "raw_utf8": "{\"schema\":\"cass.restore-source-contexts/1\",\"inputs\":[{\"manifest_id\":\"manifest-base\",\"identity_namespace\":\"S42_PRIVATE_NAMESPACE\",\"connector\":\"claude_code\",\"scan_root\":\"/synthetic/S42_PRIVATE_PATH/root\",\"relative_locator\":\"session.jsonl\",\"role\":\"primary_session_log\",\"origin\":{\"source_id\":\"local\",\"kind\":\"local\",\"host\":null,\"source_version\":null},\"platform\":null,\"workspace_rewrites\":[{\"from\":\"/synthetic/from\",\"to\":\"/synthetic/to\",\"agent\":\"S42_PRIVATE_VALUE\"}]}]}",
      "direct_input_utf8": "{\"manifest_id\":\"manifest-base\",\"identity_namespace\":\"S42_PRIVATE_NAMESPACE\",\"connector\":\"claude_code\",\"scan_root\":\"/synthetic/S42_PRIVATE_PATH/root\",\"relative_locator\":\"session.jsonl\",\"role\":\"primary_session_log\",\"origin\":{\"source_id\":\"local\",\"kind\":\"local\",\"host\":null,\"source_version\":null},\"platform\":null,\"workspace_rewrites\":[{\"from\":\"/synthetic/from\",\"to\":\"/synthetic/to\",\"agent\":\"S42_PRIVATE_VALUE\"}]}"
    },
    {
      "test": "d4_duplicate_and_priority",
      "case": "duplicate_manifest_same",
      "expected": "ambiguous",
      "direct_scope": "root",
      "raw_utf8": "{\"schema\":\"cass.restore-source-contexts/1\",\"inputs\":[{\"manifest_id\":\"manifest-base\",\"identity_namespace\":\"S42_PRIVATE_NAMESPACE\",\"connector\":\"claude_code\",\"scan_root\":\"/synthetic/S42_PRIVATE_PATH/root\",\"relative_locator\":\"session.jsonl\",\"role\":\"primary_session_log\",\"origin\":{\"source_id\":\"local\",\"kind\":\"local\",\"host\":null,\"source_version\":null},\"platform\":null,\"workspace_rewrites\":[{\"from\":\"/synthetic/from\",\"to\":\"/synthetic/to\"}]},{\"manifest_id\":\"manifest-base\",\"identity_namespace\":\"S42_PRIVATE_NAMESPACE\",\"connector\":\"claude_code\",\"scan_root\":\"/synthetic/S42_PRIVATE_PATH/root\",\"relative_locator\":\"session.jsonl\",\"role\":\"primary_session_log\",\"origin\":{\"source_id\":\"local\",\"kind\":\"local\",\"host\":null,\"source_version\":null},\"platform\":null,\"workspace_rewrites\":[{\"from\":\"/synthetic/from\",\"to\":\"/synthetic/to\"}]}]}"
    },
    {
      "test": "d4_duplicate_and_priority",
      "case": "duplicate_manifest_different",
      "expected": "ambiguous",
      "direct_scope": "root",
      "raw_utf8": "{\"schema\":\"cass.restore-source-contexts/1\",\"inputs\":[{\"manifest_id\":\"manifest-base\",\"identity_namespace\":\"S42_PRIVATE_NAMESPACE\",\"connector\":\"claude_code\",\"scan_root\":\"/synthetic/S42_PRIVATE_PATH/root\",\"relative_locator\":\"session.jsonl\",\"role\":\"primary_session_log\",\"origin\":{\"source_id\":\"local\",\"kind\":\"local\",\"host\":null,\"source_version\":null},\"platform\":null,\"workspace_rewrites\":[{\"from\":\"/synthetic/from\",\"to\":\"/synthetic/to\"}]},{\"manifest_id\":\"manifest-base\",\"identity_namespace\":\"S42_PRIVATE_NAMESPACE\",\"connector\":\"claude_code\",\"scan_root\":\"/synthetic/S42_PRIVATE_PATH/root\",\"relative_locator\":\"other.jsonl\",\"role\":\"primary_session_log\",\"origin\":{\"source_id\":\"local\",\"kind\":\"local\",\"host\":null,\"source_version\":null},\"platform\":null,\"workspace_rewrites\":[{\"from\":\"/synthetic/from\",\"to\":\"/synthetic/to\"}]}]}"
    },
    {
      "test": "d4_duplicate_and_priority",
      "case": "duplicate_root_key",
      "expected": "invalid",
      "direct_scope": "root",
      "raw_utf8": "{\"schema\":\"cass.restore-source-contexts/1\",\"schema\":\"cass.restore-source-contexts/1\",\"inputs\":[{\"manifest_id\":\"manifest-base\",\"identity_namespace\":\"S42_PRIVATE_NAMESPACE\",\"connector\":\"claude_code\",\"scan_root\":\"/synthetic/S42_PRIVATE_PATH/root\",\"relative_locator\":\"session.jsonl\",\"role\":\"primary_session_log\",\"origin\":{\"source_id\":\"local\",\"kind\":\"local\",\"host\":null,\"source_version\":null},\"platform\":null,\"workspace_rewrites\":[{\"from\":\"/synthetic/from\",\"to\":\"/synthetic/to\"}]}]}"
    },
    {
      "test": "d4_duplicate_and_priority",
      "case": "duplicate_input_key",
      "expected": "invalid",
      "direct_scope": "input",
      "raw_utf8": "{\"schema\":\"cass.restore-source-contexts/1\",\"inputs\":[{\"manifest_id\":\"manifest-base\",\"manifest_id\":\"manifest-base\",\"identity_namespace\":\"S42_PRIVATE_NAMESPACE\",\"connector\":\"claude_code\",\"scan_root\":\"/synthetic/S42_PRIVATE_PATH/root\",\"relative_locator\":\"session.jsonl\",\"role\":\"primary_session_log\",\"origin\":{\"source_id\":\"local\",\"kind\":\"local\",\"host\":null,\"source_version\":null},\"platform\":null,\"workspace_rewrites\":[{\"from\":\"/synthetic/from\",\"to\":\"/synthetic/to\"}]}]}",
      "direct_input_utf8": "{\"manifest_id\":\"manifest-base\",\"manifest_id\":\"manifest-base\",\"identity_namespace\":\"S42_PRIVATE_NAMESPACE\",\"connector\":\"claude_code\",\"scan_root\":\"/synthetic/S42_PRIVATE_PATH/root\",\"relative_locator\":\"session.jsonl\",\"role\":\"primary_session_log\",\"origin\":{\"source_id\":\"local\",\"kind\":\"local\",\"host\":null,\"source_version\":null},\"platform\":null,\"workspace_rewrites\":[{\"from\":\"/synthetic/from\",\"to\":\"/synthetic/to\"}]}"
    },
    {
      "test": "d4_duplicate_and_priority",
      "case": "duplicate_origin_key",
      "expected": "invalid",
      "direct_scope": "origin",
      "raw_utf8": "{\"schema\":\"cass.restore-source-contexts/1\",\"inputs\":[{\"manifest_id\":\"manifest-base\",\"identity_namespace\":\"S42_PRIVATE_NAMESPACE\",\"connector\":\"claude_code\",\"scan_root\":\"/synthetic/S42_PRIVATE_PATH/root\",\"relative_locator\":\"session.jsonl\",\"role\":\"primary_session_log\",\"origin\":{\"kind\":\"local\",\"kind\":\"local\",\"source_id\":\"local\",\"host\":null,\"source_version\":null},\"platform\":null,\"workspace_rewrites\":[{\"from\":\"/synthetic/from\",\"to\":\"/synthetic/to\"}]}]}",
      "direct_input_utf8": "{\"manifest_id\":\"manifest-base\",\"identity_namespace\":\"S42_PRIVATE_NAMESPACE\",\"connector\":\"claude_code\",\"scan_root\":\"/synthetic/S42_PRIVATE_PATH/root\",\"relative_locator\":\"session.jsonl\",\"role\":\"primary_session_log\",\"origin\":{\"kind\":\"local\",\"kind\":\"local\",\"source_id\":\"local\",\"host\":null,\"source_version\":null},\"platform\":null,\"workspace_rewrites\":[{\"from\":\"/synthetic/from\",\"to\":\"/synthetic/to\"}]}",
      "direct_origin_utf8": "{\"kind\":\"local\",\"kind\":\"local\",\"source_id\":\"local\",\"host\":null,\"source_version\":null}"
    },
    {
      "test": "d4_duplicate_and_priority",
      "case": "duplicate_rewrite_key",
      "expected": "invalid",
      "direct_scope": "rewrite",
      "raw_utf8": "{\"schema\":\"cass.restore-source-contexts/1\",\"inputs\":[{\"manifest_id\":\"manifest-base\",\"identity_namespace\":\"S42_PRIVATE_NAMESPACE\",\"connector\":\"claude_code\",\"scan_root\":\"/synthetic/S42_PRIVATE_PATH/root\",\"relative_locator\":\"session.jsonl\",\"role\":\"primary_session_log\",\"origin\":{\"source_id\":\"local\",\"kind\":\"local\",\"host\":null,\"source_version\":null},\"platform\":null,\"workspace_rewrites\":[{\"from\":\"/synthetic/from\",\"from\":\"/synthetic/from\",\"to\":\"/synthetic/to\"}]}]}",
      "direct_input_utf8": "{\"manifest_id\":\"manifest-base\",\"identity_namespace\":\"S42_PRIVATE_NAMESPACE\",\"connector\":\"claude_code\",\"scan_root\":\"/synthetic/S42_PRIVATE_PATH/root\",\"relative_locator\":\"session.jsonl\",\"role\":\"primary_session_log\",\"origin\":{\"source_id\":\"local\",\"kind\":\"local\",\"host\":null,\"source_version\":null},\"platform\":null,\"workspace_rewrites\":[{\"from\":\"/synthetic/from\",\"from\":\"/synthetic/from\",\"to\":\"/synthetic/to\"}]}"
    },
    {
      "test": "d4_duplicate_and_priority",
      "case": "schema_before_duplicates",
      "expected": "invalid",
      "direct_scope": "root",
      "raw_utf8": "{\"schema\":\"cass.restore-source-contexts/1 \",\"inputs\":[{\"manifest_id\":\"manifest-base\",\"identity_namespace\":\"S42_PRIVATE_NAMESPACE\",\"connector\":\"claude_code\",\"scan_root\":\"/synthetic/S42_PRIVATE_PATH/root\",\"relative_locator\":\"session.jsonl\",\"role\":\"primary_session_log\",\"origin\":{\"source_id\":\"local\",\"kind\":\"local\",\"host\":null,\"source_version\":null},\"platform\":null,\"workspace_rewrites\":[{\"from\":\"/synthetic/from\",\"to\":\"/synthetic/to\"}]},{\"manifest_id\":\"manifest-base\",\"identity_namespace\":\"S42_PRIVATE_NAMESPACE\",\"connector\":\"claude_code\",\"scan_root\":\"/synthetic/S42_PRIVATE_PATH/root\",\"relative_locator\":\"session.jsonl\",\"role\":\"primary_session_log\",\"origin\":{\"source_id\":\"local\",\"kind\":\"local\",\"host\":null,\"source_version\":null},\"platform\":null,\"workspace_rewrites\":[{\"from\":\"/synthetic/from\",\"to\":\"/synthetic/to\"}]}]}"
    },
    {
      "test": "d4_duplicate_and_priority",
      "case": "shape_before_duplicates",
      "expected": "invalid",
      "direct_scope": "root",
      "raw_utf8": "{\"schema\":\"cass.restore-source-contexts/1\",\"inputs\":[{\"manifest_id\":\"manifest-base\",\"identity_namespace\":\"S42_PRIVATE_NAMESPACE\",\"connector\":\"claude_code\",\"scan_root\":\"/synthetic/S42_PRIVATE_PATH/root\",\"relative_locator\":\"session.jsonl\",\"role\":\"primary_session_log\",\"origin\":{\"source_id\":\"local\",\"kind\":\"local\",\"host\":null,\"source_version\":null},\"platform\":null,\"workspace_rewrites\":[{\"from\":\"/synthetic/from\",\"to\":\"/synthetic/to\"}]},{\"manifest_id\":\"manifest-base\",\"identity_namespace\":\"S42_PRIVATE_NAMESPACE\",\"connector\":\"claude_code\",\"scan_root\":\"/synthetic/S42_PRIVATE_PATH/root\",\"relative_locator\":\"session.jsonl\",\"role\":\"primary_session_log\",\"origin\":{\"source_id\":\"local\",\"kind\":\"local\",\"host\":null,\"source_version\":null},\"workspace_rewrites\":[{\"from\":\"/synthetic/from\",\"to\":\"/synthetic/to\"}]}]}",
      "direct_input_utf8": "{\"manifest_id\":\"manifest-base\",\"identity_namespace\":\"S42_PRIVATE_NAMESPACE\",\"connector\":\"claude_code\",\"scan_root\":\"/synthetic/S42_PRIVATE_PATH/root\",\"relative_locator\":\"session.jsonl\",\"role\":\"primary_session_log\",\"origin\":{\"source_id\":\"local\",\"kind\":\"local\",\"host\":null,\"source_version\":null},\"workspace_rewrites\":[{\"from\":\"/synthetic/from\",\"to\":\"/synthetic/to\"}]}"
    },
    {
      "test": "d5_invalid_types_and_privacy",
      "case": "invalid_json",
      "expected": "invalid",
      "direct_scope": "root",
      "raw_utf8": "{\"S42_PRIVATE_BROKEN\":"
    },
    {
      "test": "d5_invalid_types_and_privacy",
      "case": "invalid_utf8",
      "expected": "invalid",
      "direct_scope": "root",
      "raw_hex": "7b22ff223a225334325f50524956415445227d"
    },
    {
      "test": "d5_invalid_types_and_privacy",
      "case": "trailing_json",
      "expected": "invalid",
      "direct_scope": "root",
      "raw_utf8": "{\"schema\":\"cass.restore-source-contexts/1\",\"inputs\":[{\"manifest_id\":\"manifest-base\",\"identity_namespace\":\"S42_PRIVATE_NAMESPACE\",\"connector\":\"claude_code\",\"scan_root\":\"/synthetic/S42_PRIVATE_PATH/root\",\"relative_locator\":\"session.jsonl\",\"role\":\"primary_session_log\",\"origin\":{\"source_id\":\"local\",\"kind\":\"local\",\"host\":null,\"source_version\":null},\"platform\":null,\"workspace_rewrites\":[{\"from\":\"/synthetic/from\",\"to\":\"/synthetic/to\"}]}]} {}"
    },
    {
      "test": "d5_invalid_types_and_privacy",
      "case": "inputs_object",
      "expected": "invalid",
      "direct_scope": "root",
      "raw_utf8": "{\"schema\":\"cass.restore-source-contexts/1\",\"inputs\":{}}"
    },
    {
      "test": "d5_invalid_types_and_privacy",
      "case": "platform_invalid",
      "expected": "invalid",
      "direct_scope": "input",
      "raw_utf8": "{\"schema\":\"cass.restore-source-contexts/1\",\"inputs\":[{\"manifest_id\":\"manifest-base\",\"identity_namespace\":\"S42_PRIVATE_NAMESPACE\",\"connector\":\"claude_code\",\"scan_root\":\"/synthetic/S42_PRIVATE_PATH/root\",\"relative_locator\":\"session.jsonl\",\"role\":\"primary_session_log\",\"origin\":{\"source_id\":\"local\",\"kind\":\"local\",\"host\":null,\"source_version\":null},\"platform\":\"Windows\",\"workspace_rewrites\":[{\"from\":\"/synthetic/from\",\"to\":\"/synthetic/to\"}]}]}",
      "direct_input_utf8": "{\"manifest_id\":\"manifest-base\",\"identity_namespace\":\"S42_PRIVATE_NAMESPACE\",\"connector\":\"claude_code\",\"scan_root\":\"/synthetic/S42_PRIVATE_PATH/root\",\"relative_locator\":\"session.jsonl\",\"role\":\"primary_session_log\",\"origin\":{\"source_id\":\"local\",\"kind\":\"local\",\"host\":null,\"source_version\":null},\"platform\":\"Windows\",\"workspace_rewrites\":[{\"from\":\"/synthetic/from\",\"to\":\"/synthetic/to\"}]}"
    },
    {
      "test": "d5_invalid_types_and_privacy",
      "case": "kind_invalid",
      "expected": "invalid",
      "direct_scope": "origin",
      "raw_utf8": "{\"schema\":\"cass.restore-source-contexts/1\",\"inputs\":[{\"manifest_id\":\"manifest-base\",\"identity_namespace\":\"S42_PRIVATE_NAMESPACE\",\"connector\":\"claude_code\",\"scan_root\":\"/synthetic/S42_PRIVATE_PATH/root\",\"relative_locator\":\"session.jsonl\",\"role\":\"primary_session_log\",\"origin\":{\"source_id\":\"local\",\"kind\":\"SSH\",\"host\":null,\"source_version\":null},\"platform\":null,\"workspace_rewrites\":[{\"from\":\"/synthetic/from\",\"to\":\"/synthetic/to\"}]}]}",
      "direct_input_utf8": "{\"manifest_id\":\"manifest-base\",\"identity_namespace\":\"S42_PRIVATE_NAMESPACE\",\"connector\":\"claude_code\",\"scan_root\":\"/synthetic/S42_PRIVATE_PATH/root\",\"relative_locator\":\"session.jsonl\",\"role\":\"primary_session_log\",\"origin\":{\"source_id\":\"local\",\"kind\":\"SSH\",\"host\":null,\"source_version\":null},\"platform\":null,\"workspace_rewrites\":[{\"from\":\"/synthetic/from\",\"to\":\"/synthetic/to\"}]}",
      "direct_origin_utf8": "{\"source_id\":\"local\",\"kind\":\"SSH\",\"host\":null,\"source_version\":null}"
    },
    {
      "test": "d5_invalid_types_and_privacy",
      "case": "role_invalid",
      "expected": "invalid",
      "direct_scope": "input",
      "raw_utf8": "{\"schema\":\"cass.restore-source-contexts/1\",\"inputs\":[{\"manifest_id\":\"manifest-base\",\"identity_namespace\":\"S42_PRIVATE_NAMESPACE\",\"connector\":\"claude_code\",\"scan_root\":\"/synthetic/S42_PRIVATE_PATH/root\",\"relative_locator\":\"session.jsonl\",\"role\":\"S42_PRIVATE_ROLE\",\"origin\":{\"source_id\":\"local\",\"kind\":\"local\",\"host\":null,\"source_version\":null},\"platform\":null,\"workspace_rewrites\":[{\"from\":\"/synthetic/from\",\"to\":\"/synthetic/to\"}]}]}",
      "direct_input_utf8": "{\"manifest_id\":\"manifest-base\",\"identity_namespace\":\"S42_PRIVATE_NAMESPACE\",\"connector\":\"claude_code\",\"scan_root\":\"/synthetic/S42_PRIVATE_PATH/root\",\"relative_locator\":\"session.jsonl\",\"role\":\"S42_PRIVATE_ROLE\",\"origin\":{\"source_id\":\"local\",\"kind\":\"local\",\"host\":null,\"source_version\":null},\"platform\":null,\"workspace_rewrites\":[{\"from\":\"/synthetic/from\",\"to\":\"/synthetic/to\"}]}"
    },
    {
      "test": "d5_invalid_types_and_privacy",
      "case": "agents_invalid",
      "expected": "invalid",
      "direct_scope": "rewrite",
      "raw_utf8": "{\"schema\":\"cass.restore-source-contexts/1\",\"inputs\":[{\"manifest_id\":\"manifest-base\",\"identity_namespace\":\"S42_PRIVATE_NAMESPACE\",\"connector\":\"claude_code\",\"scan_root\":\"/synthetic/S42_PRIVATE_PATH/root\",\"relative_locator\":\"session.jsonl\",\"role\":\"primary_session_log\",\"origin\":{\"source_id\":\"local\",\"kind\":\"local\",\"host\":null,\"source_version\":null},\"platform\":null,\"workspace_rewrites\":[{\"from\":\"/synthetic/from\",\"to\":\"/synthetic/to\",\"agents\":[1]}]}]}",
      "direct_input_utf8": "{\"manifest_id\":\"manifest-base\",\"identity_namespace\":\"S42_PRIVATE_NAMESPACE\",\"connector\":\"claude_code\",\"scan_root\":\"/synthetic/S42_PRIVATE_PATH/root\",\"relative_locator\":\"session.jsonl\",\"role\":\"primary_session_log\",\"origin\":{\"source_id\":\"local\",\"kind\":\"local\",\"host\":null,\"source_version\":null},\"platform\":null,\"workspace_rewrites\":[{\"from\":\"/synthetic/from\",\"to\":\"/synthetic/to\",\"agents\":[1]}]}"
    },
    {
      "test": "d5_invalid_types_and_privacy",
      "case": "string_type",
      "expected": "invalid",
      "direct_scope": "input",
      "raw_utf8": "{\"schema\":\"cass.restore-source-contexts/1\",\"inputs\":[{\"manifest_id\":17,\"identity_namespace\":\"S42_PRIVATE_NAMESPACE\",\"connector\":\"claude_code\",\"scan_root\":\"/synthetic/S42_PRIVATE_PATH/root\",\"relative_locator\":\"session.jsonl\",\"role\":\"primary_session_log\",\"origin\":{\"source_id\":\"local\",\"kind\":\"local\",\"host\":null,\"source_version\":null},\"platform\":null,\"workspace_rewrites\":[{\"from\":\"/synthetic/from\",\"to\":\"/synthetic/to\"}]}]}",
      "direct_input_utf8": "{\"manifest_id\":17,\"identity_namespace\":\"S42_PRIVATE_NAMESPACE\",\"connector\":\"claude_code\",\"scan_root\":\"/synthetic/S42_PRIVATE_PATH/root\",\"relative_locator\":\"session.jsonl\",\"role\":\"primary_session_log\",\"origin\":{\"source_id\":\"local\",\"kind\":\"local\",\"host\":null,\"source_version\":null},\"platform\":null,\"workspace_rewrites\":[{\"from\":\"/synthetic/from\",\"to\":\"/synthetic/to\"}]}"
    },
    {
      "test": "d5_invalid_types_and_privacy",
      "case": "agents_scalar",
      "expected": "invalid",
      "direct_scope": "rewrite",
      "raw_utf8": "{\"schema\":\"cass.restore-source-contexts/1\",\"inputs\":[{\"manifest_id\":\"manifest-base\",\"identity_namespace\":\"S42_PRIVATE_NAMESPACE\",\"connector\":\"claude_code\",\"scan_root\":\"/synthetic/S42_PRIVATE_PATH/root\",\"relative_locator\":\"session.jsonl\",\"role\":\"primary_session_log\",\"origin\":{\"source_id\":\"local\",\"kind\":\"local\",\"host\":null,\"source_version\":null},\"platform\":null,\"workspace_rewrites\":[{\"from\":\"/synthetic/from\",\"to\":\"/synthetic/to\",\"agents\":\"S42_PRIVATE_AGENT\"}]}]}",
      "direct_input_utf8": "{\"manifest_id\":\"manifest-base\",\"identity_namespace\":\"S42_PRIVATE_NAMESPACE\",\"connector\":\"claude_code\",\"scan_root\":\"/synthetic/S42_PRIVATE_PATH/root\",\"relative_locator\":\"session.jsonl\",\"role\":\"primary_session_log\",\"origin\":{\"source_id\":\"local\",\"kind\":\"local\",\"host\":null,\"source_version\":null},\"platform\":null,\"workspace_rewrites\":[{\"from\":\"/synthetic/from\",\"to\":\"/synthetic/to\",\"agents\":\"S42_PRIVATE_AGENT\"}]}"
    },
    {
      "test": "d5_invalid_types_and_privacy",
      "case": "role_case",
      "expected": "invalid",
      "direct_scope": "input",
      "raw_utf8": "{\"schema\":\"cass.restore-source-contexts/1\",\"inputs\":[{\"manifest_id\":\"manifest-base\",\"identity_namespace\":\"S42_PRIVATE_NAMESPACE\",\"connector\":\"claude_code\",\"scan_root\":\"/synthetic/S42_PRIVATE_PATH/root\",\"relative_locator\":\"session.jsonl\",\"role\":\"PRIMARY_SESSION_LOG\",\"origin\":{\"source_id\":\"local\",\"kind\":\"local\",\"host\":null,\"source_version\":null},\"platform\":null,\"workspace_rewrites\":[{\"from\":\"/synthetic/from\",\"to\":\"/synthetic/to\"}]}]}",
      "direct_input_utf8": "{\"manifest_id\":\"manifest-base\",\"identity_namespace\":\"S42_PRIVATE_NAMESPACE\",\"connector\":\"claude_code\",\"scan_root\":\"/synthetic/S42_PRIVATE_PATH/root\",\"relative_locator\":\"session.jsonl\",\"role\":\"PRIMARY_SESSION_LOG\",\"origin\":{\"source_id\":\"local\",\"kind\":\"local\",\"host\":null,\"source_version\":null},\"platform\":null,\"workspace_rewrites\":[{\"from\":\"/synthetic/from\",\"to\":\"/synthetic/to\"}]}"
    },
    {
      "test": "d5_invalid_types_and_privacy",
      "case": "schema_case",
      "expected": "invalid",
      "direct_scope": "root",
      "raw_utf8": "{\"schema\":\"CASS.restore-source-contexts/1\",\"inputs\":[{\"manifest_id\":\"manifest-base\",\"identity_namespace\":\"S42_PRIVATE_NAMESPACE\",\"connector\":\"claude_code\",\"scan_root\":\"/synthetic/S42_PRIVATE_PATH/root\",\"relative_locator\":\"session.jsonl\",\"role\":\"primary_session_log\",\"origin\":{\"source_id\":\"local\",\"kind\":\"local\",\"host\":null,\"source_version\":null},\"platform\":null,\"workspace_rewrites\":[{\"from\":\"/synthetic/from\",\"to\":\"/synthetic/to\"}]}]}"
    },
    {
      "test": "d5_invalid_types_and_privacy",
      "case": "schema_version",
      "expected": "invalid",
      "direct_scope": "root",
      "raw_utf8": "{\"schema\":\"cass.restore-source-contexts/2\",\"inputs\":[{\"manifest_id\":\"manifest-base\",\"identity_namespace\":\"S42_PRIVATE_NAMESPACE\",\"connector\":\"claude_code\",\"scan_root\":\"/synthetic/S42_PRIVATE_PATH/root\",\"relative_locator\":\"session.jsonl\",\"role\":\"primary_session_log\",\"origin\":{\"source_id\":\"local\",\"kind\":\"local\",\"host\":null,\"source_version\":null},\"platform\":null,\"workspace_rewrites\":[{\"from\":\"/synthetic/from\",\"to\":\"/synthetic/to\"}]}]}"
    }
  ]
}
"##;

    /// One complete, valid declaration used as the positive control before each
    /// negative case.
    const CONTROL_ROOT: &str = r#"{"schema":"cass.restore-source-contexts/1","inputs":[{"manifest_id":"manifest-control","identity_namespace":"S42_PRIVATE_NAMESPACE","connector":"claude_code","scan_root":"/synthetic/S42_PRIVATE_PATH/root","relative_locator":"session.jsonl","role":"primary_session_log","origin":{"source_id":"local","kind":"local","host":null,"source_version":null},"platform":null,"workspace_rewrites":[{"from":"/synthetic/from","to":"/synthetic/to"}]}]}"#;

    fn fixtures() -> Value {
        serde_json::from_str(FIXTURES_JSON).expect("fixture document parses")
    }

    fn cases_for(test: &str) -> Vec<Value> {
        fixtures()["cases"]
            .as_array()
            .expect("cases array")
            .iter()
            .filter(|case| case["test"].as_str() == Some(test))
            .cloned()
            .collect()
    }

    fn hex_value(nibble: u8) -> u8 {
        match nibble {
            b'0'..=b'9' => nibble - b'0',
            b'a'..=b'f' => nibble - b'a' + 10,
            _ => panic!("invalid hex nibble"),
        }
    }

    fn hex_to_bytes(hex: &str) -> Vec<u8> {
        let bytes = hex.as_bytes();
        assert_eq!(bytes.len() % 2, 0, "hex length must be even");
        bytes
            .chunks(2)
            .map(|pair| (hex_value(pair[0]) << 4) | hex_value(pair[1]))
            .collect()
    }

    fn raw_bytes(case: &Value) -> Vec<u8> {
        if let Some(text) = case.get("raw_utf8").and_then(Value::as_str) {
            text.as_bytes().to_vec()
        } else if let Some(hex) = case.get("raw_hex").and_then(Value::as_str) {
            hex_to_bytes(hex)
        } else {
            panic!("case has neither raw_utf8 nor raw_hex")
        }
    }

    fn assert_no_material(text: &str) {
        for needle in ["S42_PRIVATE", "synthetic", "not-catalogued", "future_connector"] {
            assert!(!text.contains(needle), "error leaked material `{needle}`: {text}");
        }
    }

    fn assert_control_ok() {
        let bytes = CONTROL_ROOT.as_bytes();
        match decode_restore_source_contexts(bytes) {
            Ok(_) => {}
            Err(error) => panic!("control decode failed: {error}"),
        }
        match serde_json::from_slice::<RestoreSourceContexts>(bytes) {
            Ok(_) => {}
            Err(error) => panic!("control direct root failed: {error}"),
        }
    }

    fn assert_ok_case(test: &str, case: &Value) {
        let case_id = case["case"].as_str().expect("case id");
        let raw = raw_bytes(case);
        let before = raw.clone();
        let expected = case.get("expected_value").expect("expected_value present");

        let decoded = match decode_restore_source_contexts(&raw) {
            Ok(value) => value,
            Err(error) => panic!("decode rejected {test}/{case_id}: {error}"),
        };
        assert_eq!(raw, before, "decode mutated input bytes for {test}/{case_id}");
        let decoded_value = serde_json::to_value(&decoded).expect("serialize decoded");
        assert_eq!(&decoded_value, expected, "decoded value mismatch for {test}/{case_id}");

        let direct = match serde_json::from_slice::<RestoreSourceContexts>(&raw) {
            Ok(value) => value,
            Err(error) => panic!("direct root rejected {test}/{case_id}: {error}"),
        };
        assert_eq!(
            serde_json::to_value(&direct).expect("serialize direct root"),
            *expected,
            "direct root value mismatch for {test}/{case_id}"
        );

        let entries = expected["inputs"].as_array().expect("inputs array");
        assert_eq!(entries.len(), decoded.inputs.len(), "input count for {test}/{case_id}");
        for (index, entry) in entries.iter().enumerate() {
            let decoded_entry = serde_json::to_value(&decoded.inputs[index]).expect("serialize entry");
            assert_eq!(&decoded_entry, entry, "decoded entry {index} mismatch for {test}/{case_id}");

            let entry_bytes = serde_json::to_vec(entry).expect("serialize expected entry");
            let direct_entry =
                match serde_json::from_slice::<RestoreSourceContextDeclaration>(&entry_bytes) {
                    Ok(value) => value,
                    Err(error) => panic!("direct entry rejected {test}/{case_id}/{index}: {error}"),
                };
            assert_eq!(
                serde_json::to_value(&direct_entry).expect("serialize direct entry"),
                *entry,
                "direct entry {index} mismatch for {test}/{case_id}"
            );

            let origin = entry.get("origin").expect("origin present");
            let origin_bytes = serde_json::to_vec(origin).expect("serialize expected origin");
            let direct_origin =
                match serde_json::from_slice::<RestoreSourceContextOrigin>(&origin_bytes) {
                    Ok(value) => value,
                    Err(error) => panic!("direct origin rejected {test}/{case_id}/{index}: {error}"),
                };
            assert_eq!(
                serde_json::to_value(&direct_origin).expect("serialize direct origin"),
                *origin,
                "direct origin {index} mismatch for {test}/{case_id}"
            );
        }

        println!("RESTORE_CONTEXT_DECODE_SCENARIO test={test} case={case_id} result=pass");
    }

    fn assert_error_case(case: &Value) {
        let test = case["test"].as_str().expect("test name");
        let case_id = case["case"].as_str().expect("case id");
        let expected = case["expected"].as_str().expect("expected kind");
        let raw = raw_bytes(case);

        assert_control_ok();

        let error = match decode_restore_source_contexts(&raw) {
            Ok(_) => panic!("decode accepted {test}/{case_id} but expected {expected}"),
            Err(error) => error,
        };
        let code = match expected {
            "invalid" => "source_restore_context_invalid",
            "ambiguous" => "source_restore_context_ambiguous",
            other => panic!("unexpected expected kind `{other}`"),
        };
        assert_eq!(error.to_string(), code, "function Display for {test}/{case_id}");
        assert_no_material(&format!("{error:?}"));

        let mut source = std::error::Error::source(&error);
        while let Some(inner) = source {
            assert_no_material(&inner.to_string());
            source = std::error::Error::source(inner);
        }

        match serde_json::from_slice::<RestoreSourceContexts>(&raw) {
            Ok(_) => panic!("direct root accepted {test}/{case_id}"),
            Err(direct_error) => assert_no_material(&direct_error.to_string()),
        }

        if let Some(input) = case.get("direct_input_utf8").and_then(Value::as_str) {
            match serde_json::from_slice::<RestoreSourceContextDeclaration>(input.as_bytes()) {
                Ok(_) => panic!("direct declaration accepted {test}/{case_id}"),
                Err(direct_error) => assert_no_material(&direct_error.to_string()),
            }
        }

        if let Some(origin) = case.get("direct_origin_utf8").and_then(Value::as_str) {
            match serde_json::from_slice::<RestoreSourceContextOrigin>(origin.as_bytes()) {
                Ok(_) => panic!("direct origin accepted {test}/{case_id}"),
                Err(direct_error) => assert_no_material(&direct_error.to_string()),
            }
        }

        println!("RESTORE_CONTEXT_DECODE_SCENARIO test={test} case={case_id} result=pass");
    }

    #[test]
    fn d1_valid_roundtrip() {
        let cases = cases_for("d1_valid_roundtrip");
        assert_eq!(cases.len(), 4);
        for case in &cases {
            assert_ok_case("d1_valid_roundtrip", case);
        }
    }

    #[test]
    fn d2_shape_is_not_binding() {
        let cases = cases_for("d2_shape_is_not_binding");
        assert_eq!(cases.len(), 4);
        for case in &cases {
            assert_ok_case("d2_shape_is_not_binding", case);
        }
    }

    #[test]
    fn d3_missing_and_unknown() {
        let cases = cases_for("d3_missing_and_unknown");
        assert_eq!(cases.len(), 35);
        for case in &cases {
            assert_error_case(case);
        }
    }

    #[test]
    fn d4_duplicate_and_priority() {
        let cases = cases_for("d4_duplicate_and_priority");
        assert_eq!(cases.len(), 8);
        for case in &cases {
            assert_error_case(case);
        }
    }

    #[test]
    fn d5_invalid_types_and_privacy() {
        let cases = cases_for("d5_invalid_types_and_privacy");
        assert_eq!(cases.len(), 13);
        for case in &cases {
            assert_error_case(case);
        }
    }
}
