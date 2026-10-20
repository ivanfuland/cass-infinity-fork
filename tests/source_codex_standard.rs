//! Task12 Codex standard mapper tests.
//!
//! Exactly six test functions. The original fourteen cases come from the fixed
//! product gold copy. The extra eighteen cases are embedded below as one fixed
//! independent literal. No expected data is generated from the mapper.

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::sync::OnceLock;

use coding_agent_search::storage::source_facts::{SourceFormat, map_codex_standard};
use franken_agent_detection::LosslessSourceValue;
use serde_json::{Value, json};

const BOUNDARY_JSON: &str = r#"{
  "schema": "cass.codex-mapper-boundary/1",
  "expected_origin": "Controller-authored complete literal facts; frozen de50 cross-check and explicit known original-scope gaps/positive controls. No product imports or candidate output. Original24/16 unchanged.",
  "spec_sha256": "131d3ed17d99c0661e0e138571e73b8085017531be31fc324cd8b1575fbc334a",
  "cases": [
    {
      "id": "db01-root-array",
      "connector": "codex",
      "format": "jsonl",
      "input_json": "[null,1]",
      "expected_standard": {
        "model": {
          "field": "model",
          "status": "missing",
          "reason": "not_applicable"
        },
        "provider": {
          "field": "provider",
          "status": "missing",
          "reason": "not_applicable"
        },
        "native_ids": {},
        "times": {
          "event": {
            "field": "time",
            "status": "missing",
            "reason": "absent",
            "presence_ref": "/timestamp"
          }
        },
        "tools": [],
        "usage": [],
        "messages": []
      }
    },
    {
      "id": "db02-null-payload",
      "connector": "codex",
      "format": "jsonl",
      "input_json": "{\"type\":\"turn_context\",\"payload\":null}",
      "expected_standard": {
        "model": {
          "field": "model",
          "status": "missing",
          "reason": "absent",
          "presence_ref": "/payload/model"
        },
        "provider": {
          "field": "provider",
          "status": "missing",
          "reason": "not_applicable"
        },
        "native_ids": {},
        "times": {
          "event": {
            "field": "time",
            "status": "missing",
            "reason": "absent",
            "presence_ref": "/timestamp"
          }
        },
        "tools": [],
        "usage": [],
        "messages": []
      }
    },
    {
      "id": "db03-null-model",
      "connector": "codex",
      "format": "jsonl",
      "input_json": "{\"type\":\"turn_context\",\"payload\":{\"model\":null}}",
      "expected_standard": {
        "model": {
          "field": "model",
          "status": "missing",
          "reason": "null",
          "raw_ref": "/payload/model"
        },
        "provider": {
          "field": "provider",
          "status": "missing",
          "reason": "not_applicable"
        },
        "native_ids": {},
        "times": {
          "event": {
            "field": "time",
            "status": "missing",
            "reason": "absent",
            "presence_ref": "/timestamp"
          }
        },
        "tools": [],
        "usage": [],
        "messages": []
      }
    },
    {
      "id": "db04-session-id-and-types",
      "connector": "codex",
      "format": "jsonl",
      "input_json": "{\"type\":\"session_meta\",\"payload\":{\"id\":\" \",\"model_provider\":false,\"cwd\":9,\"timestamp\":null}}",
      "expected_standard": {
        "model": {
          "field": "model",
          "status": "missing",
          "reason": "not_applicable"
        },
        "provider": {
          "field": "provider",
          "status": "invalid",
          "reason": "bad_type",
          "raw_ref": "/payload/model_provider"
        },
        "native_ids": {
          "session_metadata_id": {
            "field": "session_metadata_id",
            "status": "invalid",
            "reason": "empty_id",
            "raw_ref": "/payload/id"
          },
          "cwd": {
            "field": "cwd",
            "status": "invalid",
            "reason": "bad_type",
            "raw_ref": "/payload/cwd"
          }
        },
        "times": {
          "event": {
            "field": "time",
            "status": "missing",
            "reason": "absent",
            "presence_ref": "/timestamp"
          },
          "payload": {
            "field": "time",
            "status": "missing",
            "reason": "null",
            "raw_ref": "/payload/timestamp"
          }
        },
        "tools": [],
        "usage": [],
        "messages": []
      }
    },
    {
      "id": "db05-call-no-arguments",
      "connector": "codex",
      "format": "jsonl",
      "input_json": "{\"type\":\"response_item\",\"payload\":{\"type\":\"function_call\"}}",
      "expected_standard": {
        "model": {
          "field": "model",
          "status": "missing",
          "reason": "not_applicable"
        },
        "provider": {
          "field": "provider",
          "status": "missing",
          "reason": "not_applicable"
        },
        "native_ids": {
          "item_id": {
            "field": "item_id",
            "status": "missing",
            "reason": "absent",
            "presence_ref": "/payload/id"
          },
          "call_id": {
            "field": "call_id",
            "status": "missing",
            "reason": "absent",
            "presence_ref": "/payload/call_id"
          }
        },
        "times": {
          "event": {
            "field": "time",
            "status": "missing",
            "reason": "absent",
            "presence_ref": "/timestamp"
          }
        },
        "tools": [
          {
            "kind": "call",
            "raw_ref": "/payload",
            "name": {
              "field": "name",
              "status": "missing",
              "reason": "absent",
              "presence_ref": "/payload/name"
            },
            "id": {
              "field": "id",
              "status": "missing",
              "reason": "absent",
              "presence_ref": "/payload/call_id"
            },
            "arguments": {
              "field": "arguments",
              "status": "missing",
              "reason": "absent",
              "presence_ref": "/payload/arguments"
            }
          }
        ],
        "usage": [],
        "messages": []
      }
    },
    {
      "id": "db06-call-null-id-no-fallback",
      "connector": "codex",
      "format": "jsonl",
      "input_json": "{\"type\":\"event_msg\",\"payload\":{\"type\":\"function_call\",\"call_id\":null,\"id\":\"fallback\"}}",
      "expected_standard": {
        "model": {
          "field": "model",
          "status": "missing",
          "reason": "not_applicable"
        },
        "provider": {
          "field": "provider",
          "status": "missing",
          "reason": "not_applicable"
        },
        "native_ids": {
          "call_id": {
            "field": "call_id",
            "status": "missing",
            "reason": "null",
            "raw_ref": "/payload/call_id"
          },
          "record_id": {
            "field": "record_id",
            "status": "present",
            "value": "fallback",
            "raw_ref": "/payload/id"
          }
        },
        "times": {
          "event": {
            "field": "time",
            "status": "missing",
            "reason": "absent",
            "presence_ref": "/timestamp"
          }
        },
        "tools": [
          {
            "kind": "event",
            "raw_ref": "/payload",
            "event_type": {
              "field": "event_type",
              "status": "present",
              "value": "function_call",
              "raw_ref": "/payload/type"
            },
            "status": {
              "field": "status",
              "status": "missing",
              "reason": "absent",
              "presence_ref": "/payload/status"
            }
          },
          {
            "kind": "call",
            "raw_ref": "/payload",
            "name": {
              "field": "name",
              "status": "missing",
              "reason": "absent",
              "presence_ref": "/payload/name"
            },
            "id": {
              "field": "id",
              "status": "missing",
              "reason": "null",
              "raw_ref": "/payload/call_id"
            },
            "arguments": {
              "field": "arguments",
              "status": "missing",
              "reason": "absent",
              "presence_ref": "/payload/arguments"
            }
          }
        ],
        "usage": [],
        "messages": []
      }
    },
    {
      "id": "db07-result-false-status",
      "connector": "codex",
      "format": "jsonl",
      "input_json": "{\"type\":\"response_item\",\"payload\":{\"type\":\"function_call_output\",\"call_id\":false,\"output\":null,\"status\":false}}",
      "expected_standard": {
        "model": {
          "field": "model",
          "status": "missing",
          "reason": "not_applicable"
        },
        "provider": {
          "field": "provider",
          "status": "missing",
          "reason": "not_applicable"
        },
        "native_ids": {
          "item_id": {
            "field": "item_id",
            "status": "missing",
            "reason": "absent",
            "presence_ref": "/payload/id"
          },
          "call_id": {
            "field": "call_id",
            "status": "invalid",
            "reason": "bad_type",
            "raw_ref": "/payload/call_id"
          }
        },
        "times": {
          "event": {
            "field": "time",
            "status": "missing",
            "reason": "absent",
            "presence_ref": "/timestamp"
          }
        },
        "tools": [
          {
            "kind": "result",
            "raw_ref": "/payload/output",
            "id": {
              "field": "id",
              "status": "invalid",
              "reason": "bad_type",
              "raw_ref": "/payload/call_id"
            },
            "output": {
              "field": "output",
              "status": "missing",
              "reason": "null",
              "raw_ref": "/payload/output"
            },
            "status": {
              "field": "status",
              "status": "invalid",
              "reason": "unmapped",
              "raw_ref": "/payload/status",
              "value": false
            }
          }
        ],
        "usage": [],
        "messages": []
      }
    },
    {
      "id": "db08-token-count-no-id-promotion",
      "connector": "codex",
      "format": "jsonl",
      "input_json": "{\"type\":\"event_msg\",\"payload\":{\"type\":\"token_count\",\"response_id\":\"r\",\"thread_id\":\"t\",\"turn_id\":\"u\",\"id\":\"i\",\"call_id\":\"c\"}}",
      "expected_standard": {
        "model": {
          "field": "model",
          "status": "missing",
          "reason": "not_applicable"
        },
        "provider": {
          "field": "provider",
          "status": "missing",
          "reason": "not_applicable"
        },
        "native_ids": {},
        "times": {
          "event": {
            "field": "time",
            "status": "missing",
            "reason": "absent",
            "presence_ref": "/timestamp"
          }
        },
        "tools": [],
        "usage": [],
        "messages": []
      }
    },
    {
      "id": "db09-usage-record-container-types",
      "connector": "codex",
      "format": "jsonl",
      "input_json": "{\"type\":\"token_usage_record\",\"payload\":{\"usage\":null,\"turn_token_usage\":false,\"thread_token_usage\":[]}}",
      "expected_standard": {
        "model": {
          "field": "model",
          "status": "missing",
          "reason": "not_applicable"
        },
        "provider": {
          "field": "provider",
          "status": "missing",
          "reason": "not_applicable"
        },
        "native_ids": {
          "response_id": {
            "field": "response_id",
            "status": "missing",
            "reason": "absent",
            "presence_ref": "/payload/response_id"
          },
          "thread_id": {
            "field": "thread_id",
            "status": "missing",
            "reason": "absent",
            "presence_ref": "/payload/thread_id"
          },
          "turn_id": {
            "field": "turn_id",
            "status": "missing",
            "reason": "absent",
            "presence_ref": "/payload/turn_id"
          }
        },
        "times": {
          "event": {
            "field": "time",
            "status": "missing",
            "reason": "absent",
            "presence_ref": "/timestamp"
          }
        },
        "tools": [],
        "usage": [
          {
            "scope": "token_usage_record_usage",
            "role": "snapshot",
            "raw_ref": "/payload/usage",
            "fields": {
              "input": {
                "field": "input",
                "status": "missing",
                "reason": "null",
                "raw_ref": "/payload/usage"
              },
              "output": {
                "field": "output",
                "status": "missing",
                "reason": "null",
                "raw_ref": "/payload/usage"
              },
              "cache_read": {
                "field": "cache_read",
                "status": "missing",
                "reason": "null",
                "raw_ref": "/payload/usage"
              },
              "cache_write": {
                "field": "cache_write",
                "status": "missing",
                "reason": "null",
                "raw_ref": "/payload/usage"
              },
              "thinking": {
                "field": "thinking",
                "status": "missing",
                "reason": "null",
                "raw_ref": "/payload/usage"
              },
              "total": {
                "field": "total",
                "status": "missing",
                "reason": "null",
                "raw_ref": "/payload/usage"
              }
            }
          },
          {
            "scope": "token_usage_record_turn",
            "role": "snapshot",
            "raw_ref": "/payload/turn_token_usage",
            "fields": {
              "input": {
                "field": "input",
                "status": "invalid",
                "reason": "bad_type",
                "raw_ref": "/payload/turn_token_usage"
              },
              "output": {
                "field": "output",
                "status": "invalid",
                "reason": "bad_type",
                "raw_ref": "/payload/turn_token_usage"
              },
              "cache_read": {
                "field": "cache_read",
                "status": "invalid",
                "reason": "bad_type",
                "raw_ref": "/payload/turn_token_usage"
              },
              "cache_write": {
                "field": "cache_write",
                "status": "invalid",
                "reason": "bad_type",
                "raw_ref": "/payload/turn_token_usage"
              },
              "thinking": {
                "field": "thinking",
                "status": "invalid",
                "reason": "bad_type",
                "raw_ref": "/payload/turn_token_usage"
              },
              "total": {
                "field": "total",
                "status": "invalid",
                "reason": "bad_type",
                "raw_ref": "/payload/turn_token_usage"
              }
            }
          },
          {
            "scope": "token_usage_record_thread",
            "role": "snapshot",
            "raw_ref": "/payload/thread_token_usage",
            "fields": {
              "input": {
                "field": "input",
                "status": "invalid",
                "reason": "bad_type",
                "raw_ref": "/payload/thread_token_usage"
              },
              "output": {
                "field": "output",
                "status": "invalid",
                "reason": "bad_type",
                "raw_ref": "/payload/thread_token_usage"
              },
              "cache_read": {
                "field": "cache_read",
                "status": "invalid",
                "reason": "bad_type",
                "raw_ref": "/payload/thread_token_usage"
              },
              "cache_write": {
                "field": "cache_write",
                "status": "invalid",
                "reason": "bad_type",
                "raw_ref": "/payload/thread_token_usage"
              },
              "thinking": {
                "field": "thinking",
                "status": "invalid",
                "reason": "bad_type",
                "raw_ref": "/payload/thread_token_usage"
              },
              "total": {
                "field": "total",
                "status": "invalid",
                "reason": "bad_type",
                "raw_ref": "/payload/thread_token_usage"
              }
            }
          }
        ],
        "messages": []
      }
    },
    {
      "id": "db10-legacy-tokens-only",
      "connector": "codex",
      "format": "jsonl",
      "input_json": "{\"type\":\"token_count\",\"payload\":{\"tokens\":8}}",
      "expected_standard": {
        "model": {
          "field": "model",
          "status": "missing",
          "reason": "not_applicable"
        },
        "provider": {
          "field": "provider",
          "status": "missing",
          "reason": "not_applicable"
        },
        "native_ids": {},
        "times": {
          "event": {
            "field": "time",
            "status": "missing",
            "reason": "absent",
            "presence_ref": "/timestamp"
          }
        },
        "tools": [],
        "usage": [
          {
            "scope": "codex_legacy",
            "role": "token_count",
            "raw_ref": "/payload",
            "fields": {
              "output_legacy": {
                "field": "output_legacy",
                "status": "present",
                "value": "8",
                "raw_ref": "/payload/tokens",
                "unit": "count"
              },
              "output": {
                "field": "output",
                "status": "present",
                "value": "8",
                "raw_ref": "/payload/tokens",
                "unit": "count"
              }
            }
          }
        ],
        "messages": []
      }
    },
    {
      "id": "db11-legacy-tokens-null",
      "connector": "codex",
      "format": "jsonl",
      "input_json": "{\"type\":\"token_count\",\"payload\":{\"tokens\":null}}",
      "expected_standard": {
        "model": {
          "field": "model",
          "status": "missing",
          "reason": "not_applicable"
        },
        "provider": {
          "field": "provider",
          "status": "missing",
          "reason": "not_applicable"
        },
        "native_ids": {},
        "times": {
          "event": {
            "field": "time",
            "status": "missing",
            "reason": "absent",
            "presence_ref": "/timestamp"
          }
        },
        "tools": [],
        "usage": [
          {
            "scope": "codex_legacy",
            "role": "token_count",
            "raw_ref": "/payload",
            "fields": {
              "output_legacy": {
                "field": "output_legacy",
                "status": "missing",
                "reason": "null",
                "raw_ref": "/payload/tokens",
                "unit": "count"
              },
              "output": {
                "field": "output",
                "status": "missing",
                "reason": "null",
                "raw_ref": "/payload/tokens",
                "unit": "count"
              }
            }
          }
        ],
        "messages": []
      }
    },
    {
      "id": "db12-legacy-null-and-present-alias",
      "connector": "codex",
      "format": "jsonl",
      "input_json": "{\"type\":\"token_count\",\"payload\":{\"output_tokens\":null,\"tokens\":8}}",
      "expected_standard": {
        "model": {
          "field": "model",
          "status": "missing",
          "reason": "not_applicable"
        },
        "provider": {
          "field": "provider",
          "status": "missing",
          "reason": "not_applicable"
        },
        "native_ids": {},
        "times": {
          "event": {
            "field": "time",
            "status": "missing",
            "reason": "absent",
            "presence_ref": "/timestamp"
          }
        },
        "tools": [],
        "usage": [
          {
            "scope": "codex_legacy",
            "role": "token_count",
            "raw_ref": "/payload",
            "fields": {
              "output_legacy": {
                "field": "output_legacy",
                "status": "present",
                "value": "8",
                "raw_ref": "/payload/tokens",
                "unit": "count"
              },
              "output": {
                "field": "output",
                "status": "present",
                "value": "8",
                "raw_ref": "/payload/tokens",
                "unit": "count",
                "refs": [
                  {
                    "status": "missing",
                    "reason": "null",
                    "raw_ref": "/payload/output_tokens",
                    "unit": "count"
                  },
                  {
                    "status": "present",
                    "value": "8",
                    "raw_ref": "/payload/tokens",
                    "unit": "count"
                  }
                ]
              }
            }
          }
        ],
        "messages": []
      }
    },
    {
      "id": "db13-rate-limit-null-info-bad",
      "connector": "codex",
      "format": "jsonl",
      "input_json": "{\"type\":\"event_msg\",\"payload\":{\"type\":\"token_count\",\"info\":false,\"rate_limits\":null}}",
      "expected_standard": {
        "model": {
          "field": "model",
          "status": "missing",
          "reason": "not_applicable"
        },
        "provider": {
          "field": "provider",
          "status": "missing",
          "reason": "not_applicable"
        },
        "native_ids": {},
        "times": {
          "event": {
            "field": "time",
            "status": "missing",
            "reason": "absent",
            "presence_ref": "/timestamp"
          }
        },
        "tools": [],
        "usage": [
          {
            "scope": "rate_limits",
            "role": "limits",
            "raw_ref": "/payload/rate_limits",
            "fields": {
              "rate_limits": {
                "field": "rate_limits",
                "status": "missing",
                "reason": "null",
                "raw_ref": "/payload/rate_limits"
              }
            }
          }
        ],
        "messages": []
      }
    },
    {
      "id": "db14-snapshot-types-and-capacity",
      "connector": "codex",
      "format": "jsonl",
      "input_json": "{\"type\":\"event_msg\",\"payload\":{\"type\":\"token_count\",\"info\":{\"last_token_usage\":42,\"total_token_usage\":{},\"model_context_window\":\"128000\"}}}",
      "expected_standard": {
        "model": {
          "field": "model",
          "status": "missing",
          "reason": "not_applicable"
        },
        "provider": {
          "field": "provider",
          "status": "missing",
          "reason": "not_applicable"
        },
        "native_ids": {},
        "times": {
          "event": {
            "field": "time",
            "status": "missing",
            "reason": "absent",
            "presence_ref": "/timestamp"
          }
        },
        "tools": [],
        "usage": [
          {
            "scope": "codex_last",
            "role": "snapshot",
            "raw_ref": "/payload/info/last_token_usage",
            "fields": {
              "input": {
                "field": "input",
                "status": "invalid",
                "reason": "bad_type",
                "raw_ref": "/payload/info/last_token_usage"
              },
              "output": {
                "field": "output",
                "status": "invalid",
                "reason": "bad_type",
                "raw_ref": "/payload/info/last_token_usage"
              },
              "cache_read": {
                "field": "cache_read",
                "status": "invalid",
                "reason": "bad_type",
                "raw_ref": "/payload/info/last_token_usage"
              },
              "cache_write": {
                "field": "cache_write",
                "status": "invalid",
                "reason": "bad_type",
                "raw_ref": "/payload/info/last_token_usage"
              },
              "thinking": {
                "field": "thinking",
                "status": "invalid",
                "reason": "bad_type",
                "raw_ref": "/payload/info/last_token_usage"
              },
              "total": {
                "field": "total",
                "status": "invalid",
                "reason": "bad_type",
                "raw_ref": "/payload/info/last_token_usage"
              }
            }
          },
          {
            "scope": "codex_total",
            "role": "snapshot",
            "raw_ref": "/payload/info/total_token_usage",
            "fields": {
              "input": {
                "field": "input",
                "status": "missing",
                "reason": "absent",
                "presence_ref": "/payload/info/total_token_usage/input_tokens",
                "unit": "count"
              },
              "output": {
                "field": "output",
                "status": "missing",
                "reason": "absent",
                "presence_ref": "/payload/info/total_token_usage/output_tokens",
                "unit": "count"
              },
              "cache_read": {
                "field": "cache_read",
                "status": "missing",
                "reason": "absent",
                "presence_ref": "/payload/info/total_token_usage/cached_input_tokens",
                "unit": "count"
              },
              "cache_write": {
                "field": "cache_write",
                "status": "missing",
                "reason": "absent",
                "presence_ref": "/payload/info/total_token_usage/cache_write_input_tokens",
                "unit": "count"
              },
              "thinking": {
                "field": "thinking",
                "status": "missing",
                "reason": "absent",
                "presence_ref": "/payload/info/total_token_usage/reasoning_output_tokens",
                "unit": "count"
              },
              "total": {
                "field": "total",
                "status": "missing",
                "reason": "absent",
                "presence_ref": "/payload/info/total_token_usage/total_tokens",
                "unit": "count"
              }
            }
          },
          {
            "scope": "capacity",
            "role": "context_window",
            "raw_ref": "/payload/info/model_context_window",
            "fields": {
              "context_window": {
                "field": "context_window",
                "status": "invalid",
                "reason": "not_a_number",
                "raw_ref": "/payload/info/model_context_window",
                "unit": "count"
              }
            }
          }
        ],
        "messages": []
      }
    },
    {
      "id": "db15-unknown-event-direct-metadata",
      "connector": "codex",
      "format": "jsonl",
      "input_json": "{\"type\":\"future\",\"payload\":{\"cwd\":\"\",\"timestamp\":\"123\",\"model\":\"not-promoted\"}}",
      "expected_standard": {
        "model": {
          "field": "model",
          "status": "missing",
          "reason": "not_applicable"
        },
        "provider": {
          "field": "provider",
          "status": "missing",
          "reason": "not_applicable"
        },
        "native_ids": {
          "cwd": {
            "field": "cwd",
            "status": "present",
            "value": "",
            "raw_ref": "/payload/cwd"
          }
        },
        "times": {
          "event": {
            "field": "time",
            "status": "missing",
            "reason": "absent",
            "presence_ref": "/timestamp"
          },
          "payload": {
            "field": "time",
            "status": "invalid",
            "reason": "unit_unproven",
            "raw_ref": "/payload/timestamp"
          }
        },
        "tools": [],
        "usage": [],
        "messages": []
      }
    },
    {
      "id": "db16-document-same-event-dialect",
      "connector": "codex",
      "format": "json_document",
      "input_json": "{\"type\":\"turn_context\",\"payload\":{\"model\":\"doc-model\"}}",
      "expected_standard": {
        "model": {
          "field": "model",
          "status": "present",
          "value": "doc-model",
          "raw_ref": "/payload/model"
        },
        "provider": {
          "field": "provider",
          "status": "missing",
          "reason": "not_applicable"
        },
        "native_ids": {},
        "times": {
          "event": {
            "field": "time",
            "status": "missing",
            "reason": "absent",
            "presence_ref": "/timestamp"
          }
        },
        "tools": [],
        "usage": [],
        "messages": []
      }
    },
    {
      "id": "db17-invalid-event-type",
      "connector": "codex",
      "format": "jsonl",
      "input_json": "{\"type\":false,\"payload\":{\"model\":\"not-promoted\",\"model_provider\":\"not-promoted\",\"id\":\"not-promoted\"}}",
      "expected_standard": {
        "model": {
          "field": "model",
          "status": "missing",
          "reason": "not_applicable"
        },
        "provider": {
          "field": "provider",
          "status": "missing",
          "reason": "not_applicable"
        },
        "native_ids": {},
        "times": {
          "event": {
            "field": "time",
            "status": "missing",
            "reason": "absent",
            "presence_ref": "/timestamp"
          }
        },
        "tools": [],
        "usage": [],
        "messages": []
      }
    },
    {
      "id": "db18-result-structured-status",
      "connector": "codex",
      "format": "jsonl",
      "input_json": "{\"type\":\"response_item\",\"payload\":{\"type\":\"custom_tool_call_output\",\"status\":{\"x\":1e-400}}}",
      "expected_standard": {
        "model": {
          "field": "model",
          "status": "missing",
          "reason": "not_applicable"
        },
        "provider": {
          "field": "provider",
          "status": "missing",
          "reason": "not_applicable"
        },
        "native_ids": {
          "item_id": {
            "field": "item_id",
            "status": "missing",
            "reason": "absent",
            "presence_ref": "/payload/id"
          },
          "call_id": {
            "field": "call_id",
            "status": "missing",
            "reason": "absent",
            "presence_ref": "/payload/call_id"
          }
        },
        "times": {
          "event": {
            "field": "time",
            "status": "missing",
            "reason": "absent",
            "presence_ref": "/timestamp"
          }
        },
        "tools": [
          {
            "kind": "result",
            "raw_ref": "/payload/output",
            "id": {
              "field": "id",
              "status": "missing",
              "reason": "absent",
              "presence_ref": "/payload/call_id"
            },
            "output": {
              "field": "output",
              "status": "missing",
              "reason": "absent",
              "presence_ref": "/payload/output"
            },
            "status": {
              "field": "status",
              "status": "invalid",
              "reason": "unmapped",
              "raw_ref": "/payload/status",
              "value": [
                "obj",
                [
                  [
                    "x",
                    [
                      "num",
                      "1e-400"
                    ]
                  ]
                ]
              ],
              "value_kind": "object"
            }
          }
        ],
        "usage": [],
        "messages": []
      }
    }
  ],
  "old_oracle_observations": [
    {
      "id": "db10-legacy-tokens-only",
      "known_old_oracle_gap": "tokens-only admission",
      "positive_control_full_match": true
    },
    {
      "id": "db11-legacy-tokens-null",
      "known_old_oracle_gap": "tokens-only admission",
      "positive_control_full_match": true
    },
    {
      "id": "db15-unknown-event-direct-metadata",
      "known_old_oracle_gap": "numeric String time reason; v0.4/v2.1 require unit_unproven",
      "all_other_members_match": true
    }
  ]
}
"#;

const D02_IDS: &[&str] = &[
    "db01-root-array",
    "db02-null-payload",
    "db03-null-model",
    "db04-session-id-and-types",
    "db08-token-count-no-id-promotion",
    "db16-document-same-event-dialect",
    "db17-invalid-event-type",
];

const D03_IDS: &[&str] = &[
    "db05-call-no-arguments",
    "db06-call-null-id-no-fallback",
    "db07-result-false-status",
    "db18-result-structured-status",
];

const D04_IDS: &[&str] = &[
    "db09-usage-record-container-types",
    "db14-snapshot-types-and-capacity",
];

const D05_IDS: &[&str] = &[
    "db10-legacy-tokens-only",
    "db11-legacy-tokens-null",
    "db12-legacy-null-and-present-alias",
];

const D06_IDS: &[&str] = &[
    "db13-rate-limit-null-info-bad",
    "db15-unknown-event-direct-metadata",
];

const ALL_IDS: &[&[&str]] = &[D02_IDS, D03_IDS, D04_IDS, D05_IDS, D06_IDS];

fn boundary() -> &'static Value {
    static BOUNDARY: OnceLock<Value> = OnceLock::new();
    BOUNDARY.get_or_init(|| {
        serde_json::from_str(BOUNDARY_JSON).expect("parse embedded boundary catalogue")
    })
}

fn actual_standard(format: &str, input_json: &str) -> Value {
    let safe_value =
        LosslessSourceValue::parse(input_json.as_bytes()).expect("parse lossless source value");
    let format = match format {
        "jsonl" => SourceFormat::Jsonl,
        "json_document" => SourceFormat::JsonDocument,
        other => panic!("unknown source format {other}"),
    };
    let mut before = Vec::new();
    safe_value
        .write_tagged(&mut before)
        .expect("snapshot tagged source bytes before mapping");
    let standard = map_codex_standard(format, &safe_value);
    let mut after = Vec::new();
    safe_value
        .write_tagged(&mut after)
        .expect("snapshot tagged source bytes after mapping");
    assert_eq!(before, after, "mapper changed the tagged source bytes");
    serde_json::to_value(standard).expect("serialize StandardFacts")
}

fn typed_equal(left: &Value, right: &Value) -> bool {
    match (left, right) {
        (Value::Null, Value::Null) => true,
        (Value::Bool(left), Value::Bool(right)) => left == right,
        (Value::Number(left), Value::Number(right)) => left == right,
        (Value::String(left), Value::String(right)) => left == right,
        (Value::Array(left), Value::Array(right)) => {
            left.len() == right.len()
                && left
                    .iter()
                    .zip(right.iter())
                    .all(|(left, right)| typed_equal(left, right))
        }
        (Value::Object(left), Value::Object(right)) => {
            left.len() == right.len()
                && left.iter().all(|(key, value)| {
                    right
                        .get(key)
                        .is_some_and(|expected| typed_equal(value, expected))
                })
        }
        _ => false,
    }
}

fn assert_case(id: &str, format: &str, input_json: &str, expected: &Value) -> Value {
    let actual = actual_standard(format, input_json);
    assert!(
        typed_equal(&actual, expected),
        "case {id} differs\nexpected: {}\nactual: {}",
        serde_json::to_string_pretty(expected).expect("pretty expected"),
        serde_json::to_string_pretty(&actual).expect("pretty actual")
    );
    actual
}

fn assert_boundary(function: &str, ids: &[&str]) {
    let catalogue = boundary();
    let cases = catalogue["cases"].as_array().expect("boundary cases");
    let by_id: BTreeMap<&str, &Value> = cases
        .iter()
        .map(|case| (case["id"].as_str().expect("boundary case id"), case))
        .collect();
    for id in ids {
        let case = by_id
            .get(id)
            .unwrap_or_else(|| panic!("{function}: missing embedded case {id}"));
        let format = case["format"].as_str().expect("case format");
        let input_json = case["input_json"].as_str().expect("case input_json");
        assert_case(id, format, input_json, &case["expected_standard"]);
    }
    assert_eq!(
        ids.len(),
        ids.iter()
            .copied()
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        "{function}: case list contains duplicate ids"
    );
}

fn assert_boundary_roster() {
    let catalogue = boundary();
    let mut catalogue_ids: Vec<&str> = catalogue["cases"]
        .as_array()
        .expect("boundary cases")
        .iter()
        .map(|case| case["id"].as_str().expect("boundary case id"))
        .collect();
    assert_eq!(
        catalogue_ids.len(),
        18,
        "embedded boundary catalogue must hold exactly 18 cases"
    );
    let mut listed: Vec<&str> = ALL_IDS
        .iter()
        .flat_map(|group| group.iter().copied())
        .collect();
    assert_eq!(
        listed.len(),
        18,
        "five test groups must list exactly 18 cases"
    );
    listed.sort_unstable();
    catalogue_ids.sort_unstable();
    assert_eq!(
        listed, catalogue_ids,
        "test groups must cover every embedded boundary case"
    );
    let mut unique = listed.clone();
    unique.dedup();
    assert_eq!(unique.len(), 18, "boundary case ids must be unique");
}

fn write_mapper_result(results: &[Value]) {
    let Some(path) = std::env::var_os("CASS_MAPPER_RESULT") else {
        return;
    };
    let path = PathBuf::from(path);
    let temporary = path.with_extension("json.tmp");
    let bytes = serde_json::to_vec(results).expect("serialize mapper results");
    fs::write(&temporary, bytes).expect("write temporary mapper result");
    fs::rename(&temporary, &path).expect("replace mapper result");
}

#[test]
fn d01_original_codex_gold14() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("source_standard")
        .join("two-source-gold.json");
    let gold: Value = serde_json::from_str(
        &fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("read {}: {error}", path.display())),
    )
    .expect("parse product gold copy");
    let cases = gold["cases"].as_array().expect("gold cases");
    let codex: Vec<&Value> = cases
        .iter()
        .filter(|case| case["connector"] == json!("codex"))
        .collect();
    assert_eq!(
        codex.len(),
        14,
        "original Codex gold must hold exactly 14 cases"
    );

    let mut results = Vec::new();
    for case in codex {
        let id = case["id"].as_str().expect("case id");
        let format = case["format"].as_str().expect("case format");
        let input_json = case["input_json"].as_str().expect("case input_json");
        let actual = assert_case(id, format, input_json, &case["expected_standard"]);
        results.push(json!({"id": id, "actual_standard": actual}));
    }
    assert_eq!(results.len(), 14, "d01 must write exactly 14 records");
    write_mapper_result(&results);
}

#[test]
fn d02_event_presence_and_ids() {
    assert_boundary("d02_event_presence_and_ids", D02_IDS);
    assert_boundary_roster();
}

#[test]
fn d03_tool_fields() {
    assert_boundary("d03_tool_fields", D03_IDS);
}

#[test]
fn d04_usage_snapshot_types() {
    assert_boundary("d04_usage_snapshot_types", D04_IDS);
}

#[test]
fn d05_legacy_tokens_alias() {
    assert_boundary("d05_legacy_tokens_alias", D05_IDS);
}

#[test]
fn d06_direct_metadata() {
    assert_boundary("d06_direct_metadata", D06_IDS);
}
