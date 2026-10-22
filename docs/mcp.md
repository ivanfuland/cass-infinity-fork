# cass-mcp

`cass-mcp` is a minimal Model Context Protocol server that exposes four read-only
CASS tools over Streamable HTTP. It runs the companion `cass` binary directly and
forwards exactly one recall envelope per successful call.

## Companion version

The server requires the companion binary to report exactly `cass 0.6.17`. The
version is probed once before the listener binds; a mismatch stops startup.

## Tools

| Tool | Required input | Optional input |
|---|---|---|
| `cass_search` | `query` | `agent[]`, `workspace[]`, `source`, `since`, `until`, `cursor` |
| `cass_expand` | `message_id`, `source_id`, `source_path`, `expected_content_sha256` | `context` (default 3) |
| `cass_sessions` | none | `limit` (default 10), `workspace`, `since` |
| `cass_timeline` | none | `since`, `until`, `agent[]`, `source`, `group_by` (default `hour`) |

Every tool rejects unknown fields. Every provided string must contain at least
one non-whitespace character. Arrays accept only strings and keep their order
and duplicates. Numbers must be JSON integers within the documented range;
fractions, negative values where a positive value is required, and values that
do not fit the target type are rejected. `null` is never a legal provided value;
omit an optional field to get its default.

`since` and `until` accept only RFC3339 timestamps with `Z` or an explicit
numeric offset. The server validates them and compares them when both are
present; it never rewrites the text it passes to the CLI.

`workspace` is the absolute server-side identifier returned by the index. The
server does not resolve a client-relative directory against its own working
directory. `source_path` is passed through unchanged; the server never opens the
original session file.

## Fixed command lines

The server never uses a shell. Each argument is one argv element, `stdin` is
closed, inherited `CASS_*` variables are removed for the child, and
`CASS_DATA_DIR` is set to the configured directory.

```
<cass-bin> search --mode=hybrid --vector-search-mode=exact --rerank --rrf-limit=200 --rerank-limit=5 --api-config=<P> --embedding-profile=<E> --rerank-profile=<R> --no-model-fallback --recall [filters] -- <QUERY>
<cass-bin> expand <PATH> --source=<SID> --message-id=<MID> --expected-content-sha256=<SHA> --context=<N> --recall
<cass-bin> sessions --limit=<L> --recall [--workspace=<W>] [--since=<S>]
<cass-bin> timeline --group-by=<GROUP> --recall [--since=<S>] [--until=<U>] [--agent=<A>...] [--source=<SRC>]
```

`<P>`, `<E>`, and `<R>` come from startup options and cannot be overridden by a
request. The query is always the last argv element after a literal `--`; a query
that begins with `--` stays data. No command adds `--db`, refresh, catch-up, or
any management subcommand.

## Results and errors

A successful call returns the CLI stdout unchanged as one `type: "text"` content
block. The server first checks that stdout is valid UTF-8 and is one legal
`cass_recall` envelope with `version="1"`, the requested tool name, and the
result shape for that tool. It does not re-encode the envelope, add a second
layer, or populate `structuredContent`. A legal empty result is a success.

A failed call returns `isError: true` with one text block whose content is a
single top-level `error` object:

```json
{"error":{"code":"invalid_argument","message":"`since` must be an RFC3339 timestamp with an explicit offset"}}
```

| Condition | `error.code` |
|---|---|
| Invalid or unknown request input | `invalid_argument` |
| CLI `usage` | `invalid_argument` |
| CLI `identity_unavailable` | `identity_unavailable` |
| CLI `stale_reference` | `stale_reference` |
| CLI `model_unavailable` | `model_unavailable` |
| CLI `recall_invalid` | `invalid_recall` |
| Any other non-zero CLI exit, unparseable stderr, signal, or spawn failure | `cass_exit` |
| Illegal stdout envelope or payload shape | `invalid_recall` |

When a real process exit status exists, the error object also carries the
numeric `cli_exit_code`. The server never forwards the CLI stderr, the query, or
the recall payload in an error. An unknown tool name is a JSON-RPC
`METHOD_NOT_FOUND` protocol error instead of a tool result.

## Protocol

The server advertises only the `tools` capability and exactly the four tools
above. It accepts both protocol lifecycles that the SDK negotiates:

- `2025-11-25` uses the session lifecycle. The `initialize` response carries
  `Mcp-Session-Id`; send the `notifications/initialized` notification and then
  reuse that header on later requests.
- `2026-07-28` is stateless. Start with `server/discover`, carry
  `MCP-Protocol-Version: 2026-07-28`, and include the required `_meta` keys on
  each request.

Both lifecycles call the same shared runner. Cancellation follows the SDK's
native handling for the negotiated protocol; a cancelled request may not receive
a tool result.

## Example

```bash
cass-mcp \
  --bind 127.0.0.1:8765 \
  --cass-bin /usr/local/bin/cass \
  --data-dir /var/lib/cass \
  --api-config /etc/cass/model-api.toml \
  --embedding-profile default-embedding \
  --rerank-profile default-rerank \
  --max-concurrent 2 \
  --max-queued 4 \
  --max-output-bytes 1048576 \
  --request-timeout-ms 30000 \
  --terminate-grace-ms 1000 \
  --public-origin https://cass.example:443
```

Then call `cass_search` with `{"query": "authentication error"}` over the MCP
endpoint at `/mcp`.

## Known limitations

- The current Codex adapter cleans only the JSON literal single-call form
  `text(await tools.mcp__cass_mcp__cass_NAME(J))`. Dynamic scripts, batched
  calls, and `wait` segmented results are not guaranteed to be cleaned, even
  when the tool call itself succeeds.
- This entry point does not yet include the complete resource gates: output
  byte budgets for streaming reads, the global concurrency/queue/FIFO system,
  and total-deadline cancellation with child reaping are separate work. Do not
  deploy this server to production until those gates and the final integration
  pass.
- Model work stays inside the CLI. This server does not choose a retrieval
  strategy, retry model calls, or reinterpret an empty but successful result as
  a failure.
