# cass-mcp

`cass-mcp` is a minimal Model Context Protocol server that exposes four read-only
CASS tools over Streamable HTTP. It runs the companion `cass` binary directly and
forwards exactly one recall envelope per successful call.

## Companion version

The server requires the companion binary to report exactly `cass 0.6.17`. The
version is probed once before the listener binds; a mismatch stops startup.

## Building the paired candidate

`cass-mcp` is built beside the CLI from the same frozen commit by
`scripts/setup-cass-fork.sh`. Set `MCP_INSTALL_PATH` to enable paired mode:

```bash
env -u CARGO_TARGET_DIR \
  INSTALL_PATH=/abs/path/candidates/cass \
  MCP_INSTALL_PATH=/abs/path/candidates/cass-mcp \
  FORK_REPO=<repository> FORK_REF=<full commit> \
  bash scripts/setup-cass-fork.sh
```

The script builds the root CLI with
`--release --locked --no-default-features --features qr,encryption` and this
package with `--release --locked --manifest-path mcp/Cargo.toml`. The MCP
package keeps its own `Cargo.lock` and `mcp/target` directory; it is never
merged into the root runtime.

Both binaries must pass the version check and real `strings`/`ldd` probes for
ONNX symbols before either is published. Candidates are staged in their own
parent directory and linked with `ln -T`, so an existing path is never
overwritten. A failed second publish exits non-zero, leaves the first new
candidate in place and prints no success record.

On success the script prints one line:

```
PAIR_OK source_commit=<sha> cass_version=0.6.17 mcp_version=0.6.17 cass_sha256=<sha> mcp_sha256=<sha> cli_strings_hits=0 cli_ldd_hits=0 mcp_strings_hits=0 mcp_ldd_hits=0
```

Record that line together with the two absolute paths. The legacy mode without
`MCP_INSTALL_PATH` still builds and installs only the CLI.

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

## Execution pool

One pool serves the whole process, all four tools and every SDK session. It is
created once, at startup, from the fixed options `--max-concurrent` (P) and
`--max-queued` (Q). Both must be positive; no default exists.

- A request takes an execution slot only when a slot is free **and** nobody is
  waiting. A slot that is being reaped still counts, so a child that ignores
  `SIGTERM` cannot let another child start early.
- Otherwise the request is registered in one bounded queue, in strict arrival
  order. A request that arrives after a slot was released cannot take that slot
  ahead of the queue head.
- When the slots and the queue are both full the call returns
  `isError: true` with `error.code` = `busy` before any child exists.
- Input validation happens before admission. An illegal input is always
  `invalid_argument`, even while the pool is full, and never occupies a slot or
  a queue position.
- A slot is released exactly once, after that request's own child was waited
  for. A normal exit, a non-zero CLI exit, a refused spawn, an unreadable pipe
  and an over-budget read all return the slot. Dropping the caller's request
  future does not release it early: the permit lives in the same task that owns
  the child and its `wait`, and a dropped waiting request frees its queue
  position (or returns a slot it was already granted).

The queue order is decided under one lock when the request registers. It is
never inferred from network arrival times, and the server exposes no pool
metrics or test endpoint.

## Request deadline and cancellation

`--request-timeout-ms` bounds one whole request. The absolute deadline is fixed
once, when the server receives the `tools/call`, before any argument is
processed. The same deadline and the same SDK cancellation token travel through
admission, the waiting queue, the child's whole lifetime and the final
publication. A hand-over from the queue to execution never starts a fresh
budget.

- A valid request checks both signals before it can take a queue position or
  start a child. An already cancelled or expired request returns
  `error.code = cancelled` or `error.code = deadline_exceeded` without touching the pool.
- While waiting, the request watches cancellation, the deadline and the grant
  of its queue position together. Cancellation outranks the deadline, and both
  outrank an already granted slot. A request that is cancelled or expires at
  the same moment it is granted never starts a child, and its queue position or
  granted slot is returned exactly once.
- After the grant, and before the child starts, the same two signals are
  checked again. A failure returns the slot without creating a process.
- While the child runs, cancellation and the deadline are observed beside both
  output pipes and `wait`. The fixed priority in one observation is:
  cancellation, then the deadline, then the output budget, then a non-zero
  exit, then a malformed envelope, then success. The first decided failure is
  never rewritten by a later event: an output overflow that is already decided
  keeps `result_too_large` even if the SDK cancellation arrives during the
  termination grace.
- A cancelled or expired request stops reading, closes both pipes, sends
  `SIGTERM` to its own child only, waits `--terminate-grace-ms`, force-kills
  that child if it is still alive, and waits for it. The execution slot is
  released exactly once, after that `wait`. No process is ever selected by
  name or port.
- Termination runs first, so a response may arrive later than the deadline. A
  deadline observed while the connection is still open is delivered as
  `error.code = deadline_exceeded`.
- Building and measuring the final serialized tool result is part of the same
  lifecycle. If a cancellation or an elapsed deadline is already observable
  after the result exists, it replaces both the pending success and its budget
  failure. That check and the return carry no `await`, so one request publishes
  at most one result; an event that arrives after that point publishes nothing.
- A cancelled request may end without any tool result. That is the SDK's
  protocol termination and does not change the child reaping or the slot
  release.

## Output budget

`--max-output-bytes` is one budget applied at two layers.

1. While the companion runs, stdout and stderr share one byte counter. Reading
   uses fixed small chunks, stores at most the budget across both streams, and
   requests at most the remaining budget plus one probe byte per read, so a
   small remaining budget never consumes a full chunk past it. The first byte
   past the budget stops both reads immediately, without waiting for the
   producer to close its pipes.
2. The final tool result must also fit. The measured object is the compact
   serialized SDK `CallToolResult` the server returns for protocol `2026-07-28`,
   including `resultType: "complete"`, the text escaping, and `isError`. The
   JSON-RPC envelope, SSE framing, and HTTP frame are not counted.

The startup minimum is 125 bytes: that is the measured serialized size of the
largest fixed error code after every optional field is removed. A value below
125 is rejected as invalid configuration before the version probe and before
any listener exists. The measured size is counted in UTF-8 bytes, never in
characters.

When either layer is exceeded the call returns `isError: true` with
`result_too_large`; no partial recall body is forwarded. The server terminates
only that request's own child, waits for its exit, and only then publishes the
error. A non-zero exit observed in the same window never overrides the
overflow.

An error result keeps its fixed `error.code` and `isError`. If it does not fit
the budget, the optional `message` is removed first, then the optional
`cli_exit_code`; the code itself is never changed and no second error is sent.

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
| Execution slots and waiting queue are both full | `busy` |
| The request was cancelled through the SDK token before its result was published | `cancelled` |
| The fixed total deadline elapsed before the result was published | `deadline_exceeded` |
| CLI `usage` | `invalid_argument` |
| CLI `identity_unavailable` | `identity_unavailable` |
| CLI `stale_reference` | `stale_reference` |
| CLI `model_unavailable` | `model_unavailable` |
| CLI `recall_invalid` | `invalid_recall` |
| Combined stdout+stderr or the final tool result exceeds `--max-output-bytes` | `result_too_large` |
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

Both lifecycles call the same shared runner, and every session shares one
execution pool; a session never gets its own slots. Cancellation follows the
SDK's native handling for the negotiated protocol:

- `2025-11-25`: a `notifications/cancelled` for one request id cancels exactly
  that request through the SDK token. The same request id in another session is
  a different request and is not affected. A disconnect is not a cancellation:
  a request whose client went away keeps running until its own total deadline.
- `2026-07-28`: the path is stateless, and a client disconnect cancels the
  in-flight request through the SDK token. A cancellation notification is not
  promised to work on this path.

The server never treats the HTTP `202` of a cancellation notification as proof
that the request stopped. When the SDK still allows a reply, the error result
uses the same `isError` shape and error code as any other failure; when the SDK
terminates the request without a reply, only the child reaping and the slot
release are observable.

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

- This entry point has no embedded Codex cleaning adapter. A later adapter must
  recognize exactly one limited shape:
  `text(await tools.mcp__cass_mcp__cass_NAME(J));`
  where `NAME` is `search`, `expand`, `sessions`, or `timeline`, and `J` is a
  JSON object literal. Recognizing that shape still requires the cleaning
  wiring and a default-enable acceptance; a successful RPC call alone does not
  mean the recall result was cleaned. Dynamic scripts, batched calls, and
  `wait` segmented results fall outside that shape and are not covered.
- This entry point bounds execution slots, waiting positions and one total
  deadline per request. The request deadline, explicit cancellation, the
  termination grace and the single slot release are wired here; the capacity
  numbers are still deployment measurements, not defaults of this program.
  Do not deploy this server to production until the final integration pass.
- Model work stays inside the CLI. This server does not choose a retrieval
  strategy, retry model calls, or reinterpret an empty but successful result as
  a failure.
