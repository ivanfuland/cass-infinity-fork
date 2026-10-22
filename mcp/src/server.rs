//! Streamable HTTP server wiring for `cass-mcp`.
//!
//! The server advertises the `tools` capability with exactly the four CASS
//! tools. Every SDK session clones one shared [`Runner`]; no session creates
//! its own executor. The SDK keeps negotiating the protocol: with legacy
//! session mode enabled, `2025-11-25` uses the session lifecycle and
//! `2026-07-28` takes the stateless path (C4).

use std::sync::Arc;

use axum::Router;
use axum::extract::Request;
use axum::http::{HeaderMap, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use rmcp::ErrorData as McpError;
use rmcp::ServerHandler;
use rmcp::model::{
    CallToolRequestMethod, CallToolRequestParams, CallToolResponse, CallToolResult, ContentBlock,
    Implementation, ListToolsResult, PaginatedRequestParams, ServerCapabilities, ServerConfig,
};
use rmcp::service::{RequestContext, RoleServer};
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use rmcp::transport::streamable_http_server::{StreamableHttpServerConfig, StreamableHttpService};

use crate::config::{Config, Origin, SERVER_NAME};
use crate::runner::{Runner, ToolError};
use crate::tools;

/// MCP handler for the companion program.
#[derive(Clone, Debug)]
pub struct CassMcpServer {
    runner: Arc<Runner>,
    max_output_bytes: usize,
}

impl CassMcpServer {
    fn new(runner: Arc<Runner>, max_output_bytes: usize) -> Self {
        Self {
            runner,
            max_output_bytes,
        }
    }

    /// The single success exit: a legal recall envelope that no longer fits
    /// the serialized-result budget becomes one `result_too_large` error, never
    /// a partial body.
    fn success_response(&self, stdout: String) -> CallToolResponse {
        let result = CallToolResult::success(vec![ContentBlock::text(stdout)]);
        if serialized_len(&result) <= self.max_output_bytes {
            return result.into();
        }
        self.error_response(&ToolError::result_too_large(
            "the recall result exceeded the configured output budget",
        ))
    }

    /// The single error exit, shared by input validation and every runner
    /// failure. The body is reduced in the fixed order: drop the optional
    /// message, then the optional CLI exit status. The code, `isError` and the
    /// single text block always stay.
    fn error_response(&self, error: &ToolError) -> CallToolResponse {
        let full = CallToolResult::error(vec![ContentBlock::text(error.to_json())]);
        if serialized_len(&full) <= self.max_output_bytes {
            return full.into();
        }

        let without_message =
            CallToolResult::error(vec![ContentBlock::text(error.render(false, true))]);
        if serialized_len(&without_message) <= self.max_output_bytes {
            return without_message.into();
        }

        let minimal = CallToolResult::error(vec![ContentBlock::text(error.render(false, false))]);
        debug_assert!(
            serialized_len(&minimal) <= self.max_output_bytes,
            "the configured budget must keep every fixed error code representable"
        );
        minimal.into()
    }
}

/// Compact bytes of the SDK tool result, including `resultType: complete`.
/// The JSON-RPC, SSE, and HTTP framing around it are not part of this budget.
fn serialized_len(result: &CallToolResult) -> usize {
    serde_json::to_vec(result)
        .map(|bytes| bytes.len())
        .unwrap_or(usize::MAX)
}

impl ServerHandler for CassMcpServer {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new(SERVER_NAME, env!("CARGO_PKG_VERSION")))
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        Ok(ListToolsResult::with_all_items(tools::definitions()))
    }

    /// `get_tool` keeps its default `None`, so the SDK does not deserialize
    /// or reject arguments before this handler can return a tool-level error.
    /// Unknown names are the one case that stays a protocol error.
    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, McpError> {
        let Some(tool) = tools::RecallTool::from_name(&request.name) else {
            return Err(McpError::method_not_found::<CallToolRequestMethod>());
        };

        let call = match tools::parse(tool, request.arguments.as_ref()) {
            Ok(call) => call,
            Err(error) => return Ok(self.error_response(&error)),
        };

        match self.runner.run(tool, &call).await {
            Ok(stdout) => Ok(self.success_response(stdout)),
            Err(error) => Ok(self.error_response(&error)),
        }
    }
}

/// Build the Streamable HTTP service mounted at `/mcp`.
///
/// Legacy session mode is enabled so the SDK can negotiate both its session
/// lifecycle (`2025-11-25`) and its stateless path (`2026-07-28`). Origin
/// validation stays enabled with exactly three loopback origins for the live
/// port plus the configured public entry.
pub fn service(
    config: &Config,
    port: u16,
) -> StreamableHttpService<CassMcpServer, LocalSessionManager> {
    let mut origins = vec![
        format!("http://localhost:{port}"),
        format!("http://127.0.0.1:{port}"),
        format!("http://[::1]:{port}"),
    ];
    origins.push(config.public_origin.normalized());

    let mut hosts = vec![
        "localhost".to_string(),
        "127.0.0.1".to_string(),
        "::1".to_string(),
    ];
    // The literal bind address is always accepted as a `Host` entry: every
    // loopback address is legal, not only the three canonical spellings above.
    let bind_host = config.bind.ip().to_string();
    if !hosts.contains(&bind_host) {
        hosts.push(bind_host);
    }
    hosts.extend(config.public_origin.host_header_entries());

    let sdk_config = StreamableHttpServerConfig::default()
        .with_legacy_session_mode(true)
        .with_json_response(true)
        .with_allowed_origins(origins)
        .enforce_origin_validation()
        .with_allowed_hosts(hosts);

    let runner = Arc::new(Runner::new(config));
    let max_output_bytes = config.max_output_bytes;
    StreamableHttpService::new(
        move || Ok(CassMcpServer::new(Arc::clone(&runner), max_output_bytes)),
        Default::default(),
        sdk_config,
    )
}

/// Router exposing the service at `/mcp`, guarded by a strict Origin syntax
/// check before the SDK parses the request.
pub fn router(service: StreamableHttpService<CassMcpServer, LocalSessionManager>) -> Router {
    Router::new()
        .nest_service("/mcp", service)
        .layer(middleware::from_fn(origin_guard))
}

async fn origin_guard(request: Request, next: Next) -> Response {
    match check_origin_headers(request.headers()) {
        Ok(()) => next.run(request).await,
        Err(reason) => (StatusCode::FORBIDDEN, format!("Forbidden: {reason}")).into_response(),
    }
}

/// Reject Origins the SDK parser would silently accept or misread: duplicate
/// headers, `null`, userinfo, paths, queries, fragments, wildcards, and bad
/// authorities. Exact allowlist matching stays in the SDK.
fn check_origin_headers(headers: &HeaderMap) -> Result<(), &'static str> {
    let mut values = headers.get_all(header::ORIGIN).iter();
    let Some(first) = values.next() else {
        return Ok(());
    };
    if values.next().is_some() {
        return Err("multiple Origin headers");
    }
    let value = first
        .to_str()
        .map_err(|_| "invalid Origin header encoding")?;
    Origin::parse(value)
        .map(|_| ())
        .map_err(|_| "malformed Origin header")
}
