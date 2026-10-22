//! Streamable HTTP server wiring for `cass-mcp`.
//!
//! This ticket exposes the protocol entry point only: the server advertises the
//! `tools` capability and keeps the SDK's default empty `tools/list` response.
//! The four CASS tools are registered by a later ticket.

use axum::Router;
use axum::extract::Request;
use axum::http::{HeaderMap, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use rmcp::ServerHandler;
use rmcp::model::{Implementation, ServerCapabilities, ServerConfig};
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use rmcp::transport::streamable_http_server::{StreamableHttpServerConfig, StreamableHttpService};

use crate::config::{Config, Origin, SERVER_NAME};

/// MCP handler for the companion program.
#[derive(Clone, Copy, Debug, Default)]
pub struct CassMcpServer;

impl ServerHandler for CassMcpServer {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build()).with_server_info(
            Implementation::new(SERVER_NAME, env!("CARGO_PKG_VERSION")),
        )
    }
}

/// Build the Streamable HTTP service mounted at `/mcp`.
///
/// Requests are served statelessly (`legacy_session_mode` off) and answered
/// with plain JSON. Origin validation stays enabled with exactly three
/// loopback origins for the live port plus the configured public entry.
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
        .with_legacy_session_mode(false)
        .with_json_response(true)
        .with_allowed_origins(origins)
        .enforce_origin_validation()
        .with_allowed_hosts(hosts);

    StreamableHttpService::new(|| Ok(CassMcpServer), Default::default(), sdk_config)
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
