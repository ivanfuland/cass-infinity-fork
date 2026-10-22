//! `cass-mcp`: the CASS companion MCP entry point.
//!
//! Startup order is fixed: parse and validate every option, probe the
//! companion CASS binary version, then bind the loopback listener. A rejected
//! configuration never starts a subprocess or a listener.

mod config;
mod server;

use std::path::Path;
use std::process::{Command, ExitCode, Stdio};

use clap::Parser;

use config::{Config, EXPECTED_CASS_VERSION};

fn main() -> ExitCode {
    let config = Config::parse();

    if let Err(message) = config.validate() {
        eprintln!("cass-mcp: invalid configuration: {message}");
        return ExitCode::from(2);
    }

    if let Err(message) = verify_cass_version(&config.cass_bin) {
        eprintln!("cass-mcp: {message}");
        return ExitCode::from(1);
    }

    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("cass-mcp: failed to start async runtime: {error}");
            return ExitCode::from(1);
        }
    };

    match runtime.block_on(serve(config)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("cass-mcp: {message}");
            ExitCode::from(1)
        }
    }
}

async fn serve(config: Config) -> Result<(), String> {
    let listener = tokio::net::TcpListener::bind(config.bind)
        .await
        .map_err(|error| format!("failed to bind {}: {error}", config.bind))?;
    let address = listener
        .local_addr()
        .map_err(|error| format!("failed to read bound address: {error}"))?;

    let app = server::router(server::service(&config, address.port()));
    eprintln!("listening=http://{address}/mcp");

    axum::serve(listener, app)
        .await
        .map_err(|error| format!("http server error: {error}"))
}

/// Run the fixed companion binary as `cass-bin --version` without a shell.
///
/// Only a successful exit with the exact expected version word is accepted.
/// The child's output is never echoed.
fn verify_cass_version(cass_bin: &Path) -> Result<(), String> {
    let output = Command::new(cass_bin)
        .arg("--version")
        .stdin(Stdio::null())
        .output()
        .map_err(|_| "cass-bin version probe could not be executed".to_string())?;

    if !output.status.success() {
        return Err("cass-bin version probe exited non-zero".to_string());
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let version_word = stdout.lines().next().unwrap_or_default().trim();
    if version_word != EXPECTED_CASS_VERSION {
        return Err(format!(
            "cass-bin version mismatch: expected `{EXPECTED_CASS_VERSION}`"
        ));
    }

    Ok(())
}
