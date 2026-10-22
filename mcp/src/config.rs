//! Startup configuration for the `cass-mcp` companion program.
//!
//! Every option is required and validated before the program probes the
//! companion CASS binary or opens a listening socket.

use std::fs;
use std::net::{Ipv6Addr, SocketAddr};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use clap::Parser;

/// The exact `--version` word accepted from the companion CASS binary.
pub const EXPECTED_CASS_VERSION: &str = "cass 0.6.17";

/// MCP implementation name advertised to clients.
pub const SERVER_NAME: &str = "cass-mcp";

/// Validated startup configuration.
#[derive(Parser, Debug, Clone)]
#[command(
    name = "cass-mcp",
    version,
    about = "Minimal MCP entry point for CASS over Streamable HTTP"
)]
pub struct Config {
    /// Loopback address to listen on. Port 0 is allowed for tests.
    #[arg(long, value_name = "ADDR")]
    pub bind: SocketAddr,

    /// Absolute path to the companion CASS binary.
    #[arg(long, value_name = "PATH")]
    pub cass_bin: PathBuf,

    /// Absolute path to an existing CASS data directory.
    #[arg(long, value_name = "PATH")]
    pub data_dir: PathBuf,

    /// Absolute path to the model API configuration file.
    #[arg(long, value_name = "PATH")]
    pub api_config: PathBuf,

    /// Embedding profile name fixed for every query.
    #[arg(long, value_name = "NAME")]
    pub embedding_profile: String,

    /// Rerank profile name fixed for every query.
    #[arg(long, value_name = "NAME")]
    pub rerank_profile: String,

    /// Execution slots shared by all tools.
    #[arg(long, value_name = "N")]
    pub max_concurrent: usize,

    /// Bounded waiting-queue capacity.
    #[arg(long, value_name = "N")]
    pub max_queued: usize,

    /// Per-request stdout/stderr byte budget.
    #[arg(long, value_name = "BYTES")]
    pub max_output_bytes: usize,

    /// Total per-request deadline in milliseconds.
    #[arg(long, value_name = "MS")]
    pub request_timeout_ms: u64,

    /// Termination grace period in milliseconds.
    #[arg(long, value_name = "MS")]
    pub terminate_grace_ms: u64,

    /// External entry origin reachable through the private network.
    #[arg(long, value_name = "ORIGIN")]
    pub public_origin: Origin,
}

impl Config {
    /// Reject every invalid value before any subprocess or listener exists.
    pub fn validate(&self) -> Result<(), String> {
        if !self.bind.ip().is_loopback() {
            return Err(format!(
                "--bind must be a loopback address, got {}",
                self.bind.ip()
            ));
        }

        require_absolute(&self.cass_bin, "--cass-bin")?;
        let metadata = fs::metadata(&self.cass_bin)
            .map_err(|_| "--cass-bin must be an existing executable file".to_string())?;
        if !metadata.is_file() {
            return Err("--cass-bin must be an existing executable file".to_string());
        }
        if metadata.permissions().mode() & 0o111 == 0 {
            return Err("--cass-bin must be executable".to_string());
        }

        require_absolute(&self.data_dir, "--data-dir")?;
        let metadata = fs::metadata(&self.data_dir)
            .map_err(|_| "--data-dir must be an existing directory".to_string())?;
        if !metadata.is_dir() {
            return Err("--data-dir must be an existing directory".to_string());
        }

        require_absolute(&self.api_config, "--api-config")?;
        let metadata = fs::metadata(&self.api_config)
            .map_err(|_| "--api-config must be a readable file".to_string())?;
        if !metadata.is_file() {
            return Err("--api-config must be a readable file".to_string());
        }
        fs::File::open(&self.api_config)
            .map_err(|_| "--api-config must be a readable file".to_string())?;

        if self.embedding_profile.trim().is_empty() {
            return Err("--embedding-profile must not be blank".to_string());
        }
        if self.rerank_profile.trim().is_empty() {
            return Err("--rerank-profile must not be blank".to_string());
        }
        if self.max_concurrent == 0 {
            return Err("--max-concurrent must be greater than zero".to_string());
        }
        if self.max_queued == 0 {
            return Err("--max-queued must be greater than zero".to_string());
        }
        if self.max_output_bytes == 0 {
            return Err("--max-output-bytes must be greater than zero".to_string());
        }
        if self.request_timeout_ms == 0 {
            return Err("--request-timeout-ms must be greater than zero".to_string());
        }
        if self.terminate_grace_ms == 0 {
            return Err("--terminate-grace-ms must be greater than zero".to_string());
        }

        Ok(())
    }
}

fn require_absolute(path: &Path, option: &str) -> Result<(), String> {
    if path.is_absolute() {
        Ok(())
    } else {
        Err(format!("{option} must be an absolute path"))
    }
}

/// A normalized `scheme://host:port` origin.
///
/// The scheme, host, and port are validated structurally. Matching against the
/// configured allowlist is left to the SDK; this type only guarantees that the
/// SDK never sees a value whose path, query, fragment, or userinfo it would
/// silently ignore.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Origin {
    pub scheme: String,
    pub host: String,
    pub port: u16,
}

impl Origin {
    pub fn parse(raw: &str) -> Result<Self, String> {
        let value = raw.trim();
        if value.is_empty() {
            return Err("origin must not be empty".to_string());
        }
        if value.eq_ignore_ascii_case("null") {
            return Err("`null` is not an allowed origin".to_string());
        }
        let (scheme, rest) = value
            .split_once("://")
            .ok_or_else(|| "origin must be scheme://authority".to_string())?;
        let scheme = scheme.to_ascii_lowercase();
        if scheme != "http" && scheme != "https" {
            return Err("origin scheme must be http or https".to_string());
        }
        if rest.is_empty() {
            return Err("origin must include a host".to_string());
        }
        for (needle, label) in [
            ('/', "path"),
            ('?', "query"),
            ('#', "fragment"),
            ('@', "userinfo"),
            ('*', "wildcard"),
        ] {
            if rest.contains(needle) {
                return Err(format!("origin must not contain a {label}"));
            }
        }
        if rest.chars().any(char::is_whitespace) {
            return Err("origin must not contain whitespace".to_string());
        }
        let (host, port) = split_authority(rest)?;
        let port = port.unwrap_or(if scheme == "https" { 443 } else { 80 });
        Ok(Self { scheme, host, port })
    }

    /// Origin string handed to the SDK, with an explicit port.
    pub fn normalized(&self) -> String {
        format!("{}://{}", self.scheme, self.authority())
    }

    /// `host:port`, with IPv6 literals bracketed.
    pub fn authority(&self) -> String {
        if self.host.contains(':') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }

    /// `Host` header entries for this origin: the bare hostname and the
    /// explicit authority. The bare hostname covers clients that omit the
    /// default port.
    pub fn host_header_entries(&self) -> Vec<String> {
        vec![self.host.clone(), self.authority()]
    }
}

impl FromStr for Origin {
    type Err = String;

    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        Self::parse(raw)
    }
}

fn split_authority(authority: &str) -> Result<(String, Option<u16>), String> {
    if let Some(rest) = authority.strip_prefix('[') {
        let (host, tail) = rest
            .split_once(']')
            .ok_or_else(|| "origin has an unterminated IPv6 literal".to_string())?;
        // Brackets are only legal around an IPv6 address. Parse the literal
        // instead of accepting any hex/colon text, so `[:::]` and bracketed
        // IPv4 forms are rejected before they reach the SDK.
        let address: Ipv6Addr = host
            .parse()
            .map_err(|_| "origin has an invalid IPv6 literal".to_string())?;
        let port = if tail.is_empty() {
            None
        } else {
            let digits = tail
                .strip_prefix(':')
                .ok_or_else(|| "origin has an invalid authority".to_string())?;
            Some(parse_port(digits)?)
        };
        return Ok((address.to_string(), port));
    }

    let mut parts = authority.split(':');
    let host = parts.next().unwrap_or("");
    let port = parts.next();
    if parts.next().is_some() {
        return Err("origin has an unbracketed IPv6 literal".to_string());
    }
    if host.is_empty() {
        return Err("origin has an empty host".to_string());
    }
    if !host
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.' || c == '_')
    {
        return Err("origin has an invalid host".to_string());
    }
    let port = match port {
        Some(digits) => Some(parse_port(digits)?),
        None => None,
    };
    Ok((host.to_ascii_lowercase(), port))
}

fn parse_port(digits: &str) -> Result<u16, String> {
    if digits.is_empty() || !digits.chars().all(|c| c.is_ascii_digit()) {
        return Err("origin has an invalid port".to_string());
    }
    let port: u16 = digits
        .parse()
        .map_err(|_| "origin port is out of range".to_string())?;
    if port == 0 {
        return Err("origin port must be non-zero".to_string());
    }
    Ok(port)
}
