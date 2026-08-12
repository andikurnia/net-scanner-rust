use std::path::PathBuf;

use clap::Parser;
use ipnetwork::Ipv4Network;
use serde::Deserialize;

use crate::netinfo;

#[derive(Debug, Clone, Parser)]
#[command(name = "net-monitor", version, about = "LAN IP scanner with a web UI")]
pub struct Cli {
    /// Path to a TOML config file (defaults to ./config.toml if present)
    #[arg(long)]
    pub config: Option<PathBuf>,

    /// Web server bind address, e.g. 0.0.0.0:8080
    #[arg(long)]
    pub bind: Option<String>,

    /// Seconds between automatic scans
    #[arg(long)]
    pub interval: Option<u64>,

    /// Subnet in CIDR form to scan, e.g. 192.168.1.0/24 (repeatable)
    #[arg(long = "subnet")]
    pub subnets: Vec<String>,

    /// Scan method: auto | arp | tcp
    #[arg(long)]
    pub method: Option<String>,

    /// Per-host probe timeout in milliseconds
    #[arg(long)]
    pub timeout_ms: Option<u64>,

    /// Max concurrent probes during TCP scan
    #[arg(long)]
    pub concurrency: Option<usize>,

    /// Attempt OS fingerprinting of used hosts (TTL + open ports)
    #[arg(long)]
    pub detect_os: Option<bool>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ScanMethod {
    #[default]
    Auto,
    Arp,
    Tcp,
}

impl ScanMethod {
    pub fn parse(s: &str) -> Result<Self, String> {
        match s.to_ascii_lowercase().as_str() {
            "auto" => Ok(ScanMethod::Auto),
            "arp" => Ok(ScanMethod::Arp),
            "tcp" => Ok(ScanMethod::Tcp),
            other => Err(format!(
                "unknown scan method '{other}' (use auto, arp or tcp)"
            )),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct Config {
    pub bind: String,
    pub scan_interval_secs: u64,
    pub subnets: Vec<String>,
    pub method: ScanMethod,
    pub timeout_ms: u64,
    pub concurrency: usize,
    pub ports: Vec<u16>,
    pub detect_os: bool,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            bind: "127.0.0.1:8080".to_string(),
            scan_interval_secs: 10,
            subnets: Vec::new(),
            method: ScanMethod::Auto,
            timeout_ms: 100,
            concurrency: 256,
            ports: vec![
                22, 53, 80, 111, 123, 135, 139, 443, 445, 631, 993, 3389, 5900, 8080, 8443, 9100,
            ],
            detect_os: true,
        }
    }
}

impl Config {
    /// Load configuration: CLI overrides config file (or ./config.toml), then
    /// resolve the list of subnets to scan (auto-detected when not specified).
    pub fn load() -> Result<(Self, Vec<Ipv4Network>), String> {
        let cli = Cli::parse();

        let mut cfg = match &cli.config {
            Some(path) => {
                let raw = std::fs::read_to_string(path)
                    .map_err(|e| format!("cannot read config {}: {e}", path.display()))?;
                toml::from_str::<Config>(&raw)
                    .map_err(|e| format!("invalid config {}: {e}", path.display()))?
            }
            None => match std::fs::read_to_string("config.toml") {
                Ok(raw) => {
                    toml::from_str::<Config>(&raw).map_err(|e| format!("invalid config.toml: {e}"))?
                }
                Err(_) => Config::default(),
            },
        };

        if let Some(bind) = cli.bind {
            cfg.bind = bind;
        }
        if let Some(interval) = cli.interval {
            cfg.scan_interval_secs = interval;
        }
        if !cli.subnets.is_empty() {
            cfg.subnets = cli.subnets;
        }
        if let Some(method) = cli.method {
            cfg.method = ScanMethod::parse(&method)?;
        }
        if let Some(timeout) = cli.timeout_ms {
            cfg.timeout_ms = timeout;
        }
        if let Some(concurrency) = cli.concurrency {
            cfg.concurrency = concurrency;
        }
        if let Some(detect_os) = cli.detect_os {
            cfg.detect_os = detect_os;
        }

        cfg.scan_interval_secs = cfg.scan_interval_secs.max(1);
        cfg.timeout_ms = cfg.timeout_ms.max(50);
        cfg.concurrency = cfg.concurrency.max(1);
        if cfg.ports.is_empty() {
            cfg.ports = Config::default().ports;
        }

        let subnets = if cfg.subnets.is_empty() {
            netinfo::detect_default_subnets()
        } else {
            let mut nets = Vec::new();
            for cidr in &cfg.subnets {
                let net = cidr
                    .parse::<Ipv4Network>()
                    .map_err(|e| format!("invalid subnet '{cidr}': {e}"))?;
                nets.push(net);
            }
            nets
        };

        if subnets.is_empty() {
            return Err(
                "no subnet to scan. Use --subnet <CIDR> or add `subnets = [...]` to config.toml"
                    .into(),
            );
        }

        Ok((cfg, subnets))
    }
}
