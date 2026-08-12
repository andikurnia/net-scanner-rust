use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ipnetwork::Ipv4Network;
use serde::Serialize;
use tokio::sync::{Notify, RwLock};

use crate::config::Config;
use crate::netinfo;
use crate::scanner::{self, Host};

/// Live scan progress, updated from both blocking and async scan workers.
#[derive(Debug)]
pub struct ScanProgress {
    phase: Mutex<String>,
    total: AtomicUsize,
    done: AtomicUsize,
    used: AtomicUsize,
}

impl ScanProgress {
    pub fn new() -> Self {
        Self {
            phase: Mutex::new("idle".into()),
            total: AtomicUsize::new(0),
            done: AtomicUsize::new(0),
            used: AtomicUsize::new(0),
        }
    }

    pub fn reset(&self, total: usize) {
        *self.phase.lock().unwrap() = "starting".into();
        self.total.store(total, Ordering::Relaxed);
        self.done.store(0, Ordering::Relaxed);
        self.used.store(0, Ordering::Relaxed);
    }

    pub fn set_phase(&self, phase: &str) {
        *self.phase.lock().unwrap() = phase.to_string();
    }

    pub fn tick(&self, used: bool) {
        self.done.fetch_add(1, Ordering::Relaxed);
        if used {
            self.used.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn snapshot(&self) -> (String, usize, usize, usize) {
        (
            self.phase.lock().unwrap().clone(),
            self.done.load(Ordering::Relaxed),
            self.total.load(Ordering::Relaxed),
            self.used.load(Ordering::Relaxed),
        )
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct SubnetState {
    pub cidr: String,
    pub interface: String,
    pub hosts: Vec<Host>,
    pub total: usize,
    pub used: usize,
    pub available: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct AppStateJson {
    pub status: String,
    pub phase: String,
    pub scanned: usize,
    pub total_ips: usize,
    pub used_total: usize,
    pub available_total: usize,
    pub last_scan_unix: Option<i64>,
    pub last_duration_ms: Option<u64>,
    pub method: String,
    pub error: Option<String>,
    pub self_ips: Vec<String>,
    pub subnets: Vec<SubnetState>,
}

pub struct ManagerInner {
    pub subnets: Vec<SubnetState>,
    pub status: String,
    pub method: String,
    pub last_scan_unix: Option<i64>,
    pub last_duration_ms: Option<u64>,
    pub error: Option<String>,
}

pub struct Manager {
    pub inner: RwLock<ManagerInner>,
    pub progress: Arc<ScanProgress>,
    pub scan_trigger: Notify,
    pub cfg: Arc<Config>,
    pub subnets: Vec<Ipv4Network>,
}

impl Manager {
    pub fn new(cfg: Arc<Config>, subnets: Vec<Ipv4Network>) -> Self {
        let inner = ManagerInner {
            subnets: Vec::new(),
            status: "idle".into(),
            method: String::new(),
            last_scan_unix: None,
            last_duration_ms: None,
            error: None,
        };
        Self {
            inner: RwLock::new(inner),
            progress: Arc::new(ScanProgress::new()),
            scan_trigger: Notify::new(),
            cfg,
            subnets,
        }
    }

    /// Run one full scan cycle over all configured subnets. Safe to call
    /// concurrently: overlapping scans are skipped.
    pub async fn run_scan(&self) {
        {
            let mut inner = self.inner.write().await;
            if inner.status == "scanning" {
                return;
            }
            inner.status = "scanning".into();
            inner.error = None;
        }

        tracing::info!("starting scan of {} subnet(s)", self.subnets.len());
        let started = std::time::Instant::now();

        let mut subnets = Vec::new();
        let mut method = String::new();
        let mut err: Option<String> = None;

        for net in &self.subnets {
            let result = scanner::scan_subnet(
                *net,
                self.cfg.method,
                Duration::from_millis(self.cfg.timeout_ms),
                &self.cfg.ports,
                self.cfg.concurrency,
                self.cfg.detect_os,
                &self.progress,
            )
            .await;

            let iface_name =
                netinfo::interface_name_for_subnet(*net).unwrap_or_else(|| "unknown".into());
            let total = result.hosts.len();
            let used = result.hosts.iter().filter(|h| h.used).count();

            if method.is_empty() {
                method = result.method.clone();
            }
            if err.is_none() {
                err = result.error;
            }

            subnets.push(SubnetState {
                cidr: net.to_string(),
                interface: iface_name,
                hosts: result.hosts,
                total,
                used,
                available: total.saturating_sub(used),
            });
        }

        let elapsed = started.elapsed();
        {
            let mut inner = self.inner.write().await;
            inner.subnets = subnets;
            inner.status = "idle".into();
            inner.method = method;
            inner.last_scan_unix = Some(unix_now());
            inner.last_duration_ms = Some(elapsed.as_millis() as u64);
            inner.error = err;
        }
        tracing::info!("scan finished in {} ms", elapsed.as_millis());
    }

    pub async fn snapshot(&self) -> AppStateJson {
        let inner = self.inner.read().await;
        let (phase, done, total, used) = self.progress.snapshot();
        let scanning = inner.status == "scanning";

        let subnets_total: usize = inner.subnets.iter().map(|s| s.total).sum();
        let subnets_used: usize = inner.subnets.iter().map(|s| s.used).sum();
        let subnets_avail: usize = inner.subnets.iter().map(|s| s.available).sum();

        let self_ips: Vec<String> = self
            .subnets
            .iter()
            .filter_map(|net| {
                netinfo::interface_for_ip(net.ip())
                    .as_ref()
                    .and_then(netinfo::source_ip)
                    .map(|ip| ip.to_string())
            })
            .collect();

        AppStateJson {
            status: inner.status.clone(),
            phase,
            scanned: if scanning { done } else { 0 },
            total_ips: if scanning { total } else { subnets_total },
            used_total: if scanning { used } else { subnets_used },
            available_total: if scanning {
                total.saturating_sub(used)
            } else {
                subnets_avail
            },
            last_scan_unix: inner.last_scan_unix,
            last_duration_ms: inner.last_duration_ms,
            method: inner.method.clone(),
            error: inner.error.clone(),
            self_ips,
            subnets: inner.subnets.clone(),
        }
    }
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
