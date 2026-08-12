pub mod arp;
pub mod icmp;
pub mod os;
pub mod resolver;
pub mod tcp;
pub mod vendor;

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use ipnetwork::Ipv4Network;
use serde::Serialize;

use crate::config::ScanMethod;
use crate::netinfo;
use crate::state::ScanProgress;

#[derive(Debug, Clone, Serialize)]
pub struct Host {
    pub ip: Ipv4Addr,
    pub used: bool,
    pub mac: Option<String>,
    pub vendor: Option<String>,
    pub hostname: Option<String>,
    pub os: Option<String>,
    pub rtt_ms: Option<u64>,
}

pub struct SubnetScanResult {
    pub hosts: Vec<Host>,
    pub method: String,
    pub error: Option<String>,
}

/// Scan every usable IP in `subnet` using the configured strategy:
///   - arp:    ARP probe (needs root / CAP_NET_RAW), gives MAC + vendor.
///   - auto:   try ARP first, fall back to ICMP + TCP probes on failure.
///   - tcp:    ICMP + TCP connect probes only (works without privileges).
pub async fn scan_subnet(
    subnet: Ipv4Network,
    method: ScanMethod,
    timeout: Duration,
    ports: &[u16],
    concurrency: usize,
    detect_os: bool,
    progress: &Arc<ScanProgress>,
) -> SubnetScanResult {
    let mut ips: Vec<Ipv4Addr> = subnet.iter().collect();
    if ips.len() > 2 {
        ips.remove(0);
        ips.pop();
    }
    let total = ips.len();
    progress.reset(total);
    progress.set_phase("preparing");

    let iface = netinfo::interface_for_ip(subnet.ip());
    let source_ip = iface.as_ref().and_then(netinfo::source_ip);

    let mut hosts: HashMap<Ipv4Addr, Host> = HashMap::new();
    for &ip in &ips {
        hosts.insert(
            ip,
            Host {
                ip,
                used: false,
                mac: None,
                vendor: None,
                hostname: None,
                os: None,
                rtt_ms: None,
            },
        );
    }

    let mut method_used = String::new();
    let mut arp_ok = false;

    // --- ARP scan -------------------------------------------------------
    if matches!(method, ScanMethod::Auto | ScanMethod::Arp) {
        if let (Some(iface), Some(src)) = (&iface, source_ip) {
            progress.set_phase("arp");
            let (iface, ips_c, timeout_c, progress_c, src) =
                (iface.clone(), ips.clone(), timeout, progress.clone(), src);
            let task = tokio::task::spawn_blocking(move || {
                arp::arp_scan(&iface, src, &ips_c, timeout_c, Some(&progress_c))
            });
            match task.await {
                Ok(Ok(found)) => {
                    arp_ok = true;
                    method_used = "arp".into();
                    for (ip, (mac, rtt)) in found {
                        if let Some(h) = hosts.get_mut(&ip) {
                            h.used = true;
                            h.mac = Some(mac.to_string());
                            h.vendor = vendor::vendor_for_mac(&mac).map(str::to_string);
                            h.rtt_ms = Some(rtt.as_millis() as u64);
                        }
                    }
                }
                Ok(Err(e)) => {
                    if method == ScanMethod::Arp {
                        return SubnetScanResult {
                            hosts: Vec::new(),
                            method: "arp".into(),
                            error: Some(e),
                        };
                    }
                    tracing::warn!("ARP scan failed ({e}); falling back to TCP probe");
                }
                Err(e) => {
                    tracing::warn!("ARP scan task failed ({e}); falling back to TCP probe");
                }
            }
        } else if method == ScanMethod::Arp {
            let detail = match (&iface, source_ip) {
                (None, _) => "no interface found for subnet".to_string(),
                (Some(i), None) => format!("no IPv4 address on interface {}", i.name),
                _ => "missing interface".to_string(),
            };
            return SubnetScanResult {
                hosts: Vec::new(),
                method: "arp".into(),
                error: Some(detail),
            };
        }
    }

    // --- ICMP + TCP fallback --------------------------------------------
    if !arp_ok {
        progress.set_phase("icmp");
        let icmp_found = icmp::icmp_probe(&ips, timeout).await;

        progress.set_phase("tcp");
        let tcp_found = tcp::tcp_probe(&ips, ports, timeout, concurrency, Some(progress), false).await;
        method_used = if method_used.is_empty() {
            "tcp".into()
        } else {
            format!("{method_used}+tcp")
        };

        for (ip, open, elapsed) in tcp_found {
            let pingable = icmp_found.iter().any(|(p, _)| *p == ip);
            if let Some(h) = hosts.get_mut(&ip) {
                h.used = !open.is_empty() || pingable;
                if h.used {
                    h.rtt_ms = Some(elapsed.as_millis() as u64);
                }
            }
        }
        for (ip, rtt) in icmp_found {
            if let Some(h) = hosts.get_mut(&ip) {
                if !h.used {
                    h.used = true;
                    h.rtt_ms = Some(rtt.as_millis() as u64);
                }
            }
        }
    }

    // --- This machine is always "used" ---------------------------------
    // The ARP probe rarely gets a reply for our own IP, but it is obviously
    // in use, so mark it explicitly (with MAC/vendor from the interface).
    if let Some(src_ip) = source_ip {
        if let Some(h) = hosts.get_mut(&src_ip) {
            h.used = true;
            if h.mac.is_none() {
                if let Some(mac) = iface.as_ref().and_then(|i| i.mac) {
                    h.mac = Some(mac.to_string());
                    if h.vendor.is_none() {
                        h.vendor = vendor::vendor_for_mac(&mac).map(str::to_string);
                    }
                }
            }
            if h.rtt_ms.is_none() {
                h.rtt_ms = Some(0);
            }
        }
    }

    // --- Hostname resolution --------------------------------------------
    progress.set_phase("dns");
    let used_ips: Vec<Ipv4Addr> = hosts
        .values()
        .filter(|h| h.used)
        .map(|h| h.ip)
        .collect();
    let names = resolver::resolve_hostnames(&used_ips).await;
    for (ip, name) in names {
        if let Some(h) = hosts.get_mut(&ip) {
            h.hostname = Some(name);
        }
    }

    // --- OS fingerprinting ---------------------------------------------
    if detect_os && !used_ips.is_empty() {
        progress.set_phase("os");
        let used_ips_c = used_ips.clone();
        let ports_c = ports.to_vec();
        let used_ips_c2 = used_ips.clone();
        let ttl_task =
            tokio::task::spawn_blocking(move || os::ttl_probe(&used_ips_c, Duration::from_secs(1)));
        let tcp_fut = async move {
            tcp::tcp_probe(&used_ips_c2, &ports_c, timeout, concurrency, None, true).await
        };
        let (ttl_map, tcp_found) = tokio::join!(ttl_task, tcp_fut);
        let ttl_map = ttl_map.unwrap_or_default();
        let port_map: HashMap<Ipv4Addr, Vec<u16>> = tcp_found
            .into_iter()
            .map(|(ip, open, _)| (ip, open))
            .collect();
        for ip in &used_ips {
            let ttl = ttl_map.get(ip).copied();
            let open_ports = port_map.get(ip).map(Vec::as_slice).unwrap_or(&[]);
            if let Some(os) = os::detect(ttl, open_ports) {
                if let Some(h) = hosts.get_mut(ip) {
                    h.os = Some(os);
                }
            }
        }
    }

    progress.set_phase("done");

    let mut hosts: Vec<Host> = hosts.into_values().collect();
    hosts.sort_by_key(|h| h.ip);

    SubnetScanResult {
        hosts,
        method: method_used,
        error: None,
    }
}
