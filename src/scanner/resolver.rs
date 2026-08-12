use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::Duration;

/// Reverse-DNS lookup for a list of IPs, with bounded concurrency and a short
/// per-host timeout. Slow or failing lookups are skipped.
pub async fn resolve_hostnames(ips: &[Ipv4Addr]) -> HashMap<Ipv4Addr, String> {
    let sem = std::sync::Arc::new(tokio::sync::Semaphore::new(64));
    let mut handles = Vec::new();

    for &ip in ips {
        let sem = sem.clone();
        handles.push(tokio::spawn(async move {
            let _permit = sem.acquire().await.ok()?;
            let ip_std = std::net::IpAddr::V4(ip);
            let fut = tokio::task::spawn_blocking(move || {
                dns_lookup::lookup_addr(&ip_std).ok()
            });
            match tokio::time::timeout(Duration::from_secs(1), fut).await {
                Ok(Ok(Some(name))) if !name.is_empty() => Some((ip, name)),
                _ => None,
            }
        }));
    }

    let mut out = HashMap::new();
    for handle in handles {
        if let Ok(Some((ip, name))) = handle.await {
            out.insert(ip, name);
        }
    }
    out
}
