use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use surge_ping::{Client, Config, PingIdentifier, PingSequence};

/// Best-effort ICMP ping of every target. Requires root / CAP_NET_RAW on most
/// systems; on failure it returns an empty list so scanning can fall back to TCP.
pub async fn icmp_probe(
    targets: &[Ipv4Addr],
    timeout: Duration,
) -> Vec<(Ipv4Addr, Duration)> {
    let client = Arc::new(match Client::new(&Config::default()) {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!("ICMP unavailable ({}); skipping ping probe", e);
            return Vec::new();
        }
    });

    let sem = Arc::new(tokio::sync::Semaphore::new(64));
    let mut handles = Vec::new();

    for (idx, &ip) in targets.iter().enumerate() {
        let client = client.clone();
        let sem = sem.clone();
        handles.push(tokio::spawn(async move {
            let _permit = sem.acquire().await.ok()?;
            let mut pinger = client
                .pinger(
                    std::net::IpAddr::V4(ip),
                    PingIdentifier(idx as u16),
                )
                .await;
            pinger.timeout(timeout);
            let (_pkt, rtt) = pinger.ping(PingSequence(1), &[0u8; 8]).await.ok()?;
            Some((ip, rtt))
        }));
    }

    let mut results = Vec::new();
    for handle in handles {
        if let Ok(Some((ip, rtt))) = handle.await {
            results.push((ip, rtt));
        }
    }
    results
}
