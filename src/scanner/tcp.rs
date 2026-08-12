use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpStream;
use tokio::sync::Semaphore;

use crate::state::ScanProgress;

/// Probe every target by trying to open TCP connections to `ports`.
/// A host is considered "used" when any port accepts a connection.
/// Returns (ip, open ports, elapsed). When `collect_all` is true, every port
/// is tried and the full set of open ports is returned (used for OS
/// fingerprinting); otherwise the probe stops at the first open port.
pub async fn tcp_probe(
    targets: &[Ipv4Addr],
    ports: &[u16],
    timeout: Duration,
    concurrency: usize,
    progress: Option<&Arc<ScanProgress>>,
    collect_all: bool,
) -> Vec<(Ipv4Addr, Vec<u16>, Duration)> {
    let sem = Arc::new(Semaphore::new(concurrency.max(1)));
    let mut handles = Vec::new();

    for &ip in targets {
        let sem = sem.clone();
        let ports = ports.to_vec();
        let progress = progress.cloned();
        handles.push(tokio::spawn(async move {
            let _permit = sem.acquire().await.expect("semaphore closed");
            let started = std::time::Instant::now();
            let mut open = Vec::new();
            for port in ports {
                let addr = std::net::SocketAddr::from((ip, port));
                match tokio::time::timeout(timeout, TcpStream::connect(addr)).await {
                    Ok(Ok(_)) => {
                        open.push(port);
                        if !collect_all {
                            break;
                        }
                    }
                    _ => continue,
                }
            }
            let elapsed = started.elapsed();
            if let Some(p) = &progress {
                p.tick(!open.is_empty());
            }
            (ip, open, elapsed)
        }));
    }

    let mut results = Vec::with_capacity(handles.len());
    for handle in handles {
        if let Ok(r) = handle.await {
            results.push(r);
        }
    }
    results
}
