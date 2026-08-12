mod api;
mod config;
mod netinfo;
mod scanner;
mod state;

use std::sync::Arc;
use std::time::Duration;

use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let (cfg, subnets) = match config::Config::load() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(1);
        }
    };
    let cfg = Arc::new(cfg);

    println!("net-monitor");
    println!("  subnets:  {}", subnets.iter().map(|n| n.to_string()).collect::<Vec<_>>().join(", "));
    println!("  method:   {:?}", cfg.method);
    println!("  interval: {}s", cfg.scan_interval_secs);
    println!("  web UI:   http://{}", cfg.bind);

    let manager = Arc::new(state::Manager::new(cfg.clone(), subnets.clone()));

    let router = api::router(manager.clone());
    let listener = tokio::net::TcpListener::bind(&cfg.bind)
        .await
        .unwrap_or_else(|e| {
            eprintln!("cannot bind {}: {e}", cfg.bind);
            std::process::exit(1);
        });
    tokio::spawn(async move {
        axum::serve(listener, router).await.expect("web server failed");
    });

    // Background scanner: scan immediately, then every interval or on demand.
    let scan_manager = manager.clone();
    let interval = cfg.scan_interval_secs;
    tokio::spawn(async move {
        loop {
            scan_manager.run_scan().await;
            tokio::select! {
                _ = scan_manager.scan_trigger.notified() => {}
                _ = tokio::time::sleep(Duration::from_secs(interval)) => {}
            }
        }
    });

    tokio::signal::ctrl_c().await.expect("failed to listen for ctrl-c");
    println!("\nshutting down");
}
