# net-scanner

Scans the local network and shows **used** vs **available** IP addresses in a
clean web UI. A Rust backend periodically probes every address in your LAN and
serves the results over HTTP.

## Features

- Periodic background scanning (default every 10s) with a "scan now" button
- **ARP scan** when run privileged (root / `CAP_NET_RAW`) -> gives MAC address
  and vendor (bundled OUI table)
- Automatic **fallback to ICMP + TCP probes** when unprivileged -> still finds
  live hosts by pinging and probing common ports
- Reverse-DNS hostnames and response times for used hosts (open ports are
  probed internally to detect hosts, but never exposed in the UI/API)
- **OS fingerprinting**: each used host is labelled with its likely OS
  (Windows, Apple macOS/iOS, Linux/Unix, Printer, Network device) from the
  ICMP reply TTL plus open TCP ports
- Dark-themed grid: green = used, grey = available, yellow = this machine
- Live stats (used / available / total), progress bar, per-subnet tabs
- Multiple subnets, configurable via `config.toml` or CLI flags

## Build & run

Requires a Rust toolchain. Install it with [rustup](https://rustup.rs/) (see also
the [official installation guide](https://www.rust-lang.org/tools/install)), then:

```bash
cargo build --release
```

Run unprivileged (TCP probe; no root needed):

```bash
./target/release/net-scanner
```

Run privileged for full ARP results (MAC + vendor):

```bash
sudo ./target/release/net-scanner
```

Open http://127.0.0.1:8080

> By default it auto-detects the subnet of the interface holding the default
> route. The provided `config.toml` pins `192.168.100.0/24` - adjust it to your
> network or pass `--subnet` instead.

## Configuration

All options can be given via CLI flags or `config.toml`:

| Option           | CLI                          | Default                  |
| ---------------- | ---------------------------- | ------------------------ |
| Web bind address | `--bind 0.0.0.0:8080`        | `127.0.0.1:8080`         |
| Scan interval    | `--interval 60`              | `10` seconds            |
| Scan method      | `--method auto\|arp\|tcp`    | `auto`                   |
| Probe timeout    | `--timeout-ms 500`           | `100` ms                 |
| Concurrency      | `--concurrency 512`          | `256`                    |
| Subnets          | `--subnet 10.0.0.0/24`       | auto-detect main LAN     |
| OS detection     | `--detect-os false`          | `true`                   |

```bash
# scan two subnets every 15 seconds, listen on all interfaces
./target/release/net-scanner --subnet 192.168.1.0/24 --subnet 10.0.0.0/24 \
  --interval 15 --bind 0.0.0.0:8080

# custom config file
./target/release/net-scanner --config /etc/net-scanner.toml
```

## How it decides "used"

1. **ARP**: sends an ARP request to every IP; any reply means the address is
   in use. Requires root / `CAP_NET_RAW`.
2. **Fallback (TCP + ICMP)**: tries connecting to a list of common ports
   (22, 53, 80, 443, 445, 8080, ...) with a short timeout; any open port marks
   the host as used. Best-effort ICMP ping adds hosts that answer pings but
   expose no common ports. Which ports are open is never shown.

Hosts are re-detected on every scan and marked accordingly in the UI.

## How it guesses the OS

1. **TTL**: the IP TTL of the ICMP reply narrows the family - Unix-likes start
   at 64, Windows at 128, routers/network gear often at 255. Requires root for
   the raw-socket probe.
2. **Open ports**: port fingerprints refine the guess (445/135/3389 -> Windows,
   62078/7000 -> Apple, 22/631 -> Linux/Unix, 9100 -> Printer, 23/53/80 ->
   router/network device).

A weighted score picks the best label; with no signal the OS stays unknown
("–"). Disable with `detect_os = false`.

## HTTP API

| Method | Path          | Description                       |
| ------ | ------------- | --------------------------------- |
| GET    | `/`           | Web UI                            |
| GET    | `/api/state`  | Current scan results (JSON)       |
| POST   | `/api/scan`   | Trigger a scan immediately        |
| GET    | `/api/health` | Liveness check                    |

## Troubleshooting

- **"failed to open datalink channel"**: run with `sudo`, or just use the TCP
  probe mode (run without `sudo`), which needs no privileges.
- **No subnet found**: pass `--subnet <CIDR>` explicitly.
- **Firewall / AP isolation**: some routers block ARP/ping between clients;
  those hosts may only be detected if they expose a common TCP port.

## Support

If you find this tool useful, consider a small tip:

[![Donate via PayPal](https://img.shields.io/badge/Donate-PayPal-00457C?logo=paypal&logoColor=white)](https://www.paypal.me/andikurnia)
