use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use pnet::packet::icmp::{checksum, IcmpCode, IcmpTypes, MutableIcmpPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::Packet;
use pnet::transport::{ipv4_packet_iter, transport_channel, TransportChannelType};

/// Fingerprint an OS from the initial TTL of an ICMP reply plus the set of
/// open TCP ports. Returns a short human label, or `None` when there is no
/// usable signal.
pub fn detect(ttl: Option<u8>, open_ports: &[u16]) -> Option<String> {
    const WINDOWS: usize = 0;
    const APPLE: usize = 1;
    const PRINTER: usize = 2;
    const LINUX: usize = 3;
    const DEVICE: usize = 4;
    const LABELS: [&str; 5] = [
        "Windows",
        "Apple (macOS/iOS)",
        "Printer",
        "Linux/Unix",
        "Network device",
    ];
    // Tie-break towards the more specific category.
    const PRIORITY: [i32; 5] = [3, 4, 2, 1, 0];

    let mut s = [0i32; 5];
    match ttl {
        Some(t) if t <= 64 => s[LINUX] += 20,
        Some(t) if t <= 128 => s[WINDOWS] += 20,
        Some(_) => s[DEVICE] += 15,
        None => {}
    }
    for &p in open_ports {
        match p {
            135 | 139 | 445 | 593 | 3389 | 5985 | 5986 => s[WINDOWS] += 40,
            88 | 3283 | 3689 | 5000 | 548 | 7000 | 8787 | 62022 | 62078 => s[APPLE] += 40,
            22 | 111 | 2049 => s[LINUX] += 15,
            515 | 631 => {
                s[LINUX] += 10;
                s[PRINTER] += 12;
            }
            9100 => s[PRINTER] += 40,
            23 | 161 | 1900 => s[DEVICE] += 12,
            53 | 123 => {
                s[DEVICE] += 8;
                s[LINUX] += 4;
            }
            80 | 443 | 8080 | 8443 => s[DEVICE] += 6,
            _ => {}
        }
    }

    let mut best = 0usize;
    for i in 1..5 {
        if s[i] > s[best] || (s[i] == s[best] && PRIORITY[i] > PRIORITY[best]) {
            best = i;
        }
    }
    if s[best] <= 0 {
        return None;
    }
    Some(LABELS[best].to_string())
}

/// Send an ICMP echo request to every target and read back the echo replies to
/// capture the IP TTL of each responder. Requires root / CAP_NET_RAW; on
/// failure (or non-Unix platforms) it returns an empty map so OS detection can
/// fall back to port fingerprints alone.
#[cfg(unix)]
pub fn ttl_probe(targets: &[Ipv4Addr], wait: Duration) -> HashMap<Ipv4Addr, u8> {
    let mut result = HashMap::new();
    if targets.is_empty() {
        return result;
    }

    let (mut tx, mut rx) = match transport_channel(
        4096,
        TransportChannelType::Layer3(IpNextHeaderProtocols::Icmp),
    ) {
        Ok(c) => c,
        Err(e) => {
            tracing::debug!("ICMP TTL probe unavailable ({e}); using port fingerprints only");
            return result;
        }
    };

    // Bounded receive: without this, iter.next() blocks forever after the
    // replies have been drained.
    unsafe {
        let tv = libc::timeval {
            tv_sec: 0,
            tv_usec: 100_000,
        };
        libc::setsockopt(
            rx.socket.fd,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            &tv as *const libc::timeval as *const libc::c_void,
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        );
    }

    let id_base = std::process::id() as u16;
    for (i, &target) in targets.iter().enumerate() {
        let ident = id_base.wrapping_add(i as u16);
        let mut buf = [0u8; 40];
        let mut pkt = match MutableIcmpPacket::new(&mut buf) {
            Some(p) => p,
            None => continue,
        };
        pkt.set_icmp_type(IcmpTypes::EchoRequest);
        pkt.set_icmp_code(IcmpCode(0));
        let mut payload = [0u8; 8];
        payload[0..2].copy_from_slice(&ident.to_be_bytes());
        payload[2..4].copy_from_slice(&(i as u16).to_be_bytes());
        pkt.set_payload(&payload);
        let sum = checksum(&pkt.to_immutable());
        pkt.set_checksum(sum);
        let _ = tx.send_to(pkt, std::net::IpAddr::V4(target));
    }

    let deadline = Instant::now() + wait;
    let mut iter = ipv4_packet_iter(&mut rx);
    while Instant::now() < deadline {
        match iter.next() {
            Ok((ip_pkt, _)) => {
                if ip_pkt.get_version() != 4 {
                    continue;
                }
                let icmp = ip_pkt.payload();
                if icmp.len() < 8 || icmp[0] != 0 {
                    continue; // not an echo reply
                }
                let ident = u16::from_be_bytes([icmp[4], icmp[5]]);
                let idx = ident.wrapping_sub(id_base) as usize;
                let ip = ip_pkt.get_source();
                if idx < targets.len() && targets[idx] == ip {
                    result.entry(ip).or_insert(ip_pkt.get_ttl());
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(_) => break,
        }
    }
    result
}

#[cfg(not(unix))]
pub fn ttl_probe(_targets: &[Ipv4Addr], _wait: Duration) -> HashMap<Ipv4Addr, u8> {
    HashMap::new()
}

#[cfg(test)]
mod tests {
    use super::detect;

    #[test]
    fn ttl_and_ssh_is_linux() {
        assert_eq!(detect(Some(64), &[22]).as_deref(), Some("Linux/Unix"));
    }

    #[test]
    fn ttl_alone_is_windows() {
        assert_eq!(detect(Some(128), &[]).as_deref(), Some("Windows"));
    }

    #[test]
    fn windows_ports_beat_linux_ttl() {
        assert_eq!(detect(Some(64), &[135, 139, 445, 3389]).as_deref(), Some("Windows"));
    }

    #[test]
    fn apple_ports_beat_linux_ttl() {
        assert_eq!(detect(Some(64), &[62078]).as_deref(), Some("Apple (macOS/iOS)"));
    }

    #[test]
    fn printer_port_wins() {
        assert_eq!(detect(Some(64), &[9100, 515, 631]).as_deref(), Some("Printer"));
    }

    #[test]
    fn router_ttl_and_web_ports() {
        assert_eq!(detect(Some(255), &[53, 80, 443]).as_deref(), Some("Network device"));
    }

    #[test]
    fn ports_without_ttl() {
        assert_eq!(detect(None, &[445, 3389]).as_deref(), Some("Windows"));
    }

    #[test]
    fn no_signal_is_none() {
        assert_eq!(detect(None, &[]), None);
        assert_eq!(detect(Some(64), &[]).as_deref(), Some("Linux/Unix"));
    }
}
