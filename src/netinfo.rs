use std::net::Ipv4Addr;

use ipnetwork::Ipv4Network;
use pnet::datalink;

/// Return the IPv4 subnet(s) of the "main" LAN(s) to scan.
/// Prefers the interface that owns the default route, then any other
/// suitable non-loopback interface with a private IPv4 address.
pub fn detect_default_subnets() -> Vec<Ipv4Network> {
    let interfaces = datalink::interfaces();
    let default_name = default_interface_name();

    let mut ordered: Vec<_> = interfaces.iter().collect();
    if let Some(name) = &default_name {
        ordered.sort_by_key(|i| if &i.name == name { 0 } else { 1 });
    }

    let mut result = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for iface in ordered {
        if iface.is_loopback() || !iface.is_up() {
            continue;
        }
        for net in &iface.ips {
            if let ipnetwork::IpNetwork::V4(v4) = net {
                let ip = v4.ip();
                if ip.is_private() && v4.prefix() > 0 && v4.prefix() <= 30 {
                    let key = (u32::from(v4.network()), v4.prefix());
                    if seen.insert(key) {
                        result.push(*v4);
                    }
                }
            }
        }
    }
    result
}

/// Find the name of the interface owning the default route (Linux /proc/net/route).
fn default_interface_name() -> Option<String> {
    let route = std::fs::read_to_string("/proc/net/route").ok()?;
    for line in route.lines().skip(1) {
        let mut parts = line.split_whitespace();
        let name = parts.next()?;
        let dest = u32::from_str_radix(parts.next()?, 16).ok()?;
        if dest == 0 {
            return Some(name.to_string());
        }
    }
    None
}

/// Find a pnet interface whose subnet contains `ip`.
pub fn interface_for_ip(ip: Ipv4Addr) -> Option<datalink::NetworkInterface> {
    datalink::interfaces()
        .into_iter()
        .find(|i| {
            i.ips
                .iter()
                .any(|n| matches!(n, ipnetwork::IpNetwork::V4(v) if v.contains(ip)))
        })
}

/// The IPv4 source address to use when scanning on `iface`.
pub fn source_ip(iface: &datalink::NetworkInterface) -> Option<Ipv4Addr> {
    iface.ips.iter().find_map(|n| match n {
        ipnetwork::IpNetwork::V4(v) => Some(v.ip()),
        _ => None,
    })
}

/// Interface name for a subnet (used for display).
pub fn interface_name_for_subnet(net: Ipv4Network) -> Option<String> {
    interface_for_ip(net.ip()).map(|i| i.name)
}
