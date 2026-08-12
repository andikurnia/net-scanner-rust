use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::Duration;

use pnet::datalink::{self, Config, NetworkInterface};
use pnet::datalink::Channel::Ethernet;
use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::{MutablePacket, Packet};
use pnet::util::MacAddr;

use crate::state::ScanProgress;

/// Send ARP requests to every target on the given interface and collect the
/// replies. Returns a map of IP -> (MAC, round-trip time).
pub fn arp_scan(
    iface: &NetworkInterface,
    source_ip: Ipv4Addr,
    targets: &[Ipv4Addr],
    wait: Duration,
    progress: Option<&ScanProgress>,
) -> Result<HashMap<Ipv4Addr, (MacAddr, Duration)>, String> {
    let config = Config {
        read_timeout: Some(wait),
        ..Config::default()
    };
    let (mut tx, mut rx) = match datalink::channel(iface, config) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => return Err("unsupported channel type".into()),
        Err(e) => {
            return Err(format!(
                "failed to open datalink channel on {}: {e} (are you root / do you have CAP_NET_RAW?)",
                iface.name
            ))
        }
    };

    let source_mac = iface
        .mac
        .ok_or_else(|| format!("interface {} has no MAC address", iface.name))?;

    let start = std::time::Instant::now();
    for &target in targets {
        let mut eth_buf = [0u8; 42];
        let mut arp_buf = [0u8; 28];

        let mut eth = MutableEthernetPacket::new(&mut eth_buf)
            .ok_or_else(|| "ethernet buffer too small".to_string())?;
        eth.set_destination(MacAddr::broadcast());
        eth.set_source(source_mac);
        eth.set_ethertype(EtherTypes::Arp);

        let mut arp = MutableArpPacket::new(&mut arp_buf)
            .ok_or_else(|| "arp buffer too small".to_string())?;
        arp.set_hardware_type(ArpHardwareTypes::Ethernet);
        arp.set_protocol_type(EtherTypes::Ipv4);
        arp.set_hw_addr_len(6);
        arp.set_proto_addr_len(4);
        arp.set_operation(ArpOperations::Request);
        arp.set_sender_hw_addr(source_mac);
        arp.set_sender_proto_addr(source_ip);
        arp.set_target_hw_addr(MacAddr::zero());
        arp.set_target_proto_addr(target);

        eth.set_payload(arp.packet_mut());
        match tx.send_to(eth.packet(), None) {
            Some(Ok(())) => {}
            Some(Err(e)) => return Err(format!("failed to send ARP request for {target}: {e}")),
            None => return Err("send buffer full while sending ARP requests".into()),
        }

        if let Some(p) = progress {
            p.tick(false);
        }
    }

    let mut found: HashMap<Ipv4Addr, (MacAddr, Duration)> = HashMap::new();
    let deadline = start + wait;
    while std::time::Instant::now() < deadline {
        let frame = match rx.next() {
            Ok(frame) => frame,
            Err(_) => break,
        };
        let Some(eth) = EthernetPacket::new(frame) else {
            continue;
        };
        if eth.get_ethertype() != EtherTypes::Arp {
            continue;
        }
        let Some(arp) = ArpPacket::new(eth.payload()) else {
            continue;
        };
        if arp.get_operation() != ArpOperations::Reply {
            continue;
        }
        if arp.get_target_proto_addr() != source_ip {
            continue;
        }
        let sender = arp.get_sender_proto_addr();
        if !targets.contains(&sender) || found.contains_key(&sender) {
            continue;
        }
        let mac = arp.get_sender_hw_addr();
        if mac == MacAddr::zero() {
            continue;
        }
        found.insert(sender, (mac, start.elapsed()));
        if let Some(p) = progress {
            p.tick(true);
        }
    }

    Ok(found)
}
