mod manufacturer;
mod sap;

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;
use tauri::{AppHandle, Emitter, Manager, State};

use manufacturer::identify_manufacturer;
use sap::{parse_sap, parse_sdp_metadata};

use dns_parser::{Packet as DnsPacket, RData};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::udp::UdpPacket;
use pnet::packet::vlan::VlanPacket;
use pnet::packet::Packet;
use socket2::{Domain, Protocol, Socket, Type};

#[cfg(windows)]
use std::os::windows::process::CommandExt;

const SAP_GROUPS: [Ipv4Addr; 2] = [
    Ipv4Addr::new(239, 255, 255, 255),
    Ipv4Addr::new(224, 2, 127, 254),
];
const MDNS_GROUP: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
const MAX_SELECTED_INTERFACES: usize = 32;
const MAX_DISCOVERY_ENTRIES: usize = 4_096;
const PCAP_FILTER: &str = "ether proto 0x88cc or udp dst port 9875 or udp port 5353 or (vlan and (ether proto 0x88cc or udp dst port 9875 or udp port 5353))";

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct NetworkInterface {
    name: String,
    ip: String,
    mask: String,
}

#[derive(Serialize, Clone)]
struct SdpPayload {
    source_ip: String,
    network_source_ip: String,
    device_name: String,
    sdp_content: String,
    session_id: String,
    is_delete: bool,
    mac: String,
    manufacturer: String,
    sap_timeout_ms: u64,
    interface_ip: String,
}

#[derive(Serialize, Clone)]
struct PtpPayload {
    ptp_id: String,
    name: String,
    ip: String,
    interface_ip: String,
    domain: u8,
}

#[derive(Serialize, Clone)]
struct DeviceInfo {
    ip: String,
    name: String,
    #[serde(skip)]
    last_seen: std::time::Instant,
}

#[derive(Serialize)]
struct StartSniffingReport {
    started_interfaces: Vec<String>,
    failed_interfaces: Vec<String>,
    sap_groups: Vec<String>,
    ptp_active: bool,
}

struct SnifferSession {
    stop_flag: Arc<AtomicBool>,
    handles: Vec<JoinHandle<()>>,
}

pub struct AppState {
    sniffer_control: Mutex<()>,
    sniffer_session: Mutex<Option<SnifferSession>>,
    default_unknown_timeout_s: Mutex<u64>,
    discovery_table: Arc<Mutex<HashMap<String, DeviceInfo>>>,
    device_timeout_modes: Arc<Mutex<HashMap<String, bool>>>,
}

#[tauri::command]
fn get_network_interfaces() -> Vec<NetworkInterface> {
    let mut interfaces_map: HashMap<String, NetworkInterface> = HashMap::new();
    for iface in netdev::get_interfaces() {
        if iface.is_loopback() {
            continue;
        }
        let name = iface.friendly_name.clone().unwrap_or(iface.name.clone());
        for ipv4 in iface.ipv4 {
            let ip = ipv4.addr.to_string();
            let new_iface = NetworkInterface {
                name: name.clone(),
                ip: ip.clone(),
                mask: ipv4.netmask.to_string(),
            };
            if let Some(existing) = interfaces_map.get(&name) {
                if existing.ip.starts_with("169.254") && !ip.starts_with("169.254") {
                    interfaces_map.insert(name.clone(), new_iface);
                }
            } else {
                interfaces_map.insert(name.clone(), new_iface);
            }
        }
    }
    let mut result: Vec<NetworkInterface> = interfaces_map.into_values().collect();
    result.sort_by(|a, b| a.name.cmp(&b.name));
    result
}

fn validate_selected_interfaces(
    requested: Vec<NetworkInterface>,
) -> Result<Vec<NetworkInterface>, String> {
    if requested.is_empty() {
        return Err("Sélectionnez au moins une interface réseau.".to_string());
    }
    if requested.len() > MAX_SELECTED_INTERFACES {
        return Err(format!(
            "Trop d'interfaces sélectionnées (maximum {MAX_SELECTED_INTERFACES})."
        ));
    }

    let available = get_network_interfaces();
    let mut seen = HashSet::new();
    let mut validated = Vec::with_capacity(requested.len());
    for candidate in requested {
        candidate
            .ip
            .parse::<Ipv4Addr>()
            .map_err(|_| format!("Adresse IPv4 invalide pour {}.", candidate.name))?;
        let key = (candidate.name.clone(), candidate.ip.clone());
        if !seen.insert(key) {
            continue;
        }
        let current = available
            .iter()
            .find(|interface| interface.name == candidate.name && interface.ip == candidate.ip)
            .ok_or_else(|| {
                format!(
                    "L'interface {} ({}) n'est plus disponible.",
                    candidate.name, candidate.ip
                )
            })?;
        validated.push(current.clone());
    }
    Ok(validated)
}

fn stop_active_session(state: &AppState) -> Result<(), String> {
    let session = state
        .sniffer_session
        .lock()
        .map_err(|_| "État de capture indisponible.".to_string())?
        .take();
    if let Some(session) = session {
        session.stop_flag.store(true, Ordering::Release);
        for handle in session.handles {
            let _ = handle.join();
        }
    }
    Ok(())
}

fn create_multicast_membership_socket(interfaces: &[NetworkInterface]) -> Result<Socket, String> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))
        .map_err(|error| format!("Création du socket IGMP impossible : {error}"))?;
    let bind_address: SocketAddr = "0.0.0.0:0"
        .parse()
        .map_err(|error| format!("Adresse locale IGMP invalide : {error}"))?;
    socket
        .bind(&bind_address.into())
        .map_err(|error| format!("Initialisation du socket IGMP impossible : {error}"))?;

    for interface in interfaces {
        let interface_ip = interface
            .ip
            .parse::<Ipv4Addr>()
            .map_err(|_| format!("Adresse IPv4 invalide pour {}.", interface.name))?;
        for group in SAP_GROUPS {
            socket
                .join_multicast_v4(&group, &interface_ip)
                .map_err(|error| {
                    format!(
                        "Adhésion IGMP à {group} impossible sur {} ({}) : {error}",
                        interface.name, interface.ip
                    )
                })?;
        }
        // mDNS est utilisé pour résoudre les noms des équipements. Une erreur
        // ne doit pas empêcher la réception SAP.
        let _ = socket.join_multicast_v4(&MDNS_GROUP, &interface_ip);
    }
    Ok(socket)
}

#[tauri::command]
fn start_sniffing(
    app: AppHandle,
    selected_interfaces: Vec<NetworkInterface>,
    state: State<'_, AppState>,
) -> Result<StartSniffingReport, String> {
    let _control_guard = state
        .sniffer_control
        .lock()
        .map_err(|_| "Contrôle de capture indisponible.".to_string())?;
    stop_active_session(&state)?;
    let selected_interfaces = validate_selected_interfaces(selected_interfaces)?;
    let stop_flag = Arc::new(AtomicBool::new(false));
    let mut handles = Vec::new();
    let mut readiness_receivers = Vec::new();

    let membership_socket = create_multicast_membership_socket(&selected_interfaces)?;
    let stop_flag_membership = Arc::clone(&stop_flag);
    handles.push(thread::spawn(move || {
        let _membership_guard = membership_socket;
        while !stop_flag_membership.load(Ordering::Acquire) {
            thread::park_timeout(Duration::from_millis(250));
        }
    }));

    let default_unknown_timeout_s = *state
        .default_unknown_timeout_s
        .lock()
        .map_err(|_| "Configuration du timeout indisponible.".to_string())?;
    let discovery_table_arc = Arc::clone(&state.discovery_table);

    // Un thread par interface pour la capture LLDP, SAP et mDNS via pcap
    for network_interface in &selected_interfaces {
        let stop_flag_node = Arc::clone(&stop_flag);
        let discovery_node = Arc::clone(&discovery_table_arc);
        let device_timeout_modes_node = Arc::clone(&state.device_timeout_modes);
        let app_node = app.clone();
        let target_name = network_interface.name.clone();
        let target_ip = network_interface.ip.clone();
        let (ready_sender, ready_receiver) = mpsc::sync_channel::<Result<(), String>>(1);
        readiness_receivers.push((
            format!("{} ({})", network_interface.name, network_interface.ip),
            ready_receiver,
        ));

        handles.push(thread::spawn(move || {
            let mut mdns_cache: HashMap<String, String> = HashMap::new();
            let mut target_npf_name = String::new();
            let socket = match Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)) {
                Ok(socket) => socket,
                Err(error) => {
                    let _ = ready_sender.send(Err(format!(
                        "Socket mDNS indisponible sur {target_name} : {error}"
                    )));
                    return;
                }
            };
            let addr: SocketAddr = SocketAddr::from(([0, 0, 0, 0], 0));
            if let Err(error) = socket.bind(&addr.into()) {
                let _ = ready_sender.send(Err(format!(
                    "Initialisation mDNS impossible sur {target_name} : {error}"
                )));
                return;
            }
            let target_ipv4 = match target_ip.parse::<Ipv4Addr>() {
                Ok(ip) => ip,
                Err(_) => {
                    let _ = ready_sender.send(Err(format!(
                        "Adresse IPv4 invalide pour {target_name}."
                    )));
                    return;
                }
            };
            let _ = socket.set_multicast_if_v4(&target_ipv4);
            let mdns_sender: std::net::UdpSocket = socket.into();

            let send_mdns_query = |ip: &str, sender: &std::net::UdpSocket| {
                let parts: Vec<&str> = ip.split('.').collect();
                if parts.len() == 4 {
                    let reverse_name = format!("{}.{}.{}.{}.in-addr.arpa", parts[3], parts[2], parts[1], parts[0]);
                    let mut query = vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
                    for part in reverse_name.split('.') {
                        query.push(part.len() as u8);
                        query.extend_from_slice(part.as_bytes());
                    }
                    query.push(0);
                    query.extend_from_slice(&[0x00, 0x0C, 0x00, 0x01]);
                    let _ = sender.send_to(&query, "224.0.0.251:5353");
                }
            };

            // 1. Traduction : Trouver le vrai GUID Npcap via pnet::datalink
            for pnet_iface in pnet::datalink::interfaces() {
                let has_ip = pnet_iface.ips.iter().any(|ip| ip.ip().to_string() == target_ip);
                let desc_match = pnet_iface.description == target_name;

                if has_ip || desc_match {
                    target_npf_name = pnet_iface.name.clone();
                    break;
                }
            }

            if target_npf_name.is_empty() {
                let _ = ready_sender.send(Err(format!(
                    "Impossible d'associer {target_name} ({target_ip}) à une interface Npcap."
                )));
                return;
            }

            // 2. Accroche pcap
            let pcap_devices = match pcap::Device::list() {
                Ok(devices) => devices,
                Err(error) => {
                    let _ = ready_sender.send(Err(format!(
                        "Liste Npcap inaccessible pour {target_name} : {error}"
                    )));
                    return;
                }
            };
            let device = match pcap_devices.into_iter().find(|d| d.name == target_npf_name) {
                Some(d) => d,
                None => {
                    let _ = ready_sender.send(Err(format!(
                        "Npcap ne trouve pas l'interface {target_npf_name}."
                    )));
                    return;
                }
            };

            let inactive_capture = match pcap::Capture::from_device(device) {
                Ok(capture) => capture,
                Err(error) => {
                    let _ = ready_sender.send(Err(format!(
                        "Configuration Npcap impossible sur {target_name} : {error}"
                    )));
                    return;
                }
            };
            let mut cap = match inactive_capture
                .promisc(true)
                .snaplen(65535)
                .timeout(100)
                .open()
            {
                Ok(capture) => capture,
                Err(error) => {
                    let _ = ready_sender.send(Err(format!(
                        "Ouverture Npcap impossible sur {target_name} : {error}"
                    )));
                    return;
                }
            };
            if let Err(error) = cap.filter(PCAP_FILTER, true) {
                let _ = ready_sender.send(Err(format!(
                    "Filtre Npcap impossible sur {target_name} : {error}"
                )));
                return;
            }
            let _ = ready_sender.send(Ok(()));


            let mut mdns_cooldown: HashMap<String, std::time::Instant> = HashMap::new();
            let mut last_memory_cleanup = std::time::Instant::now();
            let mut global_mdns_counter = 0;
            let mut global_mdns_timer = std::time::Instant::now();
            let mut sap_last_emit: HashMap<String, (std::time::Instant, u16, bool)> =
                HashMap::new();

            while !stop_flag_node.load(Ordering::Acquire) {
                if last_memory_cleanup.elapsed().as_secs() > 300 {
                    mdns_cache.clear();
                    mdns_cooldown.clear();
                    sap_last_emit.retain(|_, (last_emit, _, _)| {
                        last_emit.elapsed().as_secs() < 900
                    });

                    if let Ok(mut table) = discovery_node.lock() {
                        table.retain(|_, entry| entry.last_seen.elapsed().as_secs() < 900);
                        if let Ok(mut modes) = device_timeout_modes_node.lock() {
                            modes.retain(|ip_key, _| {
                                table.values().any(|device| &device.ip == ip_key)
                            });
                        }
                    }

                    last_memory_cleanup = std::time::Instant::now();
                }

                match cap.next_packet() {
                    Ok(packet) => {
                        if let Some(eth) = EthernetPacket::new(packet.data) {
                            let mut current_ethertype = eth.get_ethertype();
                            let mut current_payload = eth.payload();
                            let vlan_packet = if current_ethertype == EtherTypes::Vlan {
                                VlanPacket::new(current_payload)
                            } else {
                                None
                            };

                            if current_ethertype == EtherTypes::Vlan {
                                if let Some(ref vlan) = vlan_packet {
                                    current_ethertype = vlan.get_ethertype();
                                    current_payload = vlan.payload();
                                } else {
                                    continue;
                                }
                            }

                            if current_ethertype == EtherTypes::Lldp {
                                if let Some((mac, name, ip)) = parse_lldp(current_payload) {
                                    let entry_to_emit = discovery_node.lock().ok().and_then(
                                        |mut table| {
                                            let can_insert =
                                                table.len() < MAX_DISCOVERY_ENTRIES;
                                            match table.entry(mac.clone()) {
                                                std::collections::hash_map::Entry::Vacant(
                                                    vacant,
                                                ) if can_insert => {
                                                    let entry = DeviceInfo {
                                                        ip: ip.clone(),
                                                        name: name.clone(),
                                                        last_seen:
                                                            std::time::Instant::now(),
                                                    };
                                                    vacant.insert(entry.clone());
                                                    Some(entry)
                                                }
                                                std::collections::hash_map::Entry::Occupied(
                                                    mut occupied,
                                                ) => {
                                                    let entry = occupied.get_mut();
                                                    entry.last_seen =
                                                        std::time::Instant::now();
                                                    let changed =
                                                        entry.ip != ip || entry.name != name;
                                                    entry.ip = ip;
                                                    entry.name = name;
                                                    changed.then(|| entry.clone())
                                                }
                                                _ => None,
                                            }
                                        },
                                    );
                                    if let Some(entry) = entry_to_emit {
                                        let _ = app_node
                                            .emit("discovery-update", (mac, entry));
                                    }
                                }
                            } else if current_ethertype == EtherTypes::Ipv4 {
                                if let Some(ipv4) = Ipv4Packet::new(current_payload) {
                                    let origin_ipv4 = ipv4.get_source();
                                    if origin_ipv4 == target_ipv4 {
                                        continue; // BOUCLIER 1 : Anti-Echo (on ignore nos propres paquets)
                                    }
                                    if ipv4.get_next_level_protocol() == IpNextHeaderProtocols::Udp {
                                        if let Some(udp) = UdpPacket::new(ipv4.payload()) {
                                            let dest_port = udp.get_destination();
                                            let src_port = udp.get_source();

                                            // --- 1. BRANCHE SAP (9875) ---
                                            if dest_port == 9875
                                                && SAP_GROUPS.contains(&ipv4.get_destination())
                                            {
                                                if !is_allowed_device_ip(origin_ipv4) {
                                                    continue;
                                                }
                                                let sap_message = match parse_sap(udp.payload()) {
                                                    Ok(message) => message,
                                                    Err(_) => continue,
                                                };
                                                let sap_source_ip = match sap_message.originating_source {
                                                    IpAddr::V4(ip) if is_allowed_device_ip(ip) => ip,
                                                    _ => origin_ipv4,
                                                };
                                                let fallback_session_key = format!(
                                                    "sap:{}:{:04X}",
                                                    sap_source_ip, sap_message.message_id_hash
                                                );
                                                let metadata = parse_sdp_metadata(
                                                    &sap_message.sdp,
                                                    &fallback_session_key,
                                                );
                                                let origin_ip = metadata
                                                    .origin_ip
                                                    .filter(|ip| is_allowed_device_ip(*ip))
                                                    .unwrap_or(sap_source_ip)
                                                    .to_string();
                                                let session_id = metadata.session_key;

                                                let now = std::time::Instant::now();
                                                if let Some((last_emit, hash, was_delete)) =
                                                    sap_last_emit.get(&session_id)
                                                {
                                                    if *hash == sap_message.message_id_hash
                                                        && *was_delete == sap_message.is_delete
                                                        && last_emit.elapsed()
                                                            < Duration::from_millis(500)
                                                    {
                                                        continue;
                                                    }
                                                } else if sap_last_emit.len()
                                                    >= MAX_DISCOVERY_ENTRIES
                                                {
                                                    continue;
                                                }
                                                sap_last_emit.insert(
                                                    session_id.clone(),
                                                    (
                                                        now,
                                                        sap_message.message_id_hash,
                                                        sap_message.is_delete,
                                                    ),
                                                );

                                                let mac =
                                                    eth.get_source().to_string().to_uppercase();
                                                let key = mac.clone();
                                                let mut manufacturer = metadata
                                                    .ptp_id
                                                    .as_deref()
                                                    .map(identify_manufacturer)
                                                    .unwrap_or(
                                                        manufacturer::Manufacturer::Unknown,
                                                    );
                                                if manufacturer
                                                    == manufacturer::Manufacturer::Unknown
                                                {
                                                    manufacturer = identify_manufacturer(&mac);
                                                }
                                                let fallback_name = format!(
                                                    "{} ({})",
                                                    manufacturer,
                                                    mac
                                                );
                                                let advertised_name =
                                                    if metadata.stream_name != "Unknown Stream" {
                                                        metadata.stream_name
                                                    } else if !metadata.session_info.is_empty() {
                                                        metadata.session_info
                                                    } else {
                                                        fallback_name
                                                    };

                                                let is_new = discovery_node
                                                    .lock()
                                                    .map(|table| !table.contains_key(&key))
                                                    .unwrap_or(false);
                                                let final_device_name = mdns_cache
                                                    .get(&origin_ip)
                                                    .cloned()
                                                    .unwrap_or(advertised_name);

                                                if global_mdns_timer.elapsed().as_secs() >= 1 {
                                                    global_mdns_counter = 0;
                                                    global_mdns_timer =
                                                        std::time::Instant::now();
                                                }
                                                if is_new
                                                    && !mdns_cache.contains_key(&origin_ip)
                                                    && global_mdns_counter < 5
                                                {
                                                    let can_send = mdns_cooldown
                                                        .get(&origin_ip)
                                                        .map(|last_sent| {
                                                            last_sent.elapsed().as_secs() > 30
                                                        })
                                                        .unwrap_or(true);
                                                    if can_send {
                                                        if mdns_cooldown.len() > 2_048 {
                                                            mdns_cooldown.clear();
                                                        }
                                                        send_mdns_query(
                                                            &origin_ip,
                                                            &mdns_sender,
                                                        );
                                                        mdns_cooldown.insert(
                                                            origin_ip.clone(),
                                                            std::time::Instant::now(),
                                                        );
                                                        global_mdns_counter += 1;
                                                    }
                                                }

                                                let (entry_to_emit, ptp_info) = {
                                                    let mut table = match discovery_node.lock() {
                                                        Ok(table) => table,
                                                        Err(_) => continue,
                                                    };
                                                    let can_insert =
                                                        table.len() < MAX_DISCOVERY_ENTRIES;
                                                    let entry_to_emit =
                                                        match table.entry(key.clone()) {
                                                            std::collections::hash_map::Entry::Vacant(
                                                                vacant,
                                                            ) if can_insert => {
                                                                    let entry = DeviceInfo {
                                                                        ip: origin_ip.clone(),
                                                                        name: final_device_name
                                                                            .clone(),
                                                                        last_seen:
                                                                            std::time::Instant::now(
                                                                            ),
                                                                    };
                                                                    vacant.insert(entry.clone());
                                                                    Some((key.clone(), entry))
                                                            }
                                                            std::collections::hash_map::Entry::Occupied(
                                                                mut occupied,
                                                            ) => {
                                                                let entry = occupied.get_mut();
                                                                entry.last_seen =
                                                                    std::time::Instant::now();
                                                                let changed = entry.ip
                                                                    != origin_ip
                                                                    || entry.name
                                                                        != final_device_name;
                                                                entry.ip = origin_ip.clone();
                                                                entry.name =
                                                                    final_device_name.clone();
                                                                changed.then(|| {
                                                                    (key.clone(), entry.clone())
                                                                })
                                                            }
                                                            _ => None,
                                                        };

                                                    let ptp_info = metadata
                                                        .ptp_id
                                                        .filter(|_| {
                                                            table.len()
                                                                < MAX_DISCOVERY_ENTRIES
                                                        })
                                                        .map(|ptp_id| {
                                                            let info = DeviceInfo {
                                                                ip: origin_ip.clone(),
                                                                name: final_device_name.clone(),
                                                                last_seen:
                                                                    std::time::Instant::now(),
                                                            };
                                                            table.insert(
                                                                ptp_id.clone(),
                                                                info.clone(),
                                                            );
                                                            (ptp_id, info)
                                                        });
                                                    (entry_to_emit, ptp_info)
                                                };

                                                if let Some((device_key, entry)) = entry_to_emit {
                                                    let _ = app_node.emit(
                                                        "discovery-update",
                                                        (device_key, entry),
                                                    );
                                                }
                                                if let Some((ptp_id, info)) = ptp_info {
                                                    let _ = app_node.emit(
                                                        "discovery-update",
                                                        (ptp_id, info),
                                                    );
                                                }

                                                let use_global = app_node
                                                    .state::<AppState>()
                                                    .device_timeout_modes
                                                    .lock()
                                                    .ok()
                                                    .and_then(|map| map.get(&origin_ip).copied())
                                                    .unwrap_or(false);
                                                let sap_timeout_ms = if use_global {
                                                    default_unknown_timeout_s * 1_000
                                                } else {
                                                    manufacturer.default_timeout_ms(
                                                        default_unknown_timeout_s,
                                                    )
                                                };

                                                let _ = app_node.emit(
                                                    "sdp-discovered",
                                                    SdpPayload {
                                                        source_ip: origin_ip,
                                                        network_source_ip: origin_ipv4.to_string(),
                                                        device_name: final_device_name,
                                                        sdp_content: sap_message.sdp,
                                                        session_id,
                                                        is_delete: sap_message.is_delete,
                                                        mac,
                                                        manufacturer: manufacturer.to_string(),
                                                        sap_timeout_ms,
                                                        interface_ip: target_ip.clone(),
                                                    },
                                                );
                                            }
                                            // --- 2. BRANCHE mDNS (5353) ---
                                            else if dest_port == 5353 || src_port == 5353 {
                                                if let Ok(dns_packet) = DnsPacket::parse(udp.payload()) {
                                                    let mut new_cache_entries: Vec<(String, String)> = Vec::new();

                                                    let mut process_record = |name: &str, data: &RData| {
                                                        if let RData::A(ip_record) = data {
                                                            let ip_str = ip_record.0.to_string();
                                                            let clean_name = name.replace(".local", "");
                                                            if !clean_name.is_empty() {
                                                                new_cache_entries.push((ip_str, clean_name));
                                                            }
                                                        } else if let RData::PTR(ptr_record) = data {
                                                            let clean_name = ptr_record.to_string().replace(".local", "");
                                                            let name_str = name.to_string();
                                                            if name_str.ends_with(".in-addr.arpa") {
                                                                let parts: Vec<&str> = name_str.split('.').collect();
                                                                if parts.len() >= 4 {
                                                                    let ip_str = format!("{}.{}.{}.{}", parts[3], parts[2], parts[1], parts[0]);
                                                                    new_cache_entries.push((ip_str, clean_name));
                                                                }
                                                            }
                                                        }
                                                    };

                                                    for answer in &dns_packet.answers { process_record(&answer.name.to_string(), &answer.data); }
                                                    for additional in &dns_packet.additional { process_record(&additional.name.to_string(), &additional.data); }
                                                    for authority in &dns_packet.nameservers { process_record(&authority.name.to_string(), &authority.data); }

                                                    if !new_cache_entries.is_empty() {
                                                        let mut updates = Vec::new();
                                                        if let Ok(mut table) =
                                                            discovery_node.lock()
                                                        {
                                                            for (ip_str, clean_name) in new_cache_entries {
                                                                if mdns_cache.len() >= 2_048 {
                                                                    mdns_cache.clear();
                                                                }
                                                                mdns_cache.insert(ip_str.clone(), clean_name.clone());
                                                                for (key, entry) in table.iter_mut() {
                                                                    if entry.ip == ip_str && entry.name != clean_name {
                                                                        entry.name = clean_name.clone();
                                                                        updates.push((key.clone(), entry.clone()));
                                                                    }
                                                                }
                                                            }
                                                        }
                                                        for (key, entry) in updates {
                                                            app_node.emit("discovery-update", (key, entry)).ok();
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    },
                    Err(pcap::Error::TimeoutExpired) => continue,
                    Err(error) => {
                        let _ = app_node.emit(
                            "sniffer-error",
                            format!("Erreur Npcap sur {target_name} : {error}"),
                        );
                        break;
                    }
                }
            }
        }));
    }

    // Spawn Global PTP Socket thread
    let stop_flag_ptp = Arc::clone(&stop_flag);
    let app_ptp = app.clone();
    let discovery_ptp = Arc::clone(&discovery_table_arc);
    let selected_ips: Vec<String> = selected_interfaces.iter().map(|i| i.ip.clone()).collect();
    let (ptp_ready_sender, ptp_ready_receiver) = mpsc::sync_channel::<Result<(), String>>(1);

    handles.push(thread::spawn(move || {
        let ptp_addr = Ipv4Addr::new(224, 0, 1, 129);
        let socket = match Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)) {
            Ok(socket) => socket,
            Err(error) => {
                let _ = ptp_ready_sender
                    .send(Err(format!("Création du socket PTP impossible : {error}")));
                return;
            }
        };
        let _ = socket.set_reuse_address(true);
        let _ = socket.set_multicast_loop_v4(false);
        let bind_address = SocketAddr::from(([0, 0, 0, 0], 320));
        if let Err(error) = socket.bind(&bind_address.into()) {
            let _ =
                ptp_ready_sender.send(Err(format!("Écoute PTP impossible sur UDP/320 : {error}")));
            return;
        }

        let interfaces = netdev::get_interfaces();
        let mut subnets = Vec::new();
        let mut joined_interfaces = 0usize;
        for ip_str in &selected_ips {
            if let Ok(interface_address) = ip_str.parse::<Ipv4Addr>() {
                if socket
                    .join_multicast_v4(&ptp_addr, &interface_address)
                    .is_ok()
                {
                    joined_interfaces += 1;
                }
            }
            for interface in &interfaces {
                for ipv4 in &interface.ipv4 {
                    if ipv4.addr.to_string() == *ip_str {
                        subnets.push((
                            ip_str.clone(),
                            u32::from_be_bytes(ipv4.addr.octets()),
                            u32::from_be_bytes(ipv4.netmask.octets()),
                        ));
                    }
                }
            }
        }
        if joined_interfaces == 0 {
            let _ = ptp_ready_sender.send(Err(
                "Aucune adhésion multicast PTP n'a pu être créée.".to_string()
            ));
            return;
        }

        let udp_socket: std::net::UdpSocket = socket.into();
        if let Err(error) = udp_socket.set_read_timeout(Some(Duration::from_millis(500))) {
            let _ =
                ptp_ready_sender.send(Err(format!("Timeout du socket PTP impossible : {error}")));
            return;
        }
        let _ = ptp_ready_sender.send(Ok(()));

        let mut buffer = [0u8; 1_024];
        while !stop_flag_ptp.load(Ordering::Acquire) {
            match udp_socket.recv_from(&mut buffer) {
                Ok((size, source)) => {
                    let payload = &buffer[..size];
                    if payload.len() >= 44 && payload[0] & 0x0F == 0x0B {
                        let domain = payload[4];
                        let ptp_id = payload[20..28]
                            .iter()
                            .map(|byte| format!("{byte:02X}"))
                            .collect::<Vec<_>>()
                            .join("-");
                        let source_ip = source.ip().to_string();
                        let mut matched_interface =
                            selected_ips.first().cloned().unwrap_or_default();
                        if let IpAddr::V4(source_v4) = source.ip() {
                            let source_u32 = u32::from_be_bytes(source_v4.octets());
                            for (interface_ip, ip, mask) in &subnets {
                                if (source_u32 & *mask) == (*ip & *mask) {
                                    matched_interface = interface_ip.clone();
                                    break;
                                }
                            }
                        }
                        let (name, final_ip) = discovery_ptp
                            .lock()
                            .ok()
                            .and_then(|table| {
                                table
                                    .get(&ptp_id)
                                    .or_else(|| table.values().find(|info| info.ip == source_ip))
                                    .map(|info| (info.name.clone(), info.ip.clone()))
                            })
                            .unwrap_or_else(|| ("---".to_string(), source_ip));
                        let _ = app_ptp.emit(
                            "ptp-clock-update",
                            PtpPayload {
                                ptp_id,
                                name,
                                ip: final_ip,
                                interface_ip: matched_interface,
                                domain,
                            },
                        );
                    }
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) => {}
                Err(error) => {
                    eprintln!("Erreur de réception PTP : {error}");
                    break;
                }
            }
        }
    }));

    let mut started_interfaces = Vec::new();
    let mut failed_interfaces = Vec::new();
    for (interface, receiver) in readiness_receivers {
        match receiver.recv_timeout(Duration::from_secs(3)) {
            Ok(Ok(())) => started_interfaces.push(interface),
            Ok(Err(error)) => failed_interfaces.push(error),
            Err(_) => {
                failed_interfaces.push(format!("Délai dépassé pendant l'ouverture de {interface}."))
            }
        }
    }
    let ptp_active = matches!(
        ptp_ready_receiver.recv_timeout(Duration::from_secs(3)),
        Ok(Ok(()))
    );

    if started_interfaces.is_empty() {
        stop_flag.store(true, Ordering::Release);
        for handle in handles {
            let _ = handle.join();
        }
        return Err(if failed_interfaces.is_empty() {
            "Aucune interface Npcap n'a pu être ouverte.".to_string()
        } else {
            failed_interfaces.join("\n")
        });
    }

    match state.sniffer_session.lock() {
        Ok(mut session_lock) => {
            *session_lock = Some(SnifferSession { stop_flag, handles });
        }
        Err(_) => {
            stop_flag.store(true, Ordering::Release);
            for handle in handles {
                let _ = handle.join();
            }
            return Err("État de capture indisponible.".to_string());
        }
    }

    Ok(StartSniffingReport {
        started_interfaces,
        failed_interfaces,
        sap_groups: SAP_GROUPS.iter().map(ToString::to_string).collect(),
        ptp_active,
    })
}

#[tauri::command]
fn stop_sniffing(state: State<'_, AppState>) -> Result<(), String> {
    let _control_guard = state
        .sniffer_control
        .lock()
        .map_err(|_| "Contrôle de capture indisponible.".to_string())?;
    stop_active_session(&state)
}

#[tauri::command]
fn get_arp_table(state: State<'_, AppState>) -> HashMap<String, DeviceInfo> {
    let mut table = state
        .discovery_table
        .lock()
        .map(|table| table.clone())
        .unwrap_or_default();
    let mut cmd = std::process::Command::new("arp");
    cmd.arg("-a");
    #[cfg(windows)]
    cmd.creation_flags(0x08000000);
    if let Ok(out) = cmd.output() {
        let stdout = String::from_utf8_lossy(&out.stdout);
        for line in stdout.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                let ip = parts[0];
                let mac = parts[1].replace("-", ":").to_uppercase();
                if mac.split(':').count() == 6 {
                    table.entry(mac).or_insert(DeviceInfo {
                        ip: ip.to_string(),
                        name: "---".to_string(),
                        last_seen: std::time::Instant::now(),
                    });
                }
            }
        }
    }
    table
}

#[tauri::command]
fn set_unknown_timeout(seconds: u64, state: State<'_, AppState>) -> Result<(), String> {
    let clamped = seconds.clamp(60, 300);
    let mut lock = state
        .default_unknown_timeout_s
        .lock()
        .map_err(|_| "Configuration du timeout indisponible.".to_string())?;
    *lock = clamped;
    Ok(())
}

#[tauri::command]
fn set_network_ip(
    interface_name: String,
    is_dhcp: bool,
    ip: Option<String>,
    mask: Option<String>,
) -> Result<String, String> {
    if interface_name.is_empty() || interface_name.len() > 256 {
        return Err("Nom d'interface invalide.".to_string());
    }
    if !get_network_interfaces()
        .iter()
        .any(|interface| interface.name == interface_name)
    {
        return Err("Interface réseau inconnue.".to_string());
    }

    let mut cmd = std::process::Command::new("netsh");
    #[cfg(windows)]
    cmd.creation_flags(0x08000000);
    let mut args = vec!["interface", "ip", "set", "address", interface_name.as_str()];
    if is_dhcp {
        args.push("dhcp");
    } else if let (Some(ip_addr), Some(mask_addr)) = (ip.as_deref(), mask.as_deref()) {
        let parsed_ip = ip_addr
            .parse::<Ipv4Addr>()
            .map_err(|_| "Adresse IPv4 invalide.".to_string())?;
        let parsed_mask = mask_addr
            .parse::<Ipv4Addr>()
            .map_err(|_| "Masque IPv4 invalide.".to_string())?;
        if parsed_ip.is_unspecified()
            || parsed_ip.is_broadcast()
            || parsed_ip.is_multicast()
            || !is_contiguous_netmask(parsed_mask)
        {
            return Err("Adresse IPv4 ou masque non utilisable.".to_string());
        }
        args.push("static");
        args.push(ip_addr);
        args.push(mask_addr);
    } else {
        return Err("IP and Mask are required".to_string());
    }
    cmd.args(args);
    match cmd.output() {
        Ok(out) => {
            if out.status.success() {
                Ok("OK".to_string())
            } else {
                Err(String::from_utf8_lossy(&out.stderr).to_string())
            }
        }
        Err(e) => Err(e.to_string()),
    }
}

#[tauri::command]
fn set_window_constraints(
    window: tauri::Window,
    collapsed: bool,
    zoom_level: f64,
) -> Result<(), String> {
    if !zoom_level.is_finite() {
        return Err("Niveau de zoom invalide.".to_string());
    }
    let zoom_level = zoom_level.clamp(1.0, 1.3);
    let base_min_width = if collapsed { 609.0 } else { 800.0 };
    let min_width = base_min_width * zoom_level;
    let min_height = 600.0 * zoom_level;
    window
        .set_min_size(Some(tauri::LogicalSize::new(min_width, min_height)))
        .map_err(|error| format!("Contraintes de fenêtre impossibles : {error}"))
}

#[tauri::command]
fn set_device_timeout_mode(
    ip: String,
    use_default: bool,
    state: State<'_, AppState>,
) -> Result<(), String> {
    ip.parse::<Ipv4Addr>()
        .map_err(|_| "Adresse IPv4 invalide.".to_string())?;
    let mut map = state
        .device_timeout_modes
        .lock()
        .map_err(|_| "Configuration des timeouts indisponible.".to_string())?;
    if map.len() >= MAX_DISCOVERY_ENTRIES && !map.contains_key(&ip) {
        return Err("Trop de configurations d'équipements.".to_string());
    }
    map.insert(ip, use_default);
    Ok(())
}

pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_fs::init())
        .plugin(tauri_plugin_opener::init())
        .manage(AppState {
            sniffer_control: Mutex::new(()),
            sniffer_session: Mutex::new(None),
            default_unknown_timeout_s: Mutex::new(60),
            discovery_table: Arc::new(Mutex::new(HashMap::new())),
            device_timeout_modes: Arc::new(Mutex::new(HashMap::new())),
        })
        .invoke_handler(tauri::generate_handler![
            get_network_interfaces,
            get_arp_table,
            start_sniffing,
            stop_sniffing,
            set_network_ip,
            set_unknown_timeout,
            set_window_constraints,
            set_device_timeout_mode
        ])
        .setup(|app| {
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.set_theme(Some(tauri::Theme::Dark));
                let _ = window.set_min_size(Some(tauri::LogicalSize::new(800.0, 600.0)));
            }
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

fn is_allowed_device_ip(ip: Ipv4Addr) -> bool {
    ip.is_private() || ip.is_link_local()
}

fn is_contiguous_netmask(mask: Ipv4Addr) -> bool {
    let mask = u32::from(mask);
    mask != 0 && (!mask).wrapping_add(1).is_power_of_two()
}

fn parse_lldp(packet: &[u8]) -> Option<(String, String, String)> {
    let mut pos = 0;
    let mut chassis_id = String::new();
    let mut system_name = String::new();
    let mut mgmt_ip = String::new();
    while pos + 2 <= packet.len() {
        let header = u16::from_be_bytes([packet[pos], packet[pos + 1]]);
        let tlv_type = (header >> 9) as u8;
        let tlv_len = (header & 0x01FF) as usize;
        pos += 2;
        if tlv_len == 0 || pos + tlv_len > packet.len() {
            break;
        } // Empêche les boucles infinies sur TLV=0
        let value = &packet[pos..pos + tlv_len];
        match tlv_type {
            1 => {
                if tlv_len >= 7 && value[0] == 4 {
                    chassis_id = value[1..7]
                        .iter()
                        .map(|b| format!("{:02X}", b))
                        .collect::<Vec<_>>()
                        .join(":");
                }
            }
            5 => system_name = String::from_utf8_lossy(value).to_string(),
            8 => {
                if tlv_len >= 6 && value[0] >= 5 && value[1] == 1 {
                    mgmt_ip = value[2..6]
                        .iter()
                        .map(|byte| byte.to_string())
                        .collect::<Vec<_>>()
                        .join(".");
                }
            }
            0 => break,
            _ => {}
        }
        pos += tlv_len;
    }
    if !chassis_id.is_empty() {
        Some((chassis_id, system_name, mgmt_ip))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_contiguous_netmasks() {
        assert!(is_contiguous_netmask(Ipv4Addr::new(255, 255, 255, 0)));
        assert!(is_contiguous_netmask(Ipv4Addr::new(255, 255, 255, 255)));
        assert!(!is_contiguous_netmask(Ipv4Addr::new(255, 0, 255, 0)));
        assert!(!is_contiguous_netmask(Ipv4Addr::UNSPECIFIED));
    }

    #[test]
    fn malformed_lldp_management_address_does_not_panic() {
        let mut packet = vec![0x02, 0x07, 0x04, 0, 1, 2, 3, 4, 5];
        packet.extend_from_slice(&[0x10, 0x05, 0x05, 0x01, 192, 168, 1]);
        packet.extend_from_slice(&[0x00, 0x00]);

        let parsed = parse_lldp(&packet).expect("chassis ID remains valid");
        assert_eq!(parsed.0, "00:01:02:03:04:05");
        assert!(parsed.2.is_empty());
    }
}
