"""PCAP file processing module."""

import socket
from scapy.all import rdpcap, IP, IPv6, TCP, UDP, ARP, Ether
from scapy.layers.l2 import CookedLinux, CookedLinuxV2
from backend.utils.helpers import get_protocol_name, parse_ipv6
from backend.processing.threat_detection import detect_threats
from backend.utils.ip_filters import should_filter_ip


def process_pcap(filepath, no_dns=False, ipv4_only=False, private_only=False):
    """Reads and processes a PCAP file."""
    try:
        packets = rdpcap(filepath)
    except Exception as e:
        return {'error': f"Scapy could not read the file. It might be corrupted or in an unsupported format. Details: {e}"}

    hosts = {}
    connections = {}
    protocols = {}
    alerts = []
    packet_data = []  # Store packet information for frontend
    total_bytes = 0
    recent_icmp = [] # For flood detection: (timestamp, src_ip)
    ip_to_mac = {}  # Track IP to MAC address mapping

    for pkt in packets:
        total_bytes += len(pkt)

        # Extract MAC addresses from Ethernet or Linux Cooked Capture layer
        src_mac = None
        dst_mac = None
        if pkt.haslayer(Ether):
            src_mac = pkt[Ether].src
            dst_mac = pkt[Ether].dst
        elif pkt.haslayer(CookedLinux):
            src_mac = pkt[CookedLinux].src
        elif pkt.haslayer(CookedLinuxV2):
            # CookedLinuxV2 stores MAC as raw bytes, convert to string format
            if hasattr(pkt[CookedLinuxV2], 'src') and pkt[CookedLinuxV2].src:
                mac_bytes = pkt[CookedLinuxV2].src
                # Convert bytes to MAC address string (first 6 bytes)
                if len(mac_bytes) >= 6:
                    src_mac = ':'.join(f'{b:02x}' for b in mac_bytes[:6])

        # Get protocol first
        proto = get_protocol_name(pkt)

        # Handle ARP packets (no IP layer)
        if pkt.haslayer(ARP):
            src_ip = pkt[ARP].psrc
            dst_ip = pkt[ARP].pdst
            src_port = 0
            dst_port = 0
            # ARP packets have MAC addresses - get from ARP layer if not already found
            if not src_mac and hasattr(pkt[ARP], 'hwsrc'):
                src_mac = pkt[ARP].hwsrc
            if not dst_mac and hasattr(pkt[ARP], 'hwdst'):
                dst_mac = pkt[ARP].hwdst
            # Store MAC to IP mapping
            if src_mac and src_ip and src_ip != '0.0.0.0':
                ip_to_mac[src_ip] = src_mac
            if dst_mac and dst_ip and dst_ip != '0.0.0.0':
                ip_to_mac[dst_ip] = dst_mac
        # Handle IP traffic
        elif pkt.haslayer(IP) or pkt.haslayer(IPv6):
            src_ip, dst_ip = (pkt[IP].src, pkt[IP].dst) if pkt.haslayer(IP) else parse_ipv6(pkt)
            src_port = pkt.sport if pkt.haslayer(TCP) or pkt.haslayer(UDP) else 0
            dst_port = pkt.dport if pkt.haslayer(TCP) or pkt.haslayer(UDP) else 0
            # Track MAC to IP mapping
            if src_mac and src_ip:
                ip_to_mac[src_ip] = src_mac
            if dst_mac and dst_ip:
                ip_to_mac[dst_ip] = dst_mac
        else:
            # Skip packets without IP or ARP
            continue

        pkt_time = float(pkt.time)

        # Update protocol count
        protocols[proto] = protocols.get(proto, 0) + 1

        # Initialize hosts if not seen
        for ip in [src_ip, dst_ip]:
            if ip not in hosts:
                hosts[ip] = {'ip': ip, 'packetsSent': 0, 'packetsReceived': 0, 'bytesSent': 0, 'bytesReceived': 0, 'protocols': set(), 'connections': set()}

        # Update host stats
        hosts[src_ip]['packetsSent'] += 1
        hosts[src_ip]['bytesSent'] += len(pkt)
        hosts[src_ip]['protocols'].add(proto)
        hosts[src_ip]['connections'].add(dst_ip)

        hosts[dst_ip]['packetsReceived'] += 1
        hosts[dst_ip]['bytesReceived'] += len(pkt)
        hosts[dst_ip]['protocols'].add(proto)
        hosts[dst_ip]['connections'].add(src_ip)

        # Update connection stats
        conn_key_fwd = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{proto}"
        conn_key_rev = f"{dst_ip}:{dst_port}-{src_ip}:{src_port}-{proto}"
        conn_key = conn_key_fwd if conn_key_fwd in connections else conn_key_rev

        if conn_key not in connections:
            connections[conn_key] = {
                'source': src_ip,
                'destination': dst_ip,
                'protocol': proto,
                'packets': 0,
                'bytes': 0,
                'startTime': pkt_time,
                'lastTime': pkt_time
            }

        connections[conn_key]['packets'] += 1
        connections[conn_key]['bytes'] += len(pkt)
        connections[conn_key]['lastTime'] = pkt_time

        # Run threat detection
        detect_threats(pkt, alerts, recent_icmp)

        # Store packet data for frontend
        packet_info = {
            'timestamp': pkt_time,
            'source': src_ip,
            'destination': dst_ip,
            'protocol': proto,
            'length': len(pkt),
            'srcPort': src_port,
            'dstPort': dst_port,
            'data': list(bytes(pkt))  # Store raw packet bytes as list for JSON
        }

        # Add TCP flags if present
        if pkt.haslayer(TCP):
            packet_info['flags'] = int(pkt[TCP].flags)

        packet_data.append(packet_info)

    # --- Final Data Assembly ---
    # Convert sets to lists for JSON serialization and add MAC addresses
    for ip in hosts:
        hosts[ip]['protocols'] = list(hosts[ip]['protocols'])
        hosts[ip]['connections'] = list(hosts[ip]['connections'])
        # Add MAC address if we have it
        if ip in ip_to_mac:
            hosts[ip]['mac'] = ip_to_mac[ip]

        # Perform DNS resolution if not disabled
        if not no_dns:
            try:
                socket.setdefaulttimeout(2)  # 2 second timeout
                hostname = socket.gethostbyaddr(ip)[0]
                hosts[ip]['hostname'] = hostname
                print(f"[DNS] Resolved {ip} -> {hostname}")
            except (socket.herror, socket.timeout, socket.gaierror):
                # Resolution failed, don't add hostname
                pass
            except Exception as e:
                print(f"[DNS] Error resolving {ip}: {e}")

    start_time = float(packets[0].time) if packets else 0
    end_time = float(packets[-1].time) if packets else 0
    duration = max(1, end_time - start_time)

    summary = {
        'totalPackets': len(packets),
        'uniqueHosts': len(hosts),
        'activeConnections': len(connections),
        'dataVolumeMB': round(total_bytes / 1048576, 2),
        'avgPacketSize': round(total_bytes / len(packets)) if packets else 0,
        'protocolCount': len(protocols),
        'duration': round(duration, 2),
        'packetsPerSec': round(len(packets) / duration),
        'bandwidthMbps': round((total_bytes * 8 / duration) / 1000000, 2),
        'threatsFound': len(alerts)
    }

    # Apply IP filtering if requested
    if ipv4_only or private_only:
        # Filter hosts
        filtered_hosts = [h for h in hosts.values() if not should_filter_ip(h['ip'], ipv4_only, private_only)]
        filtered_ips = set(h['ip'] for h in filtered_hosts)

        # Filter connections (only keep if both endpoints are in filtered hosts)
        filtered_connections = [
            c for c in connections.values()
            if c['source'] in filtered_ips and c['destination'] in filtered_ips
        ]

        # Filter packets (only keep if both endpoints are in filtered hosts)
        filtered_packets = [
            p for p in packet_data
            if p['source'] in filtered_ips and p['destination'] in filtered_ips
        ]

        # Filter alerts
        filtered_alerts = [
            a for a in alerts
            if a['source'] in filtered_ips and a['destination'] in filtered_ips
        ]

        print(f"[IP Filter] Original: {len(hosts)} hosts, {len(connections)} connections, {len(packet_data)} packets")
        print(f"[IP Filter] Filtered: {len(filtered_hosts)} hosts, {len(filtered_connections)} connections, {len(filtered_packets)} packets")
    else:
        filtered_hosts = list(hosts.values())
        filtered_connections = list(connections.values())
        filtered_packets = packet_data
        filtered_alerts = alerts

    return {
        'summary': summary,
        'hosts': filtered_hosts,
        'connections': filtered_connections,
        'packets': filtered_packets,
        'alerts': sorted(filtered_alerts, key=lambda x: x['timestamp'])
    }
