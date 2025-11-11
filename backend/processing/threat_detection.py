"""Threat detection module for network traffic analysis."""

from scapy.all import IP, IPv6, TCP, UDP, ICMP
from backend.utils.helpers import get_protocol_name


def detect_threats(pkt, alerts, recent_packets):
    """Detects suspicious activity in a packet."""
    src_ip = pkt[IP].src if pkt.haslayer(IP) else pkt.getlayer(IPv6).src if pkt.haslayer(IPv6) else "N/A"
    dst_ip = pkt[IP].dst if pkt.haslayer(IP) else pkt.getlayer(IPv6).dst if pkt.haslayer(IPv6) else "N/A"

    # 1. Port Scanning Detection (SYN flag without ACK)
    if pkt.haslayer(TCP) and pkt[TCP].flags == 'S':
        suspicious_ports = [21, 22, 23, 25, 80, 139, 443, 445, 3389, 5900]
        if pkt[TCP].dport in suspicious_ports:
            alerts.append({
                'type': 'Potential Port Scan',
                'severity': 'high',
                'source': src_ip,
                'destination': dst_ip,
                'port': pkt[TCP].dport,
                'protocol': 'TCP',
                'timestamp': float(pkt.time),
                'details': f"SYN packet to common port {pkt[TCP].dport}"
            })

    # 2. Large Data Transfer
    if len(pkt) > 15000: # Increased threshold for backend
        alerts.append({
            'type': 'Large Data Transfer',
            'severity': 'medium',
            'source': src_ip,
            'destination': dst_ip,
            'size': len(pkt),
            'protocol': get_protocol_name(pkt),
            'timestamp': float(pkt.time),
            'details': f"Unusually large packet: {len(pkt)} bytes"
        })

    # 3. Suspicious Ports (Known malware/trojan ports)
    if pkt.haslayer(TCP) or pkt.haslayer(UDP):
        suspicious_ports = [4444, 5555, 6666, 7777, 8888, 9999, 31337]
        if pkt.dport in suspicious_ports:
            alerts.append({
                'type': 'Suspicious Port Activity',
                'severity': 'high',
                'source': src_ip,
                'destination': dst_ip,
                'port': pkt.dport,
                'protocol': get_protocol_name(pkt),
                'timestamp': float(pkt.time),
                'details': f"Connection to known malware port {pkt.dport}"
            })

    # 4. ICMP Flood Detection
    if pkt.haslayer(ICMP):
        icmp_count = 0
        for p_time, p_src in recent_packets:
            if p_src == src_ip and (float(pkt.time) - p_time) < 1.0:
                icmp_count += 1

        if icmp_count > 20: # If more than 20 ICMP packets from same source in 1 sec
             # Avoid adding duplicate alerts for the same flood
            if not any(a['type'] == 'ICMP Flood' and a['source'] == src_ip for a in alerts[-5:]):
                alerts.append({
                    'type': 'ICMP Flood',
                    'severity': 'high',
                    'source': src_ip,
                    'destination': dst_ip,
                    'protocol': 'ICMP',
                    'timestamp': float(pkt.time),
                    'details': f"Potential ICMP flood attack detected ({icmp_count+1}/sec)"
                })
        recent_packets.append((float(pkt.time), src_ip))
