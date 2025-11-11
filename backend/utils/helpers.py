"""Helper functions for PCAP analysis."""

from scapy.all import IPv6, ARP, DNS, BOOTP, TCP, UDP, ICMP, Raw


def parse_ipv6(pkt):
    """Formats an IPv6 address from a packet."""
    return pkt[IPv6].src, pkt[IPv6].dst


def get_protocol_name(pkt):
    """Gets the application/transport layer protocol name."""
    # Check for ARP first (doesn't use IP)
    if pkt.haslayer(ARP):
        return 'ARP'

    # Check for application layer protocols
    if pkt.haslayer(DNS):
        return 'DNS'
    if pkt.haslayer(BOOTP):
        return 'BOOTP'

    # Check for common protocols (port-based detection)
    if pkt.haslayer(TCP):
        sport = pkt[TCP].sport
        dport = pkt[TCP].dport

        # Web protocols
        if dport == 80 or sport == 80:
            return 'HTTP'
        elif dport == 443 or sport == 443:
            return 'HTTPS'
        elif dport == 8080 or sport == 8080:
            return 'HTTP-ALT'
        elif dport == 8443 or sport == 8443:
            return 'HTTPS-ALT'

        # Remote access
        elif dport == 22 or sport == 22:
            return 'SSH'
        elif dport == 23 or sport == 23:
            return 'TELNET'
        elif dport == 3389 or sport == 3389:
            return 'RDP'
        elif dport == 5900 or sport == 5900 or (5900 <= dport <= 5910) or (5900 <= sport <= 5910):
            return 'VNC'

        # File transfer
        elif dport == 21 or sport == 21:
            return 'FTP'
        elif dport == 20 or sport == 20:
            return 'FTP-DATA'
        elif dport == 69 or sport == 69:
            return 'TFTP'
        elif dport == 445 or sport == 445:
            return 'SMB'
        elif dport == 139 or sport == 139:
            return 'NetBIOS'

        # Email
        elif dport == 25 or sport == 25:
            return 'SMTP'
        elif dport == 587 or sport == 587:
            return 'SMTP-SUBMISSION'
        elif dport == 110 or sport == 110:
            return 'POP3'
        elif dport == 143 or sport == 143:
            return 'IMAP'
        elif dport == 993 or sport == 993:
            return 'IMAPS'
        elif dport == 995 or sport == 995:
            return 'POP3S'

        # Database
        elif dport == 3306 or sport == 3306:
            return 'MySQL'
        elif dport == 5432 or sport == 5432:
            return 'PostgreSQL'
        elif dport == 1433 or sport == 1433:
            return 'MSSQL'
        elif dport == 27017 or sport == 27017:
            return 'MongoDB'
        elif dport == 6379 or sport == 6379:
            return 'Redis'

        # Other common services
        elif dport == 3128 or sport == 3128:
            return 'SQUID'
        elif dport == 8888 or sport == 8888:
            return 'HTTP-PROXY'
        elif dport == 9000 or sport == 9000 or dport == 9001 or sport == 9001:
            return 'HTTP-DEV'

        # Check for HTTP in payload
        if pkt.haslayer(Raw):
            payload = bytes(pkt[Raw].load)
            if payload[:4] in [b'GET ', b'POST', b'HTTP', b'HEAD', b'PUT ', b'DELE']:
                return 'HTTP'
        return 'TCP'

    if pkt.haslayer(UDP):
        sport = pkt[UDP].sport
        dport = pkt[UDP].dport

        # Common UDP protocols
        if dport == 53 or sport == 53:
            return 'DNS'
        elif dport == 67 or sport == 67 or dport == 68 or sport == 68:
            return 'DHCP'
        elif dport == 69 or sport == 69:
            return 'TFTP'
        elif dport == 123 or sport == 123:
            return 'NTP'
        elif dport == 161 or sport == 161 or dport == 162 or sport == 162:
            return 'SNMP'
        elif dport == 514 or sport == 514:
            return 'SYSLOG'
        elif dport == 1900 or sport == 1900:
            return 'SSDP'
        elif dport == 5353 or sport == 5353:
            return 'mDNS'

        return 'UDP'
    if pkt.haslayer(ICMP):
        return 'ICMP'
    if pkt.haslayer(IPv6):
        if pkt.nh == 6: return 'TCP/IPv6'
        if pkt.nh == 17: return 'UDP/IPv6'
        return 'IPv6'
    return 'Other'
