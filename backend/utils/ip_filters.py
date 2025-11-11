"""IP address filtering utilities."""

def is_ipv4(ip):
    """Check if IP address is IPv4."""
    return '.' in ip and ':' not in ip

def is_ipv6(ip):
    """Check if IP address is IPv6."""
    return ':' in ip

def is_private_ip(ip):
    """Check if IP address is private/LAN address."""
    if is_ipv4(ip):
        # Private IPv4 ranges:
        # 10.0.0.0/8
        # 172.16.0.0/12
        # 192.168.0.0/16
        # 127.0.0.0/8 (loopback)
        try:
            parts = [int(p) for p in ip.split('.')]
            if len(parts) != 4:
                return False

            if parts[0] == 10:
                return True
            if parts[0] == 172 and 16 <= parts[1] <= 31:
                return True
            if parts[0] == 192 and parts[1] == 168:
                return True
            if parts[0] == 127:
                return True
            return False
        except (ValueError, IndexError):
            return False

    elif is_ipv6(ip):
        # Private IPv6 ranges:
        # fc00::/7 (Unique Local Addresses)
        # fe80::/10 (Link-local)
        # ::1 (loopback)
        lower = ip.lower()
        if lower.startswith('fc') or lower.startswith('fd'):
            return True
        if lower.startswith('fe80:'):
            return True
        if lower == '::1':
            return True
        return False

    return False

def should_filter_ip(ip, ipv4_only=False, private_only=False):
    """
    Check if an IP address should be filtered out based on settings.
    Returns True if IP should be HIDDEN/FILTERED.
    """
    if ipv4_only and is_ipv6(ip):
        return True  # Hide IPv6 addresses

    if private_only and not is_private_ip(ip):
        return True  # Hide public addresses

    return False  # Don't filter
