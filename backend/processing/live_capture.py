"""Live packet capture from network interfaces using scapy."""

import threading
import time
import socket
from scapy.all import sniff, conf, wrpcap
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, Ether, CookedLinux, CookedLinuxV2
from scapy.layers.dns import DNS
from backend.utils.helpers import get_protocol_name
from backend.utils.ip_filters import should_filter_ip


class LiveCapture:
    """Handles live packet capture from network interfaces."""

    def __init__(self, interface, socketio, upload_folder, no_dns=False, ipv4_only=False, private_only=False):
        self.interface = interface
        self.socketio = socketio
        self.upload_folder = upload_folder
        self.no_dns = no_dns  # Flag to disable DNS resolution
        self.ipv4_only = ipv4_only  # Flag to show only IPv4
        self.private_only = private_only  # Flag to show only private IPs
        self.running = False
        self.thread = None
        self.packet_count = 0
        self.packet_buffer = []
        self.all_packets = []  # Store all captured packets for PCAP export
        self.batch_interval = 2  # Send batches every 2 seconds
        self.last_batch_time = time.time()
        self.total_bytes = 0  # Track total bytes processed
        self.start_time = None  # Track capture start time
        self.first_packet_time = None  # Track first packet timestamp
        self.last_packet_time = None  # Track last packet timestamp

        # Backend aggregation for nodes and edges
        self.nodes = {}  # IP -> node data
        self.edges = {}  # (src, dst) -> edge data
        self.max_packets_per_batch = 500  # Limit packets sent per batch (increased from 100)
        self.max_buffer_size = 5000  # Maximum buffer size before dropping packets (increased from 1000)

        # Packet loss tracking
        self.packets_dropped = 0

        # MAC address tracking
        self.ip_to_mac = {}  # IP -> MAC address mapping

        # DNS resolution cache
        self.dns_cache = {}  # IP -> hostname
        self.dns_lookup_queue = []  # IPs to resolve
        self.dns_thread = None

    def start(self):
        """Start capturing packets."""
        if self.running:
            return

        self.running = True
        self.packet_buffer = []
        self.all_packets = []
        self.nodes = {}
        self.edges = {}
        self.ip_to_mac = {}
        self.dns_cache = {}
        self.dns_lookup_queue = []
        self.last_batch_time = time.time()
        self.total_bytes = 0
        self.start_time = time.time()
        self.first_packet_time = None
        self.last_packet_time = None
        self.packets_dropped = 0
        self.thread = threading.Thread(target=self._capture_loop, daemon=True)
        self.thread.start()

        # Start batch sender thread
        self.batch_thread = threading.Thread(target=self._batch_sender, daemon=True)
        self.batch_thread.start()

        # Start DNS resolver thread only if DNS is enabled
        if not self.no_dns:
            self.dns_thread = threading.Thread(target=self._dns_resolver, daemon=True)
            self.dns_thread.start()

    def stop(self):
        """Stop capturing packets."""
        self.running = False
        if self.thread:
            self.thread.join(timeout=2)

        # Save all captured packets to PCAP file
        self._save_pcap()

    def _capture_loop(self):
        """Main capture loop running in separate thread."""
        try:
            # Use scapy's sniff with a callback for each packet
            # Enable promiscuous mode to capture all traffic on the network
            sniff(
                iface=self.interface,
                prn=self._process_packet,
                store=False,
                promisc=True,  # Enable promiscuous mode
                stop_filter=lambda x: not self.running
            )
        except Exception as e:
            self.socketio.emit('capture_error', {'error': str(e)})

    def _batch_sender(self):
        """Send aggregated data in batches every few seconds."""
        while self.running:
            time.sleep(self.batch_interval)

            if len(self.packet_buffer) > 0:
                # Limit packets sent to frontend
                packets_to_send = self.packet_buffer[:self.max_packets_per_batch]

                # Convert nodes to serializable format (sets to lists) and add hostnames/MAC
                nodes_serializable = []
                for node in self.nodes.values():
                    node_copy = node.copy()
                    node_copy['protocols'] = list(node['protocols'])
                    # Add hostname if available
                    node_copy['hostname'] = self.dns_cache.get(node['ip'], None)
                    # Add MAC address if available
                    node_copy['mac'] = self.ip_to_mac.get(node['ip'], None)
                    nodes_serializable.append(node_copy)

                # Debug: Log MAC address count
                macs_found = sum(1 for n in nodes_serializable if n.get('mac'))
                print(f"[LiveCapture] Sending {len(nodes_serializable)} nodes, {macs_found} with MAC addresses")

                # Calculate complete statistics
                unique_hosts = len(self.nodes)
                active_connections = len(self.edges)

                # Calculate data volume in MB
                data_volume_mb = round(self.total_bytes / 1048576, 2)

                # Calculate average packet size
                avg_packet_size = round(self.total_bytes / self.packet_count) if self.packet_count > 0 else 0

                # Count unique protocols
                all_protocols = set()
                for node in self.nodes.values():
                    all_protocols.update(node['protocols'])
                protocol_count = len(all_protocols)

                # Calculate packets per second and bandwidth
                if self.first_packet_time and self.last_packet_time:
                    duration = max(self.last_packet_time - self.first_packet_time, 0.001)  # Avoid division by zero
                    packets_per_sec = round(self.packet_count / duration)
                    bandwidth_mbps = round((self.total_bytes * 8 / duration) / 1000000, 2)
                else:
                    packets_per_sec = 0
                    bandwidth_mbps = 0.0

                # Send aggregated data to frontend
                batch_data = {
                    'packets': packets_to_send,
                    'count': len(packets_to_send),
                    'nodes': nodes_serializable,
                    'edges': list(self.edges.values()),
                    'totalCaptured': self.packet_count,
                    'dnsCache': self.dns_cache,  # Send DNS cache for packet display
                    'statistics': {
                        'uniqueHosts': unique_hosts,
                        'activeConnections': active_connections,
                        'totalPackets': self.packet_count,
                        'totalNodes': unique_hosts,
                        'totalEdges': active_connections,
                        'dataVolumeMB': data_volume_mb,
                        'avgPacketSize': avg_packet_size,
                        'protocolCount': protocol_count,
                        'packetsPerSec': packets_per_sec,
                        'bandwidthMbps': bandwidth_mbps,
                        'packetsDropped': self.packets_dropped,
                        'bufferSize': len(self.packet_buffer),
                        'threatsFound': 0  # Threats are tracked on frontend
                    }
                }
                print(f"[LiveCapture] Sending batch: {len(packets_to_send)} packets, {unique_hosts} unique hosts, {active_connections} active connections, {self.packet_count} total packets")
                self.socketio.emit('packet_batch', batch_data)

                # Keep only unprocessed packets in buffer
                self.packet_buffer = self.packet_buffer[self.max_packets_per_batch:]
            else:
                print(f"[LiveCapture] No packets in buffer (total captured: {self.packet_count})")

    def _dns_resolver(self):
        """Background DNS resolution thread."""
        while self.running:
            time.sleep(1)  # Check queue every second

            # Process up to 5 DNS lookups per iteration to avoid blocking
            for _ in range(min(5, len(self.dns_lookup_queue))):
                if not self.dns_lookup_queue:
                    break

                ip = self.dns_lookup_queue.pop(0)

                # Skip if already resolved
                if ip in self.dns_cache:
                    continue

                # Attempt reverse DNS lookup with timeout
                try:
                    socket.setdefaulttimeout(2)  # 2 second timeout
                    hostname = socket.gethostbyaddr(ip)[0]
                    self.dns_cache[ip] = hostname
                    print(f"[DNS] Resolved {ip} -> {hostname}")
                except (socket.herror, socket.timeout, socket.gaierror):
                    # Resolution failed, cache as None to avoid retry
                    self.dns_cache[ip] = None
                except Exception as e:
                    print(f"[DNS] Error resolving {ip}: {e}")
                    self.dns_cache[ip] = None

    def _save_pcap(self):
        """Save captured packets to PCAP file with rotation (keep only 3 most recent)."""
        if len(self.all_packets) > 0:
            import os
            import glob
            timestamp = int(time.time())
            filename = f"live_capture_{timestamp}.pcap"
            filepath = os.path.join(self.upload_folder, filename)
            try:
                wrpcap(filepath, self.all_packets)
                print(f"Saved {len(self.all_packets)} packets to {filepath}")
                self.socketio.emit('pcap_saved', {'filename': filename, 'packet_count': len(self.all_packets)})

                # Rotate old live_capture files (keep only 3 most recent)
                self._rotate_live_captures()
            except Exception as e:
                print(f"Error saving PCAP: {e}")

    def _rotate_live_captures(self, keep_count=3):
        """Keep only the most recent live_capture files, delete older ones."""
        import os
        import glob

        try:
            # Find all live_capture files
            pattern = os.path.join(self.upload_folder, "live_capture_*.pcap")
            live_capture_files = glob.glob(pattern)

            if len(live_capture_files) <= keep_count:
                return  # Nothing to rotate

            # Sort by modification time (newest first)
            live_capture_files.sort(key=lambda x: os.path.getmtime(x), reverse=True)

            # Keep only the most recent files
            files_to_keep = live_capture_files[:keep_count]
            files_to_delete = live_capture_files[keep_count:]

            # Delete old files
            for filepath in files_to_delete:
                try:
                    os.remove(filepath)
                    filename = os.path.basename(filepath)
                    print(f"[Rotation] Deleted old capture: {filename}")
                except Exception as e:
                    print(f"[Rotation] Error deleting {filepath}: {e}")

            if files_to_delete:
                print(f"[Rotation] Kept {len(files_to_keep)} most recent live captures, deleted {len(files_to_delete)} old files")
        except Exception as e:
            print(f"[Rotation] Error during rotation: {e}")

    def _process_packet(self, pkt):
        """Process a single captured packet."""
        try:
            # Store raw packet for PCAP export
            self.all_packets.append(pkt)

            # Extract packet info
            packet_data = self._extract_packet_info(pkt)
            if not packet_data:
                return

            src_ip = packet_data['source']
            dst_ip = packet_data['destination']

            # Apply IP filters - skip packet if either endpoint should be filtered
            if should_filter_ip(src_ip, self.ipv4_only, self.private_only) or \
               should_filter_ip(dst_ip, self.ipv4_only, self.private_only):
                return  # Skip this packet

            # Store MAC addresses if available
            if 'sourceMac' in packet_data and packet_data['sourceMac']:
                self.ip_to_mac[src_ip] = packet_data['sourceMac']
                if self.packet_count <= 5:  # Debug first few packets
                    print(f"[LiveCapture] Stored MAC for {src_ip}: {packet_data['sourceMac']}")
            if 'destMac' in packet_data and packet_data['destMac']:
                self.ip_to_mac[dst_ip] = packet_data['destMac']
                if self.packet_count <= 5:  # Debug first few packets
                    print(f"[LiveCapture] Stored MAC for {dst_ip}: {packet_data['destMac']}")

            # Update nodes (aggregate)
            if src_ip not in self.nodes:
                self.nodes[src_ip] = {
                    'ip': src_ip,
                    'packetsSent': 0,
                    'packetsReceived': 0,
                    'bytesSent': 0,
                    'bytesReceived': 0,
                    'protocols': set(),
                    'connections': 0
                }
                # Queue for DNS resolution (only if DNS is enabled)
                if not self.no_dns and src_ip not in self.dns_cache and src_ip not in self.dns_lookup_queue:
                    self.dns_lookup_queue.append(src_ip)

            if dst_ip not in self.nodes:
                self.nodes[dst_ip] = {
                    'ip': dst_ip,
                    'packetsSent': 0,
                    'packetsReceived': 0,
                    'bytesSent': 0,
                    'bytesReceived': 0,
                    'protocols': set(),
                    'connections': 0
                }
                # Queue for DNS resolution (only if DNS is enabled)
                if not self.no_dns and dst_ip not in self.dns_cache and dst_ip not in self.dns_lookup_queue:
                    self.dns_lookup_queue.append(dst_ip)

            # Update node stats
            self.nodes[src_ip]['packetsSent'] += 1
            self.nodes[src_ip]['bytesSent'] += packet_data['length']
            self.nodes[src_ip]['protocols'].add(packet_data['protocol'])

            self.nodes[dst_ip]['packetsReceived'] += 1
            self.nodes[dst_ip]['bytesReceived'] += packet_data['length']
            self.nodes[dst_ip]['protocols'].add(packet_data['protocol'])

            # Update edges (aggregate)
            edge_key = f"{src_ip}-{dst_ip}"
            reverse_key = f"{dst_ip}-{src_ip}"

            if edge_key not in self.edges and reverse_key not in self.edges:
                self.edges[edge_key] = {
                    'source': src_ip,
                    'destination': dst_ip,
                    'protocol': packet_data['protocol'],
                    'packets': 1,
                    'bytes': packet_data['length']
                }
                self.nodes[src_ip]['connections'] += 1
                self.nodes[dst_ip]['connections'] += 1
            else:
                # Update existing edge
                existing_key = edge_key if edge_key in self.edges else reverse_key
                self.edges[existing_key]['packets'] += 1
                self.edges[existing_key]['bytes'] += packet_data['length']

            # Add to buffer for batch sending (limit buffer size)
            if len(self.packet_buffer) < self.max_buffer_size:
                self.packet_buffer.append(packet_data)
            else:
                # Track dropped packets
                self.packets_dropped += 1
                if self.packets_dropped % 100 == 1:  # Log every 100 drops
                    print(f"[LiveCapture] WARNING: Dropped {self.packets_dropped} packets due to buffer overflow. Consider reducing traffic or increasing batch interval.")

            # Track statistics
            self.packet_count += 1
            self.total_bytes += packet_data['length']

            # Track packet timestamps
            if self.first_packet_time is None:
                self.first_packet_time = packet_data['timestamp']
            self.last_packet_time = packet_data['timestamp']

            # Log every 100 packets
            if self.packet_count % 100 == 0:
                print(f"[LiveCapture] Captured {self.packet_count} packets, {len(self.nodes)} nodes, {len(self.edges)} edges")

        except Exception as e:
            print(f"[LiveCapture] Error processing packet: {e}")

    def _extract_packet_info(self, pkt):
        """Extract relevant information from a packet."""
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

        # Check for IPv4 or IPv6
        if pkt.haslayer(IP):
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
        elif pkt.haslayer(IPv6):
            src_ip = pkt[IPv6].src
            dst_ip = pkt[IPv6].dst
        else:
            # For non-IP packets (like ARP), handle separately
            if pkt.haslayer(ARP):
                return self._extract_arp_info(pkt, src_mac, dst_mac)
            return None

        src_port = None
        dst_port = None

        # Get port numbers if available
        if pkt.haslayer(TCP):
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
        elif pkt.haslayer(UDP):
            src_port = pkt[UDP].sport
            dst_port = pkt[UDP].dport

        # Use centralized protocol detection
        proto = get_protocol_name(pkt)

        # Get timestamp
        timestamp = float(pkt.time)

        # Get raw packet data
        raw_data = list(bytes(pkt))

        return {
            'timestamp': timestamp,
            'source': src_ip,
            'destination': dst_ip,
            'protocol': proto,
            'length': len(pkt),
            'srcPort': src_port,
            'dstPort': dst_port,
            'data': raw_data,
            'sourceMac': src_mac,
            'destMac': dst_mac
        }

    def _extract_arp_info(self, pkt, src_mac=None, dst_mac=None):
        """Extract ARP packet information."""
        arp = pkt[ARP]
        # ARP packets also contain MAC addresses - get from ARP layer if not already found
        if not src_mac and hasattr(arp, 'hwsrc'):
            src_mac = arp.hwsrc
        if not dst_mac and hasattr(arp, 'hwdst'):
            dst_mac = arp.hwdst

        return {
            'timestamp': float(pkt.time),
            'source': arp.psrc,
            'destination': arp.pdst,
            'protocol': 'ARP',
            'length': len(pkt),
            'srcPort': None,
            'dstPort': None,
            'data': list(bytes(pkt)),
            'sourceMac': src_mac,
            'destMac': dst_mac
        }
