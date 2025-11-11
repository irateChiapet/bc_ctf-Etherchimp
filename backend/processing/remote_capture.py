"""Remote packet capture via SSH tunnel."""

import subprocess
import threading
import time
from scapy.all import PcapReader
import io
from backend.utils.helpers import get_protocol_name
from backend.utils.ip_filters import should_filter_ip


class RemoteCapture:
    """Handles remote packet capture over SSH."""

    def __init__(self, remote_host, interface, socketio, upload_folder, username=None, password=None, no_dns=False, ipv4_only=False, private_only=False):
        """
        Initialize remote capture.

        Args:
            remote_host: SSH host (user@host or just host)
            interface: Remote interface to capture on
            socketio: SocketIO instance for sending data
            upload_folder: Folder to save captured packets
            username: Optional SSH username (if not in remote_host)
            password: Optional SSH password (requires sshpass)
            no_dns: Disable DNS resolution
            ipv4_only: Only show IPv4 addresses
            private_only: Only show private/LAN addresses
        """
        self.remote_host = remote_host
        self.interface = interface
        self.socketio = socketio
        self.upload_folder = upload_folder
        self.username = username
        self.password = password
        self.no_dns = no_dns
        self.ipv4_only = ipv4_only
        self.private_only = private_only
        self.running = False
        self.thread = None
        self.process = None
        self.packet_count = 0
        self.packet_buffer = []
        self.all_packets = []
        self.batch_interval = 5
        self.last_batch_time = time.time()

        # Backend aggregation for nodes and edges
        self.nodes = {}
        self.edges = {}
        self.max_packets_per_batch = 100

        # DNS resolution cache
        self.dns_cache = {}
        self.dns_lookup_queue = []
        self.dns_thread = None

    def start(self):
        """Start remote capture via SSH."""
        if self.running:
            return

        self.running = True
        self.packet_buffer = []
        self.all_packets = []
        self.nodes = {}
        self.edges = {}
        self.dns_cache = {}
        self.dns_lookup_queue = []
        self.last_batch_time = time.time()

        # Start capture thread
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
        """Stop remote capture."""
        self.running = False
        if self.process:
            self.process.terminate()
            self.process.wait(timeout=2)
        if self.thread:
            self.thread.join(timeout=2)

        # Save captured packets
        self._save_pcap()

    def _capture_loop(self):
        """Main capture loop using SSH tunnel."""
        try:
            # Build SSH command to run tcpdump on remote host
            # Determine SSH host string
            ssh_host = self.remote_host
            if self.username and '@' not in self.remote_host:
                ssh_host = f"{self.username}@{self.remote_host}"

            # Build command - use sshpass if password is provided
            # Important: Use multiple options to ensure unbuffered output
            # -U: packet-buffered output (write each packet immediately)
            # --immediate-mode: capture packets as soon as they arrive
            # -l: line buffered (for text output, but we use -w -)
            # stdbuf -o0: disable output buffering
            # -s 0: capture full packets (snaplen)
            tcpdump_cmd = f"sudo tcpdump -i {self.interface} -U -w - --immediate-mode -s 0 2>/dev/null"

            if self.password:
                # Use sshpass for password authentication
                cmd = [
                    'sshpass',
                    '-p', self.password,
                    'ssh',
                    '-o', 'StrictHostKeyChecking=no',
                    '-o', 'ServerAliveInterval=5',
                    '-o', 'TCPKeepAlive=yes',
                    '-o', 'Compression=no',  # Disable compression for real-time
                    '-T',  # Disable pseudo-terminal allocation
                    ssh_host,
                    tcpdump_cmd
                ]
                print(f"[RemoteCapture] Starting SSH capture with password authentication")
            else:
                # Use SSH key authentication
                cmd = [
                    'ssh',
                    '-o', 'StrictHostKeyChecking=no',
                    '-o', 'ServerAliveInterval=5',
                    '-o', 'TCPKeepAlive=yes',
                    '-o', 'Compression=no',  # Disable compression for real-time
                    '-T',  # Disable pseudo-terminal allocation
                    ssh_host,
                    tcpdump_cmd
                ]
                print(f"[RemoteCapture] Starting SSH capture with key authentication")

            print(f"[RemoteCapture] Command: {' '.join([c for c in cmd if c != self.password])}")  # Don't log password

            # Start SSH process
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.PIPE if self.password else None,
                bufsize=0
            )

            # If using password, send it for sudo
            if self.password:
                self.process.stdin.write(f"{self.password}\n".encode())
                self.process.stdin.flush()

            # Read packets from SSH stdout using scapy PcapReader
            # Use unbuffered reading
            try:
                packet_reader = PcapReader(self.process.stdout)

                packet_count = 0
                for pkt in packet_reader:
                    if not self.running:
                        break
                    self._process_packet(pkt)
                    packet_count += 1

                    # Debug output every 10 packets
                    if packet_count % 10 == 0:
                        print(f"[RemoteCapture] Received {packet_count} packets from remote")

            except Exception as e:
                # Check if it's a normal shutdown or actual error
                if self.running:
                    print(f"[RemoteCapture] Packet reader error: {e}")
                    import traceback
                    traceback.print_exc()

        except Exception as e:
            print(f"[RemoteCapture] Error: {e}")
            import traceback
            traceback.print_exc()
            self.socketio.emit('capture_error', {'error': f'Remote capture error: {str(e)}'})

    def _batch_sender(self):
        """Send aggregated data in batches."""
        while self.running:
            time.sleep(self.batch_interval)

            if len(self.packet_buffer) > 0:
                packets_to_send = self.packet_buffer[:self.max_packets_per_batch]

                # Convert nodes to serializable format
                nodes_serializable = []
                for node in self.nodes.values():
                    node_copy = node.copy()
                    node_copy['protocols'] = list(node['protocols'])
                    node_copy['hostname'] = self.dns_cache.get(node['ip'], None)
                    nodes_serializable.append(node_copy)

                # Calculate statistics
                unique_hosts = len(self.nodes)
                active_connections = len(self.edges)

                # Send aggregated data
                batch_data = {
                    'packets': packets_to_send,
                    'count': len(packets_to_send),
                    'nodes': nodes_serializable,
                    'edges': list(self.edges.values()),
                    'totalCaptured': self.packet_count,
                    'dnsCache': self.dns_cache,
                    'statistics': {
                        'uniqueHosts': unique_hosts,
                        'activeConnections': active_connections,
                        'totalPackets': self.packet_count,
                        'totalNodes': unique_hosts,
                        'totalEdges': active_connections
                    }
                }
                print(f"[RemoteCapture] Sending batch: {len(packets_to_send)} packets, {unique_hosts} unique hosts, {active_connections} active connections, {self.packet_count} total packets")
                self.socketio.emit('packet_batch', batch_data)

                self.packet_buffer = self.packet_buffer[self.max_packets_per_batch:]

    def _dns_resolver(self):
        """Background DNS resolution thread."""
        import socket
        while self.running:
            time.sleep(1)

            for _ in range(min(5, len(self.dns_lookup_queue))):
                if not self.dns_lookup_queue:
                    break

                ip = self.dns_lookup_queue.pop(0)

                if ip in self.dns_cache:
                    continue

                try:
                    socket.setdefaulttimeout(2)
                    hostname = socket.gethostbyaddr(ip)[0]
                    self.dns_cache[ip] = hostname
                    print(f"[DNS] Resolved {ip} -> {hostname}")
                except:
                    self.dns_cache[ip] = None

    def _save_pcap(self):
        """Save captured packets to PCAP file."""
        from scapy.all import wrpcap
        if len(self.all_packets) > 0:
            import os
            timestamp = int(time.time())

            # Extract IP from remote_host (handle user@host or just host)
            remote_ip = self.remote_host
            if '@' in remote_ip:
                remote_ip = remote_ip.split('@')[1]

            # Create filename: IP-INTERFACE-TIMESTAMP.pcap
            filename = f"{remote_ip}-{self.interface}-{timestamp}.pcap"
            filepath = os.path.join(self.upload_folder, filename)

            try:
                wrpcap(filepath, self.all_packets)
                print(f"Saved {len(self.all_packets)} packets to {filepath}")
                self.socketio.emit('pcap_saved', {'filename': filename, 'packet_count': len(self.all_packets)})
            except Exception as e:
                print(f"Error saving PCAP: {e}")

    def _process_packet(self, pkt):
        """Process a single captured packet."""
        from scapy.layers.inet import IP, TCP, UDP, ICMP
        from scapy.layers.l2 import ARP

        try:
            self.all_packets.append(pkt)

            # Extract packet info (reuse logic from live_capture)
            packet_data = self._extract_packet_info(pkt)
            if not packet_data:
                return

            src_ip = packet_data['source']
            dst_ip = packet_data['destination']

            # Apply IP filters - skip packet if either endpoint should be filtered
            if should_filter_ip(src_ip, self.ipv4_only, self.private_only) or \
               should_filter_ip(dst_ip, self.ipv4_only, self.private_only):
                return  # Skip this packet

            # Update nodes
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
                if not self.no_dns and dst_ip not in self.dns_cache and dst_ip not in self.dns_lookup_queue:
                    self.dns_lookup_queue.append(dst_ip)

            # Update node stats
            self.nodes[src_ip]['packetsSent'] += 1
            self.nodes[src_ip]['bytesSent'] += packet_data['length']
            self.nodes[src_ip]['protocols'].add(packet_data['protocol'])

            self.nodes[dst_ip]['packetsReceived'] += 1
            self.nodes[dst_ip]['bytesReceived'] += packet_data['length']
            self.nodes[dst_ip]['protocols'].add(packet_data['protocol'])

            # Update edges
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
                existing_key = edge_key if edge_key in self.edges else reverse_key
                self.edges[existing_key]['packets'] += 1
                self.edges[existing_key]['bytes'] += packet_data['length']

            # Add to buffer
            if len(self.packet_buffer) < 1000:
                self.packet_buffer.append(packet_data)

            self.packet_count += 1

            if self.packet_count % 100 == 0:
                print(f"[RemoteCapture] Captured {self.packet_count} packets, {len(self.nodes)} nodes, {len(self.edges)} edges")

        except Exception as e:
            print(f"[RemoteCapture] Error processing packet: {e}")

    def _extract_packet_info(self, pkt):
        """Extract packet information (same as live_capture)."""
        from scapy.layers.inet import IP, TCP, UDP
        from scapy.layers.inet6 import IPv6
        from scapy.layers.l2 import ARP

        # Check for IPv4 or IPv6
        if pkt.haslayer(IP):
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
        elif pkt.haslayer(IPv6):
            src_ip = pkt[IPv6].src
            dst_ip = pkt[IPv6].dst
        else:
            if pkt.haslayer(ARP):
                return self._extract_arp_info(pkt)
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

        timestamp = float(pkt.time)
        raw_data = list(bytes(pkt))

        return {
            'timestamp': timestamp,
            'source': src_ip,
            'destination': dst_ip,
            'protocol': proto,
            'length': len(pkt),
            'srcPort': src_port,
            'dstPort': dst_port,
            'data': raw_data
        }

    def _extract_arp_info(self, pkt):
        """Extract ARP packet information."""
        from scapy.layers.l2 import ARP
        arp = pkt[ARP]
        return {
            'timestamp': float(pkt.time),
            'source': arp.psrc,
            'destination': arp.pdst,
            'protocol': 'ARP',
            'length': len(pkt),
            'srcPort': None,
            'dstPort': None,
            'data': list(bytes(pkt))
        }
