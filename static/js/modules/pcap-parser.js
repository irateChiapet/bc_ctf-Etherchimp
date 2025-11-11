// PCAP Parser with proper binary format handling
class PCAPParser {
    constructor() {
        this.packets = [];
        this.hosts = new Map();
        this.connections = new Map();
        this.protocols = new Map();
        this.alerts = [];
    }

    parse(arrayBuffer, progressCallback) {
        const dataView = new DataView(arrayBuffer);
        let offset = 0;

        // Read PCAP Global Header (24 bytes)
        const magic = dataView.getUint32(0, true);
        const isLittleEndian = (magic === 0xa1b2c3d4 || magic === 0xd4c3b2a1);
        const isNanosecond = (magic === 0xa1b23c4d || magic === 0x4d3cb2a1);

        if (!isLittleEndian && magic !== 0xa1b2c3d4 && magic !== 0xd4c3b2a1) {
            throw new Error('Invalid PCAP file format');
        }

        // Skip rest of global header
        offset = 24;

        let packetCount = 0;
        const totalSize = arrayBuffer.byteLength;

        while (offset < totalSize - 16) {
            try {
                // Read packet header (16 bytes)
                const ts_sec = dataView.getUint32(offset, isLittleEndian);
                const ts_usec = dataView.getUint32(offset + 4, isLittleEndian);
                const incl_len = dataView.getUint32(offset + 8, isLittleEndian);
                const orig_len = dataView.getUint32(offset + 12, isLittleEndian);

                offset += 16;

                if (incl_len > 65535 || offset + incl_len > totalSize) {
                    break;
                }

                // Parse packet data
                const packetData = new Uint8Array(arrayBuffer, offset, incl_len);
                const packet = this.parsePacket(packetData, ts_sec, ts_usec, orig_len);

                if (packet) {
                    this.packets.push(packet);
                    this.updateStats(packet);
                    packetCount++;

                    if (progressCallback && packetCount % 100 === 0) {
                        progressCallback(Math.min(90, (offset / totalSize) * 100));
                    }
                }

                offset += incl_len;
            } catch (e) {
                console.warn('Error parsing packet:', e);
                break;
            }
        }

        if (progressCallback) progressCallback(100);
        return this.packets;
    }

    parsePacket(data, ts_sec, ts_usec, orig_len) {
        if (data.length < 14) return null;

        let offset = 0;
        const packet = {
            timestamp: ts_sec + ts_usec / 1000000,
            length: orig_len,
            data: data
        };

        // Parse Ethernet header (14 bytes)
        const ethType = (data[12] << 8) | data[13];
        offset = 14;

        // Parse IP header (if IPv4)
        if (ethType === 0x0800 && data.length >= offset + 20) {
            const ipVersion = (data[offset] >> 4) & 0xF;

            if (ipVersion === 4) {
                const ipHeaderLen = (data[offset] & 0xF) * 4;

                // Extract source and destination IPs
                packet.source = `${data[offset + 12]}.${data[offset + 13]}.${data[offset + 14]}.${data[offset + 15]}`;
                packet.destination = `${data[offset + 16]}.${data[offset + 17]}.${data[offset + 18]}.${data[offset + 19]}`;

                // Get protocol
                const protocol = data[offset + 9];
                packet.protocolNum = protocol;

                switch(protocol) {
                    case 6:
                        packet.protocol = 'TCP';
                        // Parse TCP header
                        if (data.length >= offset + ipHeaderLen + 20) {
                            const tcpOffset = offset + ipHeaderLen;
                            packet.srcPort = (data[tcpOffset] << 8) | data[tcpOffset + 1];
                            packet.dstPort = (data[tcpOffset + 2] << 8) | data[tcpOffset + 3];
                            packet.flags = data[tcpOffset + 13];

                            // Identify application protocols by port
                            if (packet.dstPort === 20 || packet.dstPort === 21 || packet.srcPort === 20 || packet.srcPort === 21) {
                                packet.protocol = 'FTP';
                            } else if (packet.dstPort === 22 || packet.srcPort === 22) {
                                packet.protocol = 'SSH';
                            } else if (packet.dstPort === 80 || packet.srcPort === 80) {
                                packet.protocol = 'HTTP';
                            } else if (packet.dstPort === 443 || packet.srcPort === 443) {
                                packet.protocol = 'HTTPS';
                            }
                        }
                        break;
                    case 17:
                        packet.protocol = 'UDP';
                        // Parse UDP header
                        if (data.length >= offset + ipHeaderLen + 8) {
                            const udpOffset = offset + ipHeaderLen;
                            packet.srcPort = (data[udpOffset] << 8) | data[udpOffset + 1];
                            packet.dstPort = (data[udpOffset + 2] << 8) | data[udpOffset + 3];

                            // Identify application protocols by port
                            if (packet.dstPort === 53 || packet.srcPort === 53) {
                                packet.protocol = 'DNS';
                            } else if (packet.dstPort === 67 || packet.dstPort === 68 || packet.srcPort === 67 || packet.srcPort === 68) {
                                packet.protocol = 'BOOTP';
                            }
                        }
                        break;
                    case 1:
                        packet.protocol = 'ICMP';
                        break;
                    default:
                        packet.protocol = 'Other';
                }

                return packet;
            }
        } else if (ethType === 0x86dd && data.length >= offset + 40) {
            // IPv6
            packet.source = this.parseIPv6(data.slice(offset + 8, offset + 24));
            packet.destination = this.parseIPv6(data.slice(offset + 24, offset + 40));
            packet.protocol = 'IPv6';
            const nextHeader = data[offset + 6];

            if (nextHeader === 6) packet.protocol = 'TCP/IPv6';
            else if (nextHeader === 17) packet.protocol = 'UDP/IPv6';

            return packet;
        }

        return null;
    }

    parseIPv6(bytes) {
        const parts = [];
        for (let i = 0; i < 16; i += 2) {
            parts.push(((bytes[i] << 8) | bytes[i + 1]).toString(16));
        }
        return parts.join(':');
    }

    updateStats(packet) {
        // Update hosts
        if (packet.source) {
            if (!this.hosts.has(packet.source)) {
                this.hosts.set(packet.source, {
                    ip: packet.source,
                    packetsSent: 0,
                    packetsReceived: 0,
                    bytesSent: 0,
                    bytesReceived: 0,
                    protocols: new Set(),
                    ports: new Set(),
                    connections: new Set()
                });
            }
            const host = this.hosts.get(packet.source);
            host.packetsSent++;
            host.bytesSent += packet.length;
            if (packet.protocol) host.protocols.add(packet.protocol);
            if (packet.srcPort) host.ports.add(packet.srcPort);
        }

        if (packet.destination) {
            if (!this.hosts.has(packet.destination)) {
                this.hosts.set(packet.destination, {
                    ip: packet.destination,
                    packetsSent: 0,
                    packetsReceived: 0,
                    bytesSent: 0,
                    bytesReceived: 0,
                    protocols: new Set(),
                    ports: new Set(),
                    connections: new Set()
                });
            }
            const host = this.hosts.get(packet.destination);
            host.packetsReceived++;
            host.bytesReceived += packet.length;
            if (packet.protocol) host.protocols.add(packet.protocol);
            if (packet.dstPort) host.ports.add(packet.dstPort);
        }

        // Update connections
        if (packet.source && packet.destination) {
            const connKey = `${packet.source}:${packet.srcPort || 0}-${packet.destination}:${packet.dstPort || 0}`;
            if (!this.connections.has(connKey)) {
                this.connections.set(connKey, {
                    source: packet.source,
                    destination: packet.destination,
                    srcPort: packet.srcPort,
                    dstPort: packet.dstPort,
                    protocol: packet.protocol,
                    packets: 0,
                    bytes: 0,
                    startTime: packet.timestamp,
                    lastTime: packet.timestamp
                });
            }
            const conn = this.connections.get(connKey);
            conn.packets++;
            conn.bytes += packet.length;
            conn.lastTime = packet.timestamp;

            // Link hosts
            if (this.hosts.has(packet.source)) {
                this.hosts.get(packet.source).connections.add(packet.destination);
            }
            if (this.hosts.has(packet.destination)) {
                this.hosts.get(packet.destination).connections.add(packet.source);
            }
        }

        // Update protocols
        if (packet.protocol) {
            this.protocols.set(packet.protocol, (this.protocols.get(packet.protocol) || 0) + 1);
        }

        // Detect suspicious activity
        this.detectThreats(packet);
    }

    detectThreats(packet) {
        // Initialize alert deduplication tracker
        if (!this.alreadyAlerted) this.alreadyAlerted = new Set();

        // Helper function to create unique alert key
        const createAlertKey = (type, ip, mac) => {
            return `${type}:${ip}:${mac || 'nomac'}`;
        };

        // Skip alerts for standard HTTPS/DNS traffic to avoid noise
        if (packet.dstPort === 443 || packet.dstPort === 53 || packet.srcPort === 443 || packet.srcPort === 53) {
            return;
        }

        // Track unique destination ports per source for port scanning
        if (packet.protocol === 'TCP' && packet.flags) {
            const sourceKey = packet.source;
            if (!this.portScanTracker) this.portScanTracker = new Map();
            if (!this.portScanTracker.has(sourceKey)) {
                this.portScanTracker.set(sourceKey, new Set());
            }

            const ports = this.portScanTracker.get(sourceKey);
            ports.add(packet.dstPort);

            // Alert only if scanning multiple ports (10+) - indicates actual scanning
            const alertKey = createAlertKey('portscan', packet.source, packet.sourceMac);
            if (ports.size >= 10 && !this.alreadyAlerted.has(alertKey)) {
                this.alreadyAlerted.add(alertKey);

                this.alerts.push({
                    type: 'Port Scan Detected',
                    severity: 'high',
                    source: packet.source,
                    destination: packet.destination,
                    port: packet.dstPort,
                    protocol: packet.protocol,
                    timestamp: packet.timestamp,
                    sourceMac: packet.sourceMac,
                    details: `Host scanning ${ports.size} ports - potential reconnaissance`
                });
            }
        }

        // Detect MAC/IP address changes (ARP spoofing indicator)
        if (packet.protocol === 'ARP' && packet.source) {
            if (!this.macIpMap) this.macIpMap = new Map();

            const macKey = packet.sourceMac;
            if (macKey && this.macIpMap.has(macKey) && this.macIpMap.get(macKey) !== packet.source) {
                const alertKey = createAlertKey('ipchange', packet.source, packet.sourceMac);
                if (!this.alreadyAlerted.has(alertKey)) {
                    this.alreadyAlerted.add(alertKey);

                    this.alerts.push({
                        type: 'IP Address Change Detected',
                        severity: 'high',
                        source: packet.source,
                        destination: packet.destination,
                        protocol: 'ARP',
                        timestamp: packet.timestamp,
                        sourceMac: packet.sourceMac,
                        details: `Host changed from ${this.macIpMap.get(macKey)} to ${packet.source} - possible ARP spoofing`
                    });
                }
            }
            if (macKey) this.macIpMap.set(macKey, packet.source);
        }

        // Detect hosts with multiple IPs (potential pivoting/tunneling)
        if (packet.source) {
            if (!this.hostIpTracker) this.hostIpTracker = new Map();

            const macKey = packet.sourceMac || packet.source;
            if (!this.hostIpTracker.has(macKey)) {
                this.hostIpTracker.set(macKey, new Set());
            }

            const ips = this.hostIpTracker.get(macKey);
            ips.add(packet.source);

            const alertKey = createAlertKey('multiip', packet.source, packet.sourceMac);
            if (ips.size > 2 && !this.alreadyAlerted.has(alertKey)) {
                this.alreadyAlerted.add(alertKey);

                this.alerts.push({
                    type: 'Multiple IP Addresses',
                    severity: 'medium',
                    source: packet.source,
                    destination: packet.destination,
                    protocol: packet.protocol,
                    timestamp: packet.timestamp,
                    sourceMac: packet.sourceMac,
                    details: `Host using ${ips.size} different IPs: ${Array.from(ips).join(', ')}`
                });
            }
        }

        // Suspicious backdoor/C2 ports
        if (packet.dstPort && [4444, 5555, 6666, 7777, 31337, 12345].includes(packet.dstPort)) {
            const alertKey = createAlertKey(`suspicious-${packet.dstPort}`, packet.source, packet.sourceMac);
            if (!this.alreadyAlerted.has(alertKey)) {
                this.alreadyAlerted.add(alertKey);

                this.alerts.push({
                    type: 'Suspicious Port Activity',
                    severity: 'high',
                    source: packet.source,
                    destination: packet.destination,
                    port: packet.dstPort,
                    protocol: packet.protocol,
                    timestamp: packet.timestamp,
                    sourceMac: packet.sourceMac,
                    details: `Connection to known backdoor/C2 port ${packet.dstPort}`
                });
            }
        }

        // ICMP flood detection (more refined)
        if (packet.protocol === 'ICMP' && packet.icmpType !== 0 && packet.icmpType !== 8) { // Ignore ping request/reply
            const recentICMP = this.packets.filter(p =>
                p.protocol === 'ICMP' &&
                p.source === packet.source &&
                packet.timestamp - p.timestamp < 1
            ).length;

            const alertKey = createAlertKey('icmpflood', packet.source, packet.sourceMac);
            if (recentICMP > 50 && !this.alreadyAlerted.has(alertKey)) {
                this.alreadyAlerted.add(alertKey);

                this.alerts.push({
                    type: 'ICMP Flood',
                    severity: 'high',
                    source: packet.source,
                    destination: packet.destination,
                    protocol: 'ICMP',
                    timestamp: packet.timestamp,
                    sourceMac: packet.sourceMac,
                    details: `ICMP flood detected - ${recentICMP} packets in 1 second`
                });
            }
        }

        // Detect unusual connection patterns (many failed connections)
        if (packet.protocol === 'TCP' && packet.flags) {
            const isRST = packet.flags & 0x04; // RST flag
            if (isRST) {
                if (!this.rstTracker) this.rstTracker = new Map();
                const key = `${packet.source}-${packet.destination}`;
                this.rstTracker.set(key, (this.rstTracker.get(key) || 0) + 1);

                const alertKey = createAlertKey(`rst-${packet.destination}`, packet.source, packet.sourceMac);
                if (this.rstTracker.get(key) > 20 && !this.alreadyAlerted.has(alertKey)) {
                    this.alreadyAlerted.add(alertKey);

                    this.alerts.push({
                        type: 'Connection Failures',
                        severity: 'medium',
                        source: packet.source,
                        destination: packet.destination,
                        protocol: 'TCP',
                        timestamp: packet.timestamp,
                        sourceMac: packet.sourceMac,
                        details: `Multiple failed connections (${this.rstTracker.get(key)} RST packets)`
                    });
                }
            }
        }
    }
}
