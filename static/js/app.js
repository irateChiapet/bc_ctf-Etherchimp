
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

        // Network Visualization
        class NetworkVisualizer {
            constructor(canvas) {
                this.canvas = canvas;
                this.ctx = canvas.getContext('2d');
                this.nodes = new Map();
                this.edges = [];
                this.particles = [];
                this.camera = { x: 0, y: 0, zoom: 1 };
                this.mouse = { x: 0, y: 0, down: false, rightDown: false };
                this.selectedNode = null;
                this.animating = true; // Enable jiggle physics by default
                this.layoutType = 'force';
                this.tooltipLocked = false;
                this.lockedNode = null;
                this.lockedEdge = null;
                this.allPackets = [];
                this.isLiveMode = false; // Track if we're in live capture mode
                this.isRemoteMode = false; // Track if we're in remote capture mode

                // 3D rotation state
                this.rotation = { x: 0, y: 0 }; // Rotation angles in radians

                // Line rider state
                this.riderActive = false;
                this.riderPath = [];
                this.riderPosition = 0;
                this.riderSpeed = 0.008; // Slower speed
                this.riderCurrentEdge = null;

                // Clustering state for intelligent grouping
                this.clusters = new Map(); // subnet -> cluster info
                this.clusterPositions = new Map(); // subnet -> {x, y} center position

                this.setupCanvas();
                this.setupEvents();
                this.animate();
            }

            setupCanvas() {
                this.resize();
                window.addEventListener('resize', () => this.resize());

                // Watch for sidebar toggle to resize canvas
                const observer = new MutationObserver(() => {
                    setTimeout(() => this.resize(), 350); // Wait for animation
                });
                const container = document.getElementById('container');
                if (container) {
                    observer.observe(container, { attributes: true, attributeFilter: ['class'] });
                }
            }

            resize() {
                const width = this.canvas.offsetWidth * window.devicePixelRatio;
                const height = this.canvas.offsetHeight * window.devicePixelRatio;

                // Only resize if dimensions actually changed
                if (this.canvas.width !== width || this.canvas.height !== height) {
                    this.canvas.width = width;
                    this.canvas.height = height;
                    this.ctx.scale(window.devicePixelRatio, window.devicePixelRatio);
                }
            }

            setupEvents() {
                this.canvas.addEventListener('mousedown', (e) => {
                    // Right-click for rotation in 3D mode
                    if (e.button === 2) {
                        e.preventDefault();
                        this.mouse.rightDown = true;
                        this.mouse.startX = e.clientX;
                        this.mouse.startY = e.clientY;
                        this.mouse.rotationStartX = this.rotation.x;
                        this.mouse.rotationStartY = this.rotation.y;
                        return;
                    }

                    this.mouse.down = true;
                    this.mouse.startX = e.clientX;
                    this.mouse.startY = e.clientY;
                    this.mouse.cameraStartX = this.camera.x;
                    this.mouse.cameraStartY = this.camera.y;

                    // Check for node click or edge click
                    const rect = this.canvas.getBoundingClientRect();
                    const mouseX = (e.clientX - rect.left - this.camera.x) / this.camera.zoom;
                    const mouseY = (e.clientY - rect.top - this.camera.y) / this.camera.zoom;

                    // Check for edge click first (before node click)
                    let clickedEdge = null;
                    this.edges.forEach(edge => {
                        // Skip hidden edges
                        if (edge.hidden) return;

                        const sourceProj = this.project3D(edge.source);
                        const targetProj = this.project3D(edge.target);
                        const dist = this.distanceToLineSegment(
                            mouseX, mouseY,
                            sourceProj.x, sourceProj.y,
                            targetProj.x, targetProj.y
                        );
                        if (dist < 10) { // 10 pixel tolerance
                            clickedEdge = edge;
                        }
                    });

                    if (clickedEdge) {
                        // Show edge packet details
                        this.showEdgePackets(clickedEdge);
                        return;
                    }

                    // Check for node click (accounting for 3D projection)
                    this.selectedNode = null;
                    let clickedNode = null;
                    this.nodes.forEach(node => {
                        // Skip hidden nodes
                        if (node.hidden) return;

                        const proj = this.project3D(node);
                        const dx = mouseX - proj.x;
                        const dy = mouseY - proj.y;

                        // Calculate node radius based on role (match rendering logic)
                        let nodeRadius = node.radius || 15;
                        if (this.layoutType === 'clustered') {
                            if (node.clusterRole === 'scanner' || node.clusterRole === 'listener') {
                                nodeRadius = 25;
                            } else if (node.clusterRole === 'hub') {
                                nodeRadius = 20;
                            }
                        } else if (this.layoutType === 'clustered-host') {
                            if (node.clusterRole === 'center') {
                                nodeRadius = 28;
                            } else if (node.clusterRole === 'satellite') {
                                nodeRadius = 12;
                            }
                        }

                        const radius = nodeRadius * proj.scale;
                        if (Math.sqrt(dx * dx + dy * dy) < radius) {
                            this.selectedNode = node;
                            clickedNode = node;
                        }
                    });

                    // Show dashboard on node click
                    if (clickedNode) {
                        this.showNodeDashboard(clickedNode);
                    }
                });

                this.canvas.addEventListener('mousemove', (e) => {
                    const rect = this.canvas.getBoundingClientRect();
                    this.mouse.x = e.clientX - rect.left;
                    this.mouse.y = e.clientY - rect.top;

                    // Right-click rotation in 3D mode
                    if (this.mouse.rightDown && this.layoutType === '3d') {
                        const deltaX = e.clientX - this.mouse.startX;
                        const deltaY = e.clientY - this.mouse.startY;

                        // Update rotation angles (sensitivity: 0.005 radians per pixel)
                        this.rotation.y = this.mouse.rotationStartY + deltaX * 0.005;
                        this.rotation.x = this.mouse.rotationStartX + deltaY * 0.005;

                        // Clamp X rotation to prevent flipping upside down
                        this.rotation.x = Math.max(-Math.PI / 2, Math.min(Math.PI / 2, this.rotation.x));
                        return;
                    }

                    if (this.mouse.down && !this.selectedNode) {
                        this.camera.x = this.mouse.cameraStartX + (e.clientX - this.mouse.startX);
                        this.camera.y = this.mouse.cameraStartY + (e.clientY - this.mouse.startY);
                    } else if (this.mouse.down && this.selectedNode) {
                        // In 3D mode, we need to unproject the mouse position
                        if (this.layoutType === '3d') {
                            // Keep the z coordinate constant while dragging in x/y
                            const focalLength = 1000;
                            const z = (this.selectedNode.z || 0) + focalLength;
                            const scale = focalLength / z;

                            const mouseWorldX = (this.mouse.x - this.camera.x) / this.camera.zoom;
                            const mouseWorldY = (this.mouse.y - this.camera.y) / this.camera.zoom;

                            // Unproject from screen space to 3D space
                            this.selectedNode.x = mouseWorldX / scale;
                            this.selectedNode.y = mouseWorldY / scale;
                        } else {
                            this.selectedNode.x = (this.mouse.x - this.camera.x) / this.camera.zoom;
                            this.selectedNode.y = (this.mouse.y - this.camera.y) / this.camera.zoom;
                        }

                        this.selectedNode.fx = this.selectedNode.x;
                        this.selectedNode.fy = this.selectedNode.y;
                        if (this.layoutType === '3d') {
                            this.selectedNode.fz = this.selectedNode.z;
                        }
                    }

                    // Show tooltip
                    this.showTooltip(e);
                });

                this.canvas.addEventListener('mouseup', (e) => {
                    if (e.button === 2) {
                        this.mouse.rightDown = false;
                        return;
                    }

                    this.mouse.down = false;
                    if (this.selectedNode) {
                        delete this.selectedNode.fx;
                        delete this.selectedNode.fy;
                        if (this.layoutType === '3d') {
                            delete this.selectedNode.fz;
                        }
                    }
                });

                // Global mouseup to catch events outside canvas
                document.addEventListener('mouseup', (e) => {
                    this.mouse.down = false;
                    this.mouse.rightDown = false;
                    if (this.selectedNode) {
                        delete this.selectedNode.fx;
                        delete this.selectedNode.fy;
                        if (this.layoutType === '3d') {
                            delete this.selectedNode.fz;
                        }
                        this.selectedNode = null;
                    }
                });

                // Reset on mouse leaving the window
                this.canvas.addEventListener('mouseleave', () => {
                    this.mouse.down = false;
                    this.mouse.rightDown = false;
                    if (this.selectedNode) {
                        delete this.selectedNode.fx;
                        delete this.selectedNode.fy;
                        if (this.layoutType === '3d') {
                            delete this.selectedNode.fz;
                        }
                    }
                });

                // Prevent context menu on right-click
                this.canvas.addEventListener('contextmenu', (e) => {
                    if (this.layoutType === '3d') {
                        e.preventDefault();
                    }
                });

                this.canvas.addEventListener('wheel', (e) => {
                    e.preventDefault();

                    // In 3D mode with a selected node, control z-axis with mouse wheel
                    if (this.layoutType === '3d' && this.selectedNode && this.mouse.down) {
                        const zDelta = e.deltaY > 0 ? -10 : 10; // Move in/out of screen
                        this.selectedNode.z = (this.selectedNode.z || 0) + zDelta;
                        // Clamp z to reasonable bounds
                        this.selectedNode.z = Math.max(-500, Math.min(500, this.selectedNode.z));
                        this.selectedNode.fz = this.selectedNode.z;
                        return;
                    }

                    // Get mouse position relative to canvas
                    const rect = this.canvas.getBoundingClientRect();
                    const mouseX = e.clientX - rect.left;
                    const mouseY = e.clientY - rect.top;

                    // Calculate world position before zoom
                    const worldX = (mouseX - this.camera.x) / this.camera.zoom;
                    const worldY = (mouseY - this.camera.y) / this.camera.zoom;

                    // Apply zoom with smooth scaling
                    const zoomDelta = e.deltaY > 0 ? 0.95 : 1.05;
                    const oldZoom = this.camera.zoom;
                    this.camera.zoom *= zoomDelta;
                    this.camera.zoom = Math.max(0.1, Math.min(5, this.camera.zoom));

                    // Calculate world position after zoom
                    const newWorldX = (mouseX - this.camera.x) / this.camera.zoom;
                    const newWorldY = (mouseY - this.camera.y) / this.camera.zoom;

                    // Adjust camera position to keep mouse point stable
                    this.camera.x += (newWorldX - worldX) * this.camera.zoom;
                    this.camera.y += (newWorldY - worldY) * this.camera.zoom;
                });

                // Reset mouse state when page loses focus or becomes hidden
                document.addEventListener('visibilitychange', () => {
                    if (document.hidden) {
                        this.mouse.down = false;
                        this.mouse.rightDown = false;
                        if (this.selectedNode) {
                            delete this.selectedNode.fx;
                            delete this.selectedNode.fy;
                            if (this.layoutType === '3d') {
                                delete this.selectedNode.fz;
                            }
                            this.selectedNode = null;
                        }
                    }
                });

                // Reset on window blur (losing focus)
                window.addEventListener('blur', () => {
                    this.mouse.down = false;
                    this.mouse.rightDown = false;
                    if (this.selectedNode) {
                        delete this.selectedNode.fx;
                        delete this.selectedNode.fy;
                        if (this.layoutType === '3d') {
                            delete this.selectedNode.fz;
                        }
                        this.selectedNode = null;
                    }
                });

                // ESC key to release any stuck states
                document.addEventListener('keydown', (e) => {
                    if (e.key === 'Escape') {
                        this.mouse.down = false;
                        this.mouse.rightDown = false;
                        if (this.selectedNode) {
                            delete this.selectedNode.fx;
                            delete this.selectedNode.fy;
                            if (this.layoutType === '3d') {
                                delete this.selectedNode.fz;
                            }
                            this.selectedNode = null;
                        }
                    }
                });

                // Keyboard controls for 3D
                document.addEventListener('keydown', (e) => {
                    if (this.layoutType !== '3d') return;

                    // Camera rotation with arrow keys (when no node selected)
                    if (!this.selectedNode) {
                        if (e.key === 'ArrowLeft') {
                            e.preventDefault();
                            this.rotation.y -= 0.1; // Rotate left
                        } else if (e.key === 'ArrowRight') {
                            e.preventDefault();
                            this.rotation.y += 0.1; // Rotate right
                        } else if (e.key === 'ArrowUp' && !e.shiftKey) {
                            e.preventDefault();
                            this.rotation.x -= 0.1; // Rotate up
                            this.rotation.x = Math.max(-Math.PI / 2, this.rotation.x);
                        } else if (e.key === 'ArrowDown' && !e.shiftKey) {
                            e.preventDefault();
                            this.rotation.x += 0.1; // Rotate down
                            this.rotation.x = Math.min(Math.PI / 2, this.rotation.x);
                        } else if (e.key === 'r' || e.key === 'R') {
                            e.preventDefault();
                            // Reset rotation
                            this.rotation.x = 0;
                            this.rotation.y = 0;
                        }
                    } else {
                        // Node z-axis movement when node is selected
                        if (e.key === 'PageUp' || e.key === 'ArrowUp' && e.shiftKey) {
                            e.preventDefault();
                            // Move node towards viewer (increase z)
                            this.selectedNode.z = (this.selectedNode.z || 0) + 20;
                            this.selectedNode.z = Math.min(500, this.selectedNode.z);
                            if (this.mouse.down) {
                                this.selectedNode.fz = this.selectedNode.z;
                            }
                        } else if (e.key === 'PageDown' || e.key === 'ArrowDown' && e.shiftKey) {
                            e.preventDefault();
                            // Move node away from viewer (decrease z)
                            this.selectedNode.z = (this.selectedNode.z || 0) - 20;
                            this.selectedNode.z = Math.max(-500, this.selectedNode.z);
                            if (this.mouse.down) {
                                this.selectedNode.fz = this.selectedNode.z;
                            }
                        }
                    }
                });
            }

            showTooltip(e) {
                const tooltip = document.getElementById('tooltip');

                // Don't update tooltip if it's locked
                if (this.tooltipLocked) {
                    if (this.lockedNode) {
                        const content = `
                            <button class="tooltip-close" id="tooltipClose">✕</button>
                            <div class="tooltip-header">${this.lockedNode.ip}</div>
                            <div class="tooltip-row">
                                <span class="tooltip-label">Packets:</span>
                                <span class="tooltip-value">${this.lockedNode.packetsSent + this.lockedNode.packetsReceived}</span>
                            </div>
                            <div class="tooltip-row">
                                <span class="tooltip-label">Data:</span>
                                <span class="tooltip-value">${((this.lockedNode.bytesSent + this.lockedNode.bytesReceived) / 1024).toFixed(2)} KB</span>
                            </div>
                            <div class="tooltip-row">
                                <span class="tooltip-label">Connections:</span>
                                <span class="tooltip-value">${this.lockedNode.connections.size}</span>
                            </div>
                            <div class="tooltip-row">
                                <span class="tooltip-label">Protocols:</span>
                                <span class="tooltip-value">${Array.from(this.lockedNode.protocols).join(', ')}</span>
                            </div>
                        `;
                        tooltip.innerHTML = content;

                        // Re-attach close button event
                        const closeBtn = document.getElementById('tooltipClose');
                        if (closeBtn) {
                            closeBtn.onclick = () => {
                                this.tooltipLocked = false;
                                this.lockedNode = null;
                                tooltip.classList.remove('active', 'locked');
                                // Hide packet data section
                                document.getElementById('packetDataSection').style.display = 'none';
                            };
                        }
                    }
                    return;
                }

                const rect = this.canvas.getBoundingClientRect();
                const x = (e.clientX - rect.left - this.camera.x) / this.camera.zoom;
                const y = (e.clientY - rect.top - this.camera.y) / this.camera.zoom;

                let hoveredNode = null;
                this.nodes.forEach(node => {
                    const dx = x - node.x;
                    const dy = y - node.y;
                    if (Math.sqrt(dx * dx + dy * dy) < node.radius) {
                        hoveredNode = node;
                    }
                });

                if (hoveredNode) {
                    const zInfo = this.layoutType === '3d'
                        ? `<div class="tooltip-row">
                               <span class="tooltip-label">Z-Depth:</span>
                               <span class="tooltip-value">${(hoveredNode.z || 0).toFixed(0)}</span>
                           </div>`
                        : '';

                    tooltip.innerHTML = `
                        <button class="tooltip-close" id="tooltipClose">✕</button>
                        <div class="tooltip-header">${hoveredNode.ip}</div>
                        <div class="tooltip-row">
                            <span class="tooltip-label">Packets:</span>
                            <span class="tooltip-value">${hoveredNode.packetsSent + hoveredNode.packetsReceived}</span>
                        </div>
                        <div class="tooltip-row">
                            <span class="tooltip-label">Data:</span>
                            <span class="tooltip-value">${((hoveredNode.bytesSent + hoveredNode.bytesReceived) / 1024).toFixed(2)} KB</span>
                        </div>
                        <div class="tooltip-row">
                            <span class="tooltip-label">Connections:</span>
                            <span class="tooltip-value">${hoveredNode.connections.size}</span>
                        </div>
                        <div class="tooltip-row">
                            <span class="tooltip-label">Protocols:</span>
                            <span class="tooltip-value">${Array.from(hoveredNode.protocols).join(', ')}</span>
                        </div>
                        ${zInfo}
                    `;
                    // Position tooltip closer to cursor with boundary checks
                    const tooltipOffset = 8; // Reduced from 10 to 8 pixels
                    let tooltipX = e.clientX + tooltipOffset;
                    let tooltipY = e.clientY + tooltipOffset;

                    // Get tooltip dimensions (approximate or measure after render)
                    const tooltipWidth = 250; // Approximate width
                    const tooltipHeight = 200; // Approximate height
                    const windowWidth = window.innerWidth;
                    const windowHeight = window.innerHeight;

                    // Keep tooltip within viewport bounds
                    if (tooltipX + tooltipWidth > windowWidth) {
                        tooltipX = e.clientX - tooltipWidth - tooltipOffset; // Show on left side
                    }
                    if (tooltipY + tooltipHeight > windowHeight) {
                        tooltipY = e.clientY - tooltipHeight - tooltipOffset; // Show above cursor
                    }

                    tooltip.style.left = tooltipX + 'px';
                    tooltip.style.top = tooltipY + 'px';
                    tooltip.classList.add('active');
                } else {
                    tooltip.classList.remove('active');
                }
            }

            loadData(parser) {
                this.nodes.clear();
                this.edges = [];

                // Dispatch event when data is loaded
                const dispatchUpdate = () => {
                    window.dispatchEvent(new Event('visualizerUpdated'));
                };
                this.particles = [];

                // Store packets if available
                if (parser.packets) {
                    this.allPackets = parser.packets;
                    const withData = this.allPackets.filter(p => p.data && p.data.length > 0).length;
                    console.log(`[Visualizer] Loaded ${this.allPackets.length} packets (${withData} with data)`);
                    if (this.allPackets.length > 0 && this.allPackets[0].data) {
                        console.log(`[Visualizer] First packet data type:`, Array.isArray(this.allPackets[0].data) ? 'Array' : typeof this.allPackets[0].data);
                        console.log(`[Visualizer] First packet data sample:`, this.allPackets[0].data.slice(0, 20));
                    }
                }

                // Create nodes
                parser.hosts.forEach(host => {
                    const node = {
                        ...host,
                        x: Math.random() * this.canvas.width / window.devicePixelRatio,
                        y: Math.random() * this.canvas.height / window.devicePixelRatio,
                        vx: 0,
                        vy: 0,
                        radius: Math.min(30, 10 + Math.sqrt(host.packetsSent + host.packetsReceived) * 2),
                        lastActivity: Date.now(), // Initialize with current time for static files
                        attentionScore: 0
                    };
                    this.nodes.set(host.ip, node);
                });

                // Create edges
                parser.connections.forEach(conn => {
                    const source = this.nodes.get(conn.source);
                    const target = this.nodes.get(conn.destination);
                    if (source && target) {
                        this.edges.push({
                            source,
                            target,
                            protocol: conn.protocol,
                            packets: conn.packets,
                            bytes: conn.bytes
                        });
                    }
                });

                // Apply layout
                this.applyLayout();

                // Dispatch update event
                setTimeout(() => dispatchUpdate(), 100);
            }

            distanceToLineSegment(px, py, x1, y1, x2, y2) {
                const dx = x2 - x1;
                const dy = y2 - y1;
                const lengthSquared = dx * dx + dy * dy;

                if (lengthSquared === 0) {
                    return Math.sqrt((px - x1) * (px - x1) + (py - y1) * (py - y1));
                }

                let t = ((px - x1) * dx + (py - y1) * dy) / lengthSquared;
                t = Math.max(0, Math.min(1, t));

                const projX = x1 + t * dx;
                const projY = y1 + t * dy;

                return Math.sqrt((px - projX) * (px - projX) + (py - projY) * (py - projY));
            }

            showPacketDetails(packet, highlightText = null) {
                const dashboard = document.getElementById('nodeDashboard');
                const title = document.getElementById('dashboardTitle');
                const stats = document.getElementById('dashboardStats');
                const connections = document.getElementById('dashboardConnections');
                const packetsDiv = document.getElementById('dashboardPackets');

                // Set title
                title.textContent = `Packet Details`;

                // Show packet statistics
                stats.innerHTML = `
                    <div class="dashboard-stat">
                        <span class="dashboard-stat-label">Protocol</span>
                        <span class="dashboard-stat-value">${packet.protocol || 'Unknown'}</span>
                    </div>
                    <div class="dashboard-stat">
                        <span class="dashboard-stat-label">Length</span>
                        <span class="dashboard-stat-value">${packet.length} bytes</span>
                    </div>
                    <div class="dashboard-stat">
                        <span class="dashboard-stat-label">Timestamp</span>
                        <span class="dashboard-stat-value">${packet.timestamp.toFixed(6)}s</span>
                    </div>
                `;

                // Show connection details
                connections.innerHTML = `
                    <div class="dashboard-stat">
                        <span class="dashboard-stat-label">Source</span>
                        <span class="dashboard-stat-value">${packet.source}${packet.srcPort ? ':' + packet.srcPort : ''}</span>
                    </div>
                    <div class="dashboard-stat">
                        <span class="dashboard-stat-label">Destination</span>
                        <span class="dashboard-stat-value">${packet.destination}${packet.dstPort ? ':' + packet.dstPort : ''}</span>
                    </div>
                    ${packet.flags ? `
                    <div class="dashboard-stat">
                        <span class="dashboard-stat-label">TCP Flags</span>
                        <span class="dashboard-stat-value">0x${packet.flags.toString(16)}</span>
                    </div>
                    ` : ''}
                `;

                // Show packet data
                if (packet.data && packet.data.length > 0) {
                    const isDarkMode = document.body.classList.contains('dark-mode');
                    const textColor = isDarkMode ? '#e0e0e0' : '#333';

                    // Extract ASCII text
                    let asciiText = '';
                    for (let i = 0; i < packet.data.length; i++) {
                        const byte = packet.data[i];
                        if (byte >= 32 && byte <= 126) {
                            asciiText += String.fromCharCode(byte);
                        } else if (byte === 10) {
                            asciiText += '\n';
                        } else if (byte === 13) {
                            asciiText += '';
                        } else {
                            asciiText += '.';
                        }
                    }

                    // Highlight search text if provided
                    let displayText = asciiText;
                    if (highlightText) {
                        const regex = new RegExp(`(${highlightText})`, 'gi');
                        displayText = asciiText.replace(regex, '<mark style="background: #ffff00; color: #000;">$1</mark>');
                    }

                    packetsDiv.innerHTML = `
                        <div style="font-family: monospace; font-size: 12px; line-height: 1.5;">
                            <div style="margin-bottom: 12px; color: #0099ff; font-weight: 600;">Packet Payload (ASCII)</div>
                            <div style="padding: 12px; background: rgba(0,150,255,0.03); border: 1px solid rgba(0,150,255,0.2); border-radius: 4px; max-height: 400px; overflow-y: auto;">
                                <pre style="margin: 0; white-space: pre-wrap; word-wrap: break-word; color: ${textColor}; font-size: 11px;">${displayText}</pre>
                            </div>
                        </div>
                    `;
                } else {
                    packetsDiv.innerHTML = '<div style="color: #666; text-align: center; padding: 20px;">No packet data available</div>';
                }

                // Show dashboard
                dashboard.classList.add('active');
            }

            showEdgePackets(edge) {
                const dashboard = document.getElementById('nodeDashboard');
                const title = document.getElementById('dashboardTitle');
                const stats = document.getElementById('dashboardStats');
                const connections = document.getElementById('dashboardConnections');
                const packets = document.getElementById('dashboardPackets');

                // Set title for edge
                title.textContent = `Connection: ${edge.source.ip} → ${edge.target.ip}`;

                // Show edge statistics
                // Handle edge.packets which could be a number or an array
                const packetCount = Array.isArray(edge.packets) ? edge.packets.length : (edge.packets || 0);
                const totalBytes = edge.bytes || 0;

                stats.innerHTML = `
                    <div class="dashboard-stat">
                        <span class="dashboard-stat-label">Protocol</span>
                        <span class="dashboard-stat-value">${edge.protocol || 'Unknown'}</span>
                    </div>
                    <div class="dashboard-stat">
                        <span class="dashboard-stat-label">Total Packets</span>
                        <span class="dashboard-stat-value">${packetCount.toLocaleString()}</span>
                    </div>
                    <div class="dashboard-stat">
                        <span class="dashboard-stat-label">Total Bytes</span>
                        <span class="dashboard-stat-value">${(totalBytes / 1024).toFixed(2)} KB</span>
                    </div>
                `;

                // Show connection details
                const avgPacketSize = packetCount > 0 ? Math.round(totalBytes / packetCount) : 0;

                connections.innerHTML = `
                    <div class="dashboard-stat">
                        <span class="dashboard-stat-label">Source</span>
                        <span class="dashboard-stat-value">${edge.source.ip}</span>
                    </div>
                    <div class="dashboard-stat">
                        <span class="dashboard-stat-label">Destination</span>
                        <span class="dashboard-stat-value">${edge.target.ip}</span>
                    </div>
                    <div class="dashboard-stat">
                        <span class="dashboard-stat-label">Avg Packet Size</span>
                        <span class="dashboard-stat-value">${avgPacketSize} bytes</span>
                    </div>
                `;

                // Filter packets for this specific connection
                const edgePackets = this.allPackets.filter(p =>
                    (p.source === edge.source.ip && p.destination === edge.target.ip) ||
                    (p.source === edge.target.ip && p.destination === edge.source.ip)
                );

                if (edgePackets.length === 0) {
                    packets.innerHTML = '<div style="color: #666; text-align: center; padding: 20px;">No packet data available for this connection</div>';
                } else {
                    // List of protocols that should show stream view
                    const streamProtocols = [
                        'TCP', 'HTTP', 'HTTPS', 'HTTP-ALT', 'HTTPS-ALT',
                        'SSH', 'TELNET', 'RDP', 'VNC',
                        'FTP', 'FTP-DATA', 'TFTP', 'SMB', 'NetBIOS',
                        'SMTP', 'SMTP-SUBMISSION', 'POP3', 'IMAP', 'IMAPS', 'POP3S',
                        'MySQL', 'PostgreSQL', 'MSSQL', 'MongoDB', 'Redis',
                        'SQUID', 'HTTP-PROXY', 'HTTP-DEV'
                    ];

                    // For TCP-based protocols, show full conversation stream
                    if (edge.protocol && streamProtocols.includes(edge.protocol)) {
                        // Concatenate all payload data into a single stream
                        let fullStreamData = [];

                        edgePackets.forEach((packet) => {
                            if (packet.data && packet.data.length > 0) {
                                // Extract payload (skip headers - typically first 54 bytes for TCP/IP)
                                const headerSize = 54;
                                const payloadData = packet.data.slice(headerSize);

                                // Only include packets with actual payload
                                if (payloadData.length > 0) {
                                    fullStreamData.push(...payloadData);
                                }
                            }
                        });

                        // Convert to readable ASCII, preserving newlines
                        const streamText = fullStreamData.map(b => {
                            if (b === 10) return '\n';  // Newline
                            if (b === 13) return '';     // Carriage return (ignore)
                            if (b === 9) return '\t';    // Tab
                            if (b >= 32 && b <= 126) return String.fromCharCode(b);
                            return '';  // Skip other non-printable chars
                        }).join('');

                        const isDarkMode = document.body.classList.contains('dark-mode');
                        const textColor = isDarkMode ? '#e0e0e0' : '#333';

                        let conversationHtml = '<div style="font-family: monospace; font-size: 12px; line-height: 1.5;">';
                        const streamProtocol = edge.protocol || 'TCP';
                        conversationHtml += `<div style="margin-bottom: 12px; color: #0099ff; font-weight: 600;">${streamProtocol} Stream Data (${edgePackets.length} packets concatenated)</div>`;
                        conversationHtml += `
                            <div style="padding: 12px; background: rgba(0,150,255,0.03); border: 1px solid rgba(0,150,255,0.2); border-radius: 4px;">
                                <pre style="margin: 0; white-space: pre-wrap; word-wrap: break-word; color: ${textColor}; font-size: 11px;">${streamText || '<i>No readable text data in stream</i>'}</pre>
                            </div>
                        `;
                        conversationHtml += '</div>';
                        packets.innerHTML = conversationHtml;
                    } else {
                        // For non-TCP, show individual packets
                        let packetsHtml = '';
                        edgePackets.slice(0, 20).forEach((packet, idx) => {
                            const direction = packet.source === edge.source.ip ? '→' : '←';
                            const flagsStr = packet.flags ? ` | Flags: 0x${packet.flags.toString(16)}` : '';
                            const packetId = `packet-${Date.now()}-${idx}`;

                            packetsHtml += `
                                <div class="packet-item" data-packet-id="${packetId}" onclick="togglePacketData('${packetId}', ${idx})">
                                    <div class="packet-header">Packet #${idx + 1} ${direction}</div>
                                    <div class="packet-detail">
                                        ${packet.source} → ${packet.destination}<br>
                                        Protocol: ${packet.protocol || 'Unknown'} |
                                        Length: ${packet.length} bytes<br>
                                        ${packet.srcPort ? `Src Port: ${packet.srcPort} | ` : ''}
                                        ${packet.dstPort ? `Dst Port: ${packet.dstPort}${flagsStr}<br>` : flagsStr ? flagsStr + '<br>' : ''}
                                        Timestamp: ${packet.timestamp.toFixed(6)}s
                                    </div>
                                    <div class="packet-data-expanded" id="${packetId}-data" style="display: none;"></div>
                                </div>
                            `;
                        });
                        packets.innerHTML = packetsHtml;
                    }

                    // Store packets for later access
                    window.currentNodePackets = edgePackets;
                }

                // Show dashboard
                dashboard.classList.add('active');
            }

            showNodeDashboard(node) {
                const dashboard = document.getElementById('nodeDashboard');
                const title = document.getElementById('dashboardTitle');
                const stats = document.getElementById('dashboardStats');
                const connections = document.getElementById('dashboardConnections');
                const packets = document.getElementById('dashboardPackets');

                // Set title with indicator showing this is source view
                title.innerHTML = `📤 ${node.ip} <span style="font-size: 12px; opacity: 0.7; font-weight: normal;">(Source Node)</span>`;

                // Populate statistics
                const totalPackets = node.packetsSent + node.packetsReceived;
                const totalBytes = node.bytesSent + node.bytesReceived;
                stats.innerHTML = `
                    <div class="dashboard-stat">
                        <span class="dashboard-stat-label">Total Packets</span>
                        <span class="dashboard-stat-value">${totalPackets.toLocaleString()}</span>
                    </div>
                    <div class="dashboard-stat">
                        <span class="dashboard-stat-label">Packets Sent</span>
                        <span class="dashboard-stat-value">${node.packetsSent.toLocaleString()}</span>
                    </div>
                    <div class="dashboard-stat">
                        <span class="dashboard-stat-label">Packets Received</span>
                        <span class="dashboard-stat-value">${node.packetsReceived.toLocaleString()}</span>
                    </div>
                    <div class="dashboard-stat">
                        <span class="dashboard-stat-label">Total Data</span>
                        <span class="dashboard-stat-value">${(totalBytes / 1024).toFixed(2)} KB</span>
                    </div>
                    <div class="dashboard-stat">
                        <span class="dashboard-stat-label">Data Sent</span>
                        <span class="dashboard-stat-value">${(node.bytesSent / 1024).toFixed(2)} KB</span>
                    </div>
                    <div class="dashboard-stat">
                        <span class="dashboard-stat-label">Data Received</span>
                        <span class="dashboard-stat-value">${(node.bytesReceived / 1024).toFixed(2)} KB</span>
                    </div>
                `;

                // Populate connections
                const portsList = Array.from(node.ports).slice(0, 10).join(', ') || 'None';
                const protocolsList = Array.from(node.protocols).join(', ') || 'None';

                // Get source ports (ports used when this node is sending)
                const sourcePorts = new Set();
                this.allPackets.filter(p => p.source === node.ip && p.srcPort).forEach(p => sourcePorts.add(p.srcPort));
                const sourcePortsList = Array.from(sourcePorts).sort((a,b) => a-b).slice(0, 10).join(', ') || 'None';

                connections.innerHTML = `
                    <div class="dashboard-stat">
                        <span class="dashboard-stat-label">Total Connections</span>
                        <span class="dashboard-stat-value">${node.connections.size}</span>
                    </div>
                    <div class="dashboard-stat">
                        <span class="dashboard-stat-label">Protocols Used</span>
                        <span class="dashboard-stat-value">${protocolsList}</span>
                    </div>
                    <div class="dashboard-stat">
                        <span class="dashboard-stat-label">Source Ports (Sending)</span>
                        <span class="dashboard-stat-value">${sourcePortsList}</span>
                    </div>
                    <div class="dashboard-stat">
                        <span class="dashboard-stat-label">All Ports Used</span>
                        <span class="dashboard-stat-value">${portsList}</span>
                    </div>
                `;

                // Filter ALL packets FROM this node's source
                const allNodePackets = this.allPackets.filter(p =>
                    p.source === node.ip
                );

                // Show most recent 100 packets (or all if less than 100)
                const nodePackets = allNodePackets.slice(-100).reverse();
                const totalPacketsFromSource = allNodePackets.length;

                if (totalPacketsFromSource === 0) {
                    packets.innerHTML = '<div style="color: #666; text-align: center; padding: 20px;">No packets sent from this source</div>';
                } else {
                    let packetsHtml = `<div style="padding: 10px; background: rgba(0,153,255,0.1); margin-bottom: 10px; border-radius: 4px;">
                        <div style="font-weight: bold; margin-bottom: 5px;">📤 Packets FROM ${node.ip}</div>
                        <div style="font-size: 12px; opacity: 0.8;">Showing most recent ${nodePackets.length} of ${totalPacketsFromSource} total packets sent</div>
                    </div>`;

                    nodePackets.forEach((packet, idx) => {
                        const packetId = `packet-${Date.now()}-${idx}`;
                        packetsHtml += `
                            <div class="packet-item" data-packet-id="${packetId}" onclick="togglePacketData('${packetId}', ${idx})">
                                <div class="packet-header">Packet #${totalPacketsFromSource - idx} (most recent)</div>
                                <div class="packet-detail">
                                    ${packet.source} → ${packet.destination}<br>
                                    Protocol: ${packet.protocol || 'Unknown'} |
                                    Length: ${packet.length} bytes<br>
                                    ${packet.srcPort ? `Src Port: ${packet.srcPort} | ` : ''}
                                    ${packet.dstPort ? `Dst Port: ${packet.dstPort}<br>` : ''}
                                    Timestamp: ${packet.timestamp.toFixed(6)}s
                                </div>
                                <div class="packet-data-expanded" id="${packetId}-data" style="display: none;"></div>
                            </div>
                        `;
                    });
                    packets.innerHTML = packetsHtml;

                    // Store packets for later access
                    window.currentNodePackets = nodePackets;
                }

                // Show dashboard
                dashboard.classList.add('active');
            }

            setLayout(layout) {
                this.layoutType = layout;

                // Show 3D controls help when entering 3D mode
                if (layout === '3d') {
                    this.show3DHelp();
                }

                this.applyLayout();
            }

            show3DHelp() {
                const infoPanel = document.getElementById('infoPanel');
                const existingHelp = document.getElementById('3dHelp');

                // Don't show help if already shown
                if (existingHelp) return;

                const helpDiv = document.createElement('div');
                helpDiv.id = '3dHelp';
                helpDiv.style.cssText = 'margin-top: 12px; padding-top: 12px; border-top: 1px solid #333; font-size: 10px; line-height: 1.5;';
                helpDiv.innerHTML = `
                    <div style="color: #00d4ff; font-weight: 600; margin-bottom: 6px;">🎮 3D Controls</div>
                    <div style="color: #aaa; font-size: 9px;">
                        <strong style="color: #ff9800;">Rotation:</strong><br>
                        • <strong>Right-Click & Drag</strong>: Rotate view<br>
                        • <strong>Arrow Keys</strong>: Rotate camera<br>
                        • <strong>R Key</strong>: Reset rotation<br>
                        <strong style="color: #4caf50; margin-top: 4px; display: block;">Node Movement:</strong><br>
                        • <strong>Click & Drag</strong>: Move node in X/Y<br>
                        • <strong>Mouse Wheel (dragging)</strong>: Move in Z<br>
                        • <strong>PageUp/PageDown</strong>: Move selected node in Z
                    </div>
                `;
                infoPanel.appendChild(helpDiv);

                // Auto-remove help after 15 seconds
                setTimeout(() => {
                    if (helpDiv.parentNode) {
                        helpDiv.style.opacity = '0';
                        helpDiv.style.transition = 'opacity 1s';
                        setTimeout(() => helpDiv.remove(), 1000);
                    }
                }, 15000);
            }

            // Project 3D coordinates to 2D screen space with rotation
            project3D(node) {
                if (this.layoutType !== '3d') {
                    return { x: node.x, y: node.y, scale: 1 };
                }

                // Apply rotation transforms
                let x = node.x || 0;
                let y = node.y || 0;
                let z = node.z || 0;

                // Rotate around Y axis (left/right rotation)
                const cosY = Math.cos(this.rotation.y);
                const sinY = Math.sin(this.rotation.y);
                const x1 = x * cosY - z * sinY;
                const z1 = x * sinY + z * cosY;

                // Rotate around X axis (up/down rotation)
                const cosX = Math.cos(this.rotation.x);
                const sinX = Math.sin(this.rotation.x);
                const y2 = y * cosX - z1 * sinX;
                const z2 = y * sinX + z1 * cosX;

                // Apply perspective projection
                const focalLength = 1000; // Perspective strength
                const zDepth = z2 + focalLength;
                const scale = focalLength / zDepth;

                return {
                    x: x1 * scale,
                    y: y2 * scale,
                    scale: scale,
                    z: z2 // Keep rotated z for depth sorting
                };
            }

            applyLayout() {
                const nodes = Array.from(this.nodes.values());
                const centerX = this.canvas.width / (2 * window.devicePixelRatio);
                const centerY = this.canvas.height / (2 * window.devicePixelRatio);

                if (this.layoutType === 'force') {
                    // Dynamic force-directed layout - no clustering
                    // Reset cluster-specific properties
                    nodes.forEach(node => {
                        node.clusterRole = null;
                        node.subnet = null;
                    });
                    this.clusters.clear();
                    this.clusterPositions.clear();

                    // Run traditional force simulation
                    for (let i = 0; i < 100; i++) {
                        this.simulateForces();
                    }
                } else if (this.layoutType === 'clustered') {
                    // Clustered subnet layout with role-based positioning
                    this.updateClusters();

                    // Position nodes initially at their cluster centers
                    nodes.forEach(node => {
                        if (node.subnet && this.clusterPositions.has(node.subnet)) {
                            const clusterPos = this.clusterPositions.get(node.subnet);
                            // Add some randomness around cluster center
                            node.x = clusterPos.x + (Math.random() - 0.5) * 100;
                            node.y = clusterPos.y + (Math.random() - 0.5) * 100;
                        }
                    });

                    // Run physics to settle into final positions
                    for (let i = 0; i < 150; i++) {
                        this.simulateForces();
                    }
                } else if (this.layoutType === 'clustered-host') {
                    // Clustered host layout based on communication patterns
                    this.updateHostClusters();

                    // Position nodes initially at their cluster centers
                    nodes.forEach(node => {
                        if (node.hostCluster && this.clusterPositions.has(node.hostCluster)) {
                            const clusterPos = this.clusterPositions.get(node.hostCluster);
                            // Add some randomness around cluster center
                            node.x = clusterPos.x + (Math.random() - 0.5) * 100;
                            node.y = clusterPos.y + (Math.random() - 0.5) * 100;
                        }
                    });

                    // Run physics to settle into final positions
                    for (let i = 0; i < 150; i++) {
                        this.simulateForces();
                    }
                } else if (this.layoutType === 'circular') {
                    // Circular layout
                    nodes.forEach(node => {
                        node.clusterRole = null;
                        node.subnet = null;
                    });
                    this.clusters.clear();
                    this.clusterPositions.clear();

                    nodes.forEach((node, i) => {
                        const angle = (i / nodes.length) * Math.PI * 2;
                        const radius = Math.min(centerX, centerY) * 0.8;
                        node.x = centerX + Math.cos(angle) * radius;
                        node.y = centerY + Math.sin(angle) * radius;
                    });
                } else if (this.layoutType === 'hierarchical') {
                    // Hierarchical layout based on connection count
                    nodes.forEach(node => {
                        node.clusterRole = null;
                        node.subnet = null;
                    });
                    this.clusters.clear();
                    this.clusterPositions.clear();

                    nodes.sort((a, b) => b.connections - a.connections);
                    const levels = 5;
                    const levelHeight = this.canvas.height / (levels * window.devicePixelRatio);

                    nodes.forEach((node, i) => {
                        const level = Math.floor(i / (nodes.length / levels));
                        const posInLevel = i % Math.ceil(nodes.length / levels);
                        const levelWidth = this.canvas.width / (Math.ceil(nodes.length / levels) * window.devicePixelRatio);

                        node.x = posInLevel * levelWidth + levelWidth / 2;
                        node.y = level * levelHeight + levelHeight / 2;
                    });
                } else if (this.layoutType === '3d') {
                    // 3D force-directed layout
                    nodes.forEach(node => {
                        node.clusterRole = null;
                        node.subnet = null;
                        // Initialize z coordinate if not present
                        if (node.z === undefined) {
                            node.z = Math.random() * 500 - 250;
                        }
                        if (node.vz === undefined) {
                            node.vz = 0;
                        }
                    });
                    this.clusters.clear();
                    this.clusterPositions.clear();

                    // Run 3D force simulation
                    for (let i = 0; i < 100; i++) {
                        this.simulateForces();
                    }
                }
            }

            getSubnet(ip) {
                // Extract /24 subnet from IP
                const parts = ip.split('.');
                if (parts.length === 4) {
                    return `${parts[0]}.${parts[1]}.${parts[2]}`;
                }
                return 'unknown';
            }

            identifyClusterRole(node) {
                // Identify if a node is a scanner, listener, or regular node
                const connectionRatio = node.packetsSent / Math.max(1, node.packetsReceived);
                const totalConnections = node.connections || 0;

                // Scanner: sends way more than receives, many connections
                if (connectionRatio > 5 && totalConnections > 10) {
                    return 'scanner';
                }
                // Listener: receives way more than sends
                if (connectionRatio < 0.2 && node.packetsReceived > 20) {
                    return 'listener';
                }
                // High-activity hub
                if (totalConnections > 15) {
                    return 'hub';
                }
                return 'regular';
            }

            updateClusters() {
                // Build clusters based on subnets and activity patterns
                this.clusters.clear();
                const nodes = Array.from(this.nodes.values());

                // Group nodes by subnet
                nodes.forEach(node => {
                    const subnet = this.getSubnet(node.ip);
                    if (!this.clusters.has(subnet)) {
                        this.clusters.set(subnet, {
                            subnet: subnet,
                            nodes: [],
                            scanner: null,
                            listener: null,
                            hubs: [],
                            regular: []
                        });
                    }

                    const cluster = this.clusters.get(subnet);
                    cluster.nodes.push(node);

                    // Classify node role
                    const role = this.identifyClusterRole(node);
                    node.clusterRole = role;
                    node.subnet = subnet;

                    if (role === 'scanner' && !cluster.scanner) {
                        cluster.scanner = node;
                    } else if (role === 'listener' && !cluster.listener) {
                        cluster.listener = node;
                    } else if (role === 'hub') {
                        cluster.hubs.push(node);
                    } else {
                        cluster.regular.push(node);
                    }
                });

                // Assign cluster center positions in a grid layout
                const clusterArray = Array.from(this.clusters.values());
                const clusterCount = clusterArray.length;
                const cols = Math.ceil(Math.sqrt(clusterCount));
                const spacing = 800; // Space between cluster centers

                const centerX = this.canvas.width / (2 * window.devicePixelRatio);
                const centerY = this.canvas.height / (2 * window.devicePixelRatio);
                const startX = centerX - ((cols - 1) * spacing) / 2;
                const startY = centerY - ((Math.ceil(clusterCount / cols) - 1) * spacing) / 2;

                clusterArray.forEach((cluster, idx) => {
                    const col = idx % cols;
                    const row = Math.floor(idx / cols);
                    const x = startX + col * spacing;
                    const y = startY + row * spacing;

                    this.clusterPositions.set(cluster.subnet, { x, y });
                });
            }

            updateHostClusters() {
                // Build clusters based on communication patterns (who talks to whom)
                this.clusters.clear();
                const nodes = Array.from(this.nodes.values());

                // Find heavy traffic nodes (scanners, servers, etc.)
                const heavyNodes = nodes.filter(node => {
                    const totalTraffic = node.packetsSent + node.packetsReceived;
                    const connections = node.connections || 0;
                    return totalTraffic > 50 || connections > 10;
                }).sort((a, b) => {
                    const aScore = (a.packetsSent + a.packetsReceived) + (a.connections || 0) * 10;
                    const bScore = (b.packetsSent + b.packetsReceived) + (b.connections || 0) * 10;
                    return bScore - aScore;
                });

                // Assign each heavy node as a cluster center
                const assignedNodes = new Set();
                const hostClusters = [];

                heavyNodes.forEach((heavyNode, idx) => {
                    if (assignedNodes.has(heavyNode.ip)) return;

                    const cluster = {
                        id: `host-${idx}`,
                        centerNode: heavyNode,
                        nodes: [heavyNode],
                        connectedNodes: []
                    };

                    assignedNodes.add(heavyNode.ip);

                    // Find all nodes this heavy node communicates with
                    this.edges.forEach(edge => {
                        let targetNode = null;

                        if (edge.source === heavyNode && !assignedNodes.has(edge.target.ip)) {
                            targetNode = edge.target;
                        } else if (edge.target === heavyNode && !assignedNodes.has(edge.source.ip)) {
                            targetNode = edge.source;
                        }

                        if (targetNode) {
                            cluster.connectedNodes.push(targetNode);
                            assignedNodes.add(targetNode.ip);
                        }
                    });

                    // Mark nodes with their cluster role
                    heavyNode.clusterRole = 'center';
                    heavyNode.hostCluster = cluster.id;

                    cluster.connectedNodes.forEach(node => {
                        node.clusterRole = 'satellite';
                        node.hostCluster = cluster.id;
                        cluster.nodes.push(node);
                    });

                    hostClusters.push(cluster);
                    this.clusters.set(cluster.id, cluster);
                });

                // Handle remaining unassigned nodes (group them together)
                const unassignedNodes = nodes.filter(node => !assignedNodes.has(node.ip));
                if (unassignedNodes.length > 0) {
                    const miscCluster = {
                        id: 'misc',
                        centerNode: null,
                        nodes: unassignedNodes,
                        connectedNodes: []
                    };

                    unassignedNodes.forEach(node => {
                        node.clusterRole = 'misc';
                        node.hostCluster = 'misc';
                    });

                    hostClusters.push(miscCluster);
                    this.clusters.set('misc', miscCluster);
                }

                // Position clusters in a grid
                const clusterCount = hostClusters.length;
                const cols = Math.ceil(Math.sqrt(clusterCount));
                const spacing = 600; // Space between cluster centers

                const centerX = this.canvas.width / (2 * window.devicePixelRatio);
                const centerY = this.canvas.height / (2 * window.devicePixelRatio);
                const startX = centerX - ((cols - 1) * spacing) / 2;
                const startY = centerY - ((Math.ceil(clusterCount / cols) - 1) * spacing) / 2;

                hostClusters.forEach((cluster, idx) => {
                    const col = idx % cols;
                    const row = Math.floor(idx / cols);
                    const x = startX + col * spacing;
                    const y = startY + row * spacing;

                    this.clusterPositions.set(cluster.id, { x, y });
                });
            }

            simulateForces() {
                const nodes = Array.from(this.nodes.values());
                const nodeCount = nodes.length;

                // Update clusters periodically (every 60 frames = ~1 second) - ONLY in clustered modes
                if (this.layoutType === 'clustered' || this.layoutType === 'clustered-host') {
                    if (!this._clusterUpdateCounter) this._clusterUpdateCounter = 0;
                    this._clusterUpdateCounter++;
                    if (this._clusterUpdateCounter % 60 === 0 || this.clusters.size === 0) {
                        if (this.layoutType === 'clustered') {
                            this.updateClusters();
                        } else if (this.layoutType === 'clustered-host') {
                            this.updateHostClusters();
                        }
                    }
                }

                // Very aggressive dampening for large subnet scans (hundreds to thousands of nodes)
                const alpha = Math.max(0.02, 0.06 * Math.pow(0.92, nodeCount / 10));
                const repulsionStrength = Math.max(0.2, 0.45 * Math.pow(0.85, nodeCount / 15));
                const clusterAttractionStrength = 0.05; // Pull nodes toward their cluster center
                const damping = Math.min(0.96, 0.90 + nodeCount / 1000); // Heavy damping for stability
                const maxVelocity = Math.max(3, 12 - nodeCount / 30); // Tighter velocity cap

                const centerX = this.canvas.width / (2 * window.devicePixelRatio);
                const centerY = this.canvas.height / (2 * window.devicePixelRatio);

                // For large graphs, use spatial hashing to optimize repulsion calculations
                const useSpatialHash = nodeCount > 50; // Enable earlier for better performance
                let spatialGrid = null;
                const cellSize = 250; // Larger cells for better clustering

                if (useSpatialHash) {
                    // Build spatial hash grid
                    spatialGrid = new Map();
                    nodes.forEach(node => {
                        const cellX = Math.floor(node.x / cellSize);
                        const cellY = Math.floor(node.y / cellSize);
                        const key = `${cellX},${cellY}`;
                        if (!spatialGrid.has(key)) {
                            spatialGrid.set(key, []);
                        }
                        spatialGrid.get(key).push(node);
                        node._cellX = cellX;
                        node._cellY = cellY;
                    });
                }

                // Apply forces
                nodes.forEach(node => {
                    if (!node.fx) {
                        // Initialize velocity if not present
                        if (node.vx === undefined) node.vx = 0;
                        if (node.vy === undefined) node.vy = 0;
                        if (this.layoutType === '3d') {
                            if (node.vz === undefined) node.vz = 0;
                            if (node.z === undefined) node.z = Math.random() * 500 - 250;
                        }

                        // Repulsion between nodes (optimized with spatial hashing)
                        if (useSpatialHash) {
                            // Only check nearby cells (for large graphs, reduce search radius)
                            const searchRadius = nodeCount > 200 ? 1 : 1; // Can be reduced further for huge graphs
                            for (let dx = -searchRadius; dx <= searchRadius; dx++) {
                                for (let dy = -searchRadius; dy <= searchRadius; dy++) {
                                    const key = `${node._cellX + dx},${node._cellY + dy}`;
                                    const nearbyNodes = spatialGrid.get(key);
                                    if (nearbyNodes) {
                                        // Limit number of repulsion calculations per node for stability
                                        const maxRepulsionChecks = Math.max(10, 50 - nodeCount / 10);
                                        let checksPerformed = 0;

                                        for (let i = 0; i < nearbyNodes.length && checksPerformed < maxRepulsionChecks; i++) {
                                            const other = nearbyNodes[i];
                                            if (node !== other) {
                                                const dx = node.x - other.x;
                                                const dy = node.y - other.y;
                                                const dz = this.layoutType === '3d' ? (node.z - other.z) : 0;
                                                const distSq = dx * dx + dy * dy + dz * dz;

                                                // Different repulsion based on cluster membership (only in clustered mode)
                                                let minDist = Math.max(80, 150 - nodeCount / 5);
                                                let clusterMultiplier = 1.0;

                                                if (this.layoutType === 'clustered' && node.subnet && other.subnet) {
                                                    const sameCluster = node.subnet === other.subnet;
                                                    minDist = sameCluster
                                                        ? Math.max(70, 130 - nodeCount / 8)  // Closer in same cluster
                                                        : Math.max(80, 150 - nodeCount / 5); // Farther from other clusters
                                                    clusterMultiplier = sameCluster ? 1.0 : 0.5; // Less repulsion between clusters
                                                }

                                                if (distSq > 0 && distSq < minDist * minDist) {
                                                    const dist = Math.sqrt(distSq);
                                                    const force = (minDist - dist) / dist * alpha * repulsionStrength * clusterMultiplier;
                                                    node.vx += dx * force;
                                                    node.vy += dy * force;
                                                    if (this.layoutType === '3d') {
                                                        node.vz += dz * force;
                                                    }
                                                }
                                                checksPerformed++;
                                            }
                                        }
                                    }
                                }
                            }
                        } else {
                            // For small graphs, use brute force
                            nodes.forEach(other => {
                                if (node !== other) {
                                    const dx = node.x - other.x;
                                    const dy = node.y - other.y;
                                    const dz = this.layoutType === '3d' ? (node.z - other.z) : 0;
                                    const distSq = dx * dx + dy * dy + dz * dz;
                                    const minDist = 150;

                                    if (distSq > 0 && distSq < minDist * minDist) {
                                        const dist = Math.sqrt(distSq);
                                        const force = (minDist - dist) / dist * alpha * repulsionStrength;
                                        node.vx += dx * force;
                                        node.vy += dy * force;
                                        if (this.layoutType === '3d') {
                                            node.vz += dz * force;
                                        }
                                    }
                                }
                            });
                        }

                        // Apply center/cluster forces based on layout type
                        if (this.layoutType === 'clustered' && node.subnet && this.clusterPositions.has(node.subnet)) {
                            // Subnet cluster positioning
                            const clusterPos = this.clusterPositions.get(node.subnet);
                            const targetX = clusterPos.x;
                            const targetY = clusterPos.y;

                            // Position nodes within cluster based on role
                            if (node.clusterRole === 'scanner' || node.clusterRole === 'listener') {
                                // Primary nodes stay at cluster center
                                node.vx += (targetX - node.x) * clusterAttractionStrength * 1.5;
                                node.vy += (targetY - node.y) * clusterAttractionStrength * 1.5;
                            } else if (node.clusterRole === 'hub') {
                                // Hubs orbit around the center at medium distance
                                const angle = (this._clusterUpdateCounter || 0) * 0.01 + node.ip.charCodeAt(node.ip.length - 1);
                                const orbitRadius = 150;
                                const orbitX = targetX + Math.cos(angle) * orbitRadius;
                                const orbitY = targetY + Math.sin(angle) * orbitRadius;
                                node.vx += (orbitX - node.x) * clusterAttractionStrength;
                                node.vy += (orbitY - node.y) * clusterAttractionStrength;
                            } else {
                                // Regular nodes distribute around cluster center
                                node.vx += (targetX - node.x) * clusterAttractionStrength * 0.8;
                                node.vy += (targetY - node.y) * clusterAttractionStrength * 0.8;
                            }
                        } else if (this.layoutType === 'clustered-host' && node.hostCluster && this.clusterPositions.has(node.hostCluster)) {
                            // Host cluster positioning
                            const clusterPos = this.clusterPositions.get(node.hostCluster);
                            const targetX = clusterPos.x;
                            const targetY = clusterPos.y;

                            if (node.clusterRole === 'center') {
                                // Center node stays at cluster position
                                node.vx += (targetX - node.x) * clusterAttractionStrength * 2.0;
                                node.vy += (targetY - node.y) * clusterAttractionStrength * 2.0;
                            } else if (node.clusterRole === 'satellite') {
                                // Satellite nodes orbit around the center
                                node.vx += (targetX - node.x) * clusterAttractionStrength * 0.6;
                                node.vy += (targetY - node.y) * clusterAttractionStrength * 0.6;
                            } else {
                                // Misc nodes
                                node.vx += (targetX - node.x) * clusterAttractionStrength * 0.5;
                                node.vy += (targetY - node.y) * clusterAttractionStrength * 0.5;
                            }
                        } else {
                            // Standard force-directed layout: attract to global center
                            if (this.layoutType === '3d') {
                                const distFromCenter = Math.sqrt((node.x - centerX) ** 2 + (node.y - centerY) ** 2 + (node.z || 0) ** 2);
                                const centerStrength = 0.01 * (1 + distFromCenter / 1500);
                                node.vx += (centerX - node.x) * centerStrength;
                                node.vy += (centerY - node.y) * centerStrength;
                                node.vz += (0 - (node.z || 0)) * centerStrength;
                            } else {
                                const distFromCenter = Math.sqrt((node.x - centerX) ** 2 + (node.y - centerY) ** 2);
                                const centerStrength = 0.01 * (1 + distFromCenter / 1500);
                                node.vx += (centerX - node.x) * centerStrength;
                                node.vy += (centerY - node.y) * centerStrength;
                            }
                        }

                        // Apply damping
                        node.vx *= damping;
                        node.vy *= damping;
                        if (this.layoutType === '3d') {
                            node.vz *= damping;
                        }

                        // Additional stability: detect and dampen oscillation
                        if (node._prevVx !== undefined) {
                            // If velocity reversed direction, apply extra damping
                            if ((node.vx * node._prevVx < 0) || (node.vy * node._prevVy < 0)) {
                                node.vx *= 0.7; // Extra damping on oscillation
                                node.vy *= 0.7;
                            }
                            if (this.layoutType === '3d' && node._prevVz !== undefined && (node.vz * node._prevVz < 0)) {
                                node.vz *= 0.7;
                            }
                        }
                        node._prevVx = node.vx;
                        node._prevVy = node.vy;
                        if (this.layoutType === '3d') {
                            node._prevVz = node.vz;
                        }

                        // Clamp velocity to prevent explosion
                        if (this.layoutType === '3d') {
                            const velocityMagnitude = Math.sqrt(node.vx * node.vx + node.vy * node.vy + node.vz * node.vz);
                            if (velocityMagnitude > maxVelocity) {
                                node.vx = (node.vx / velocityMagnitude) * maxVelocity;
                                node.vy = (node.vy / velocityMagnitude) * maxVelocity;
                                node.vz = (node.vz / velocityMagnitude) * maxVelocity;
                            }
                        } else {
                            const velocityMagnitude = Math.sqrt(node.vx * node.vx + node.vy * node.vy);
                            if (velocityMagnitude > maxVelocity) {
                                node.vx = (node.vx / velocityMagnitude) * maxVelocity;
                                node.vy = (node.vy / velocityMagnitude) * maxVelocity;
                            }
                        }

                        // Update position
                        node.x += node.vx;
                        node.y += node.vy;
                        if (this.layoutType === '3d') {
                            node.z += node.vz;
                        }

                        // Boundary containment (soft limits to keep graph visible)
                        const maxDistance = 3000;
                        if (Math.abs(node.x - centerX) > maxDistance) {
                            node.x = centerX + Math.sign(node.x - centerX) * maxDistance;
                            node.vx *= -0.5; // Bounce back gently
                        }
                        if (Math.abs(node.y - centerY) > maxDistance) {
                            node.y = centerY + Math.sign(node.y - centerY) * maxDistance;
                            node.vy *= -0.5;
                        }
                        if (this.layoutType === '3d') {
                            const maxZDistance = 500;
                            if (Math.abs(node.z) > maxZDistance) {
                                node.z = Math.sign(node.z) * maxZDistance;
                                node.vz *= -0.5;
                            }
                        }
                    }
                });

                // Attraction along edges (with adaptive strength - heavily reduced for large scans)
                const edgeStrength = Math.max(0.02, 0.08 * Math.pow(0.9, nodeCount / 15));
                const edgeLimit = nodeCount > 200 ? 500 : 1000; // Process fewer edges for huge graphs

                let edgesProcessed = 0;
                for (let i = 0; i < this.edges.length && edgesProcessed < edgeLimit; i++) {
                    const edge = this.edges[i];

                    // Skip hidden edges in physics simulation
                    if (edge.hidden) continue;

                    const dx = edge.target.x - edge.source.x;
                    const dy = edge.target.y - edge.source.y;
                    const dist = Math.sqrt(dx * dx + dy * dy);
                    if (dist > 0) {
                        const idealDistance = nodeCount > 150 ? 80 : 100; // Tighter for large graphs
                        const force = (dist - idealDistance) * alpha * edgeStrength;
                        const fx = dx / dist * force;
                        const fy = dy / dist * force;

                        if (!edge.source.fx) {
                            edge.source.vx += fx;
                            edge.source.vy += fy;
                        }
                        if (!edge.target.fx) {
                            edge.target.vx -= fx;
                            edge.target.vy -= fy;
                        }
                    }
                    edgesProcessed++;
                }
            }

            animate() {
                const isDarkMode = document.body.classList.contains('dark-mode');
                this.ctx.fillStyle = isDarkMode ? 'transparent' : 'transparent';
                this.ctx.clearRect(0, 0, this.canvas.width, this.canvas.height);

                this.ctx.save();
                this.ctx.translate(this.camera.x, this.camera.y);
                this.ctx.scale(this.camera.zoom, this.camera.zoom);

                // Draw cluster boundaries and labels (only in clustered modes)
                if (this.layoutType === 'clustered') {
                    this.ctx.globalAlpha = 0.1;
                    this.clusters.forEach((cluster, subnet) => {
                        const clusterPos = this.clusterPositions.get(subnet);
                        if (!clusterPos) return;

                        // Calculate cluster bounds
                        const clusterNodes = cluster.nodes.filter(n => !n.hidden);
                        if (clusterNodes.length === 0) return;

                        // Draw cluster circle
                        const clusterRadius = Math.max(200, Math.sqrt(clusterNodes.length) * 50);
                        this.ctx.strokeStyle = isDarkMode ? '#ffffff' : '#000000';
                        this.ctx.lineWidth = 2;
                        this.ctx.setLineDash([10, 10]);
                        this.ctx.beginPath();
                        this.ctx.arc(clusterPos.x, clusterPos.y, clusterRadius, 0, Math.PI * 2);
                        this.ctx.stroke();
                        this.ctx.setLineDash([]);

                        // Draw subnet label
                        this.ctx.globalAlpha = 0.5;
                        this.ctx.fillStyle = isDarkMode ? '#ffffff' : '#333333';
                        this.ctx.font = 'bold 14px monospace';
                        this.ctx.textAlign = 'center';
                        this.ctx.fillText(subnet + '.0/24', clusterPos.x, clusterPos.y - clusterRadius - 15);

                        // Draw role labels
                        if (cluster.scanner) {
                            this.ctx.fillStyle = '#ff6b6b';
                            this.ctx.font = '12px monospace';
                            this.ctx.fillText('Scanner: ' + cluster.scanner.ip, clusterPos.x, clusterPos.y - clusterRadius - 35);
                        }
                        if (cluster.listener) {
                            this.ctx.fillStyle = '#51cf66';
                            this.ctx.font = '12px monospace';
                            this.ctx.fillText('Listener: ' + cluster.listener.ip, clusterPos.x, clusterPos.y - clusterRadius - 50);
                        }
                    });
                    this.ctx.globalAlpha = 1.0;
                } else if (this.layoutType === 'clustered-host') {
                    this.ctx.globalAlpha = 0.1;
                    this.clusters.forEach((cluster, clusterId) => {
                        const clusterPos = this.clusterPositions.get(clusterId);
                        if (!clusterPos) return;

                        // Calculate cluster bounds
                        const clusterNodes = cluster.nodes.filter(n => !n.hidden);
                        if (clusterNodes.length === 0) return;

                        // Draw cluster circle
                        const clusterRadius = Math.max(150, Math.sqrt(clusterNodes.length) * 40);
                        this.ctx.strokeStyle = isDarkMode ? '#00d4ff' : '#0099ff';
                        this.ctx.lineWidth = 2;
                        this.ctx.setLineDash([5, 5]);
                        this.ctx.beginPath();
                        this.ctx.arc(clusterPos.x, clusterPos.y, clusterRadius, 0, Math.PI * 2);
                        this.ctx.stroke();
                        this.ctx.setLineDash([]);

                        // Draw cluster label
                        this.ctx.globalAlpha = 0.6;
                        this.ctx.fillStyle = isDarkMode ? '#00d4ff' : '#0099ff';
                        this.ctx.font = 'bold 12px monospace';
                        this.ctx.textAlign = 'center';

                        if (cluster.centerNode) {
                            this.ctx.fillText(cluster.centerNode.ip, clusterPos.x, clusterPos.y - clusterRadius - 10);
                            this.ctx.font = '10px monospace';
                            this.ctx.fillStyle = isDarkMode ? '#888' : '#666';
                            this.ctx.fillText(`${cluster.connectedNodes.length} satellites`, clusterPos.x, clusterPos.y - clusterRadius - 25);
                        } else if (clusterId === 'misc') {
                            this.ctx.fillText('Miscellaneous', clusterPos.x, clusterPos.y - clusterRadius - 10);
                            this.ctx.font = '10px monospace';
                            this.ctx.fillStyle = isDarkMode ? '#888' : '#666';
                            this.ctx.fillText(`${clusterNodes.length} nodes`, clusterPos.x, clusterPos.y - clusterRadius - 25);
                        }
                    });
                    this.ctx.globalAlpha = 1.0;
                }

                // Draw edges with pen-like effects
                // Sort edges by depth for 3D mode (paint far edges first)
                const sortedEdges = this.layoutType === '3d'
                    ? [...this.edges].sort((a, b) => {
                        const projA = this.project3D(a.source);
                        const projB = this.project3D(b.source);
                        const avgZa = (projA.z + this.project3D(a.target).z) / 2;
                        const avgZb = (projB.z + this.project3D(b.target).z) / 2;
                        return avgZa - avgZb; // Draw far edges first
                    })
                    : this.edges;

                sortedEdges.forEach(edge => {
                    if (edge.hidden) return;

                    // Project 3D coordinates to 2D
                    const sourceProj = this.project3D(edge.source);
                    const targetProj = this.project3D(edge.target);

                    this.ctx.strokeStyle = this.getProtocolColor(edge.protocol);
                    this.ctx.globalAlpha = Math.min(0.95, Math.max(0.6, edge.packets / 50));
                    const baseWidth = Math.max(2.5, Math.min(5, edge.bytes / 5000));
                    // Scale line width based on depth in 3D mode
                    const avgScale = (sourceProj.scale + targetProj.scale) / 2;
                    this.ctx.lineWidth = baseWidth * avgScale;
                    this.ctx.lineCap = 'round';
                    this.ctx.lineJoin = 'round';

                    // Choose random drawing style based on protocol
                    const drawStyle = this.getDrawStyle(edge.protocol);

                    if (drawStyle === 'dashed') {
                        this.ctx.setLineDash([8, 5, 2, 5]);
                        this.ctx.beginPath();
                        this.ctx.moveTo(sourceProj.x, sourceProj.y);
                        this.ctx.lineTo(targetProj.x, targetProj.y);
                        this.ctx.stroke();
                        this.ctx.setLineDash([]);
                    } else if (drawStyle === 'dotted') {
                        this.ctx.setLineDash([2, 6]);
                        this.ctx.beginPath();
                        this.ctx.moveTo(sourceProj.x, sourceProj.y);
                        this.ctx.lineTo(targetProj.x, targetProj.y);
                        this.ctx.stroke();
                        this.ctx.setLineDash([]);
                    } else if (drawStyle === 'scribble') {
                        // Draw scribble line
                        this.drawScribbleLine(sourceProj.x, sourceProj.y, targetProj.x, targetProj.y);
                    } else {
                        // Wavy line
                        this.drawWavyLine(sourceProj.x, sourceProj.y, targetProj.x, targetProj.y);
                    }
                });
                
                // Draw particles
                this.ctx.globalAlpha = 1;
                this.particles = this.particles.filter(particle => {
                    particle.progress += particle.speed;
                    if (particle.progress >= 1) return false;

                    const x = particle.source.x + (particle.target.x - particle.source.x) * particle.progress;
                    const y = particle.source.y + (particle.target.y - particle.source.y) * particle.progress;
                    const z = this.layoutType === '3d'
                        ? (particle.source.z || 0) + ((particle.target.z || 0) - (particle.source.z || 0)) * particle.progress
                        : 0;

                    const proj = this.project3D({ x, y, z });

                    this.ctx.fillStyle = this.getProtocolColor(particle.protocol);
                    this.ctx.beginPath();
                    this.ctx.arc(proj.x, proj.y, 3 * proj.scale, 0, Math.PI * 2);
                    this.ctx.fill();

                    return true;
                });

                // Draw nodes - sort by depth for 3D mode
                const sortedNodes = this.layoutType === '3d'
                    ? Array.from(this.nodes.values()).sort((a, b) => {
                        const projA = this.project3D(a);
                        const projB = this.project3D(b);
                        return projA.z - projB.z; // Use rotated z for sorting
                    })
                    : Array.from(this.nodes.values());

                sortedNodes.forEach(node => {
                    if (node.hidden) return;

                    // Calculate opacity and color based on age (only for live/remote capture fading)
                    let nodeOpacity = 1;
                    let nodeGrayscale = false;

                    if (this.isLiveMode || this.isRemoteMode) {
                        const now = Date.now();
                        const timeSinceActivity = (now - (node.lastActivity || now)) / 1000;

                        if (timeSinceActivity >= 120) {
                            // After 2 minutes, start fading out (completely gone at 3 minutes)
                            const fadeProgress = Math.min(1, (timeSinceActivity - 120) / 60);
                            nodeOpacity = 1 - fadeProgress;

                            // Skip completely faded nodes
                            if (nodeOpacity <= 0.05) return;
                            nodeGrayscale = true;
                        } else if (timeSinceActivity >= 30) {
                            // After 30 seconds with no traffic, turn gray
                            nodeGrayscale = true;
                        }
                    }

                    // Adjust node radius based on role (only in clustered modes)
                    let nodeRadius = node.radius || 15;
                    if (this.layoutType === 'clustered') {
                        if (node.clusterRole === 'scanner' || node.clusterRole === 'listener') {
                            nodeRadius = 25; // Larger for primary nodes
                        } else if (node.clusterRole === 'hub') {
                            nodeRadius = 20; // Medium for hubs
                        }
                    } else if (this.layoutType === 'clustered-host') {
                        if (node.clusterRole === 'center') {
                            nodeRadius = 28; // Large for center nodes
                        } else if (node.clusterRole === 'satellite') {
                            nodeRadius = 12; // Small for satellite nodes
                        }
                    }

                    // Project 3D to 2D
                    const proj = this.project3D(node);
                    const scaledRadius = nodeRadius * proj.scale;

                    // In 3D mode, add depth indicator (shadow circle)
                    if (this.layoutType === '3d') {
                        const z = node.z || 0;
                        const depthAlpha = Math.max(0.1, Math.min(0.3, (z + 250) / 500));

                        // Draw depth ring
                        this.ctx.strokeStyle = z > 0 ? 'rgba(100, 200, 255, ' + depthAlpha + ')' : 'rgba(255, 150, 100, ' + depthAlpha + ')';
                        this.ctx.lineWidth = 2 * proj.scale;
                        this.ctx.beginPath();
                        this.ctx.arc(proj.x, proj.y, scaledRadius + 5 * proj.scale, 0, Math.PI * 2);
                        this.ctx.stroke();

                        // Add glow for nodes far from viewer
                        if (Math.abs(z) > 100) {
                            const glowIntensity = Math.min(15, Math.abs(z) / 20);
                            this.ctx.shadowColor = z > 0 ? 'rgba(100, 200, 255, 0.5)' : 'rgba(255, 150, 100, 0.5)';
                            this.ctx.shadowBlur = glowIntensity * proj.scale;
                        }
                    }

                    // Node circle
                    const gradient = this.ctx.createRadialGradient(
                        proj.x, proj.y, 0,
                        proj.x, proj.y, scaledRadius
                    );

                    let color = this.getNodeColor(node);

                    // Apply grayscale if node is inactive
                    if (nodeGrayscale) {
                        // Convert to grayscale
                        const isDarkMode = document.body.classList.contains('dark-mode');
                        color = isDarkMode ? '#666666' : '#999999';
                    }

                    const alpha = Math.floor(255 * nodeOpacity).toString(16).padStart(2, '0');
                    const alphaLight = Math.floor(51 * nodeOpacity).toString(16).padStart(2, '0');
                    gradient.addColorStop(0, color + alpha);
                    gradient.addColorStop(1, color + alphaLight);

                    this.ctx.fillStyle = gradient;
                    this.ctx.beginPath();
                    this.ctx.arc(proj.x, proj.y, scaledRadius, 0, Math.PI * 2);
                    this.ctx.fill();

                    // Clear shadow for next draws
                    if (this.layoutType === '3d' && Math.abs(node.z || 0) > 100) {
                        this.ctx.shadowBlur = 0;
                    }

                    // Special border for scanner/listener nodes (only in clustered mode)
                    if (this.layoutType === 'clustered') {
                        if (node.clusterRole === 'scanner') {
                            this.ctx.globalAlpha = nodeOpacity * 0.8;
                            this.ctx.strokeStyle = '#ff6b6b';
                            this.ctx.lineWidth = 3 * proj.scale;
                            this.ctx.beginPath();
                            this.ctx.arc(proj.x, proj.y, scaledRadius + 3 * proj.scale, 0, Math.PI * 2);
                            this.ctx.stroke();
                            this.ctx.globalAlpha = 1;
                        } else if (node.clusterRole === 'listener') {
                            this.ctx.globalAlpha = nodeOpacity * 0.8;
                            this.ctx.strokeStyle = '#51cf66';
                            this.ctx.lineWidth = 3 * proj.scale;
                            this.ctx.beginPath();
                            this.ctx.arc(proj.x, proj.y, scaledRadius + 3 * proj.scale, 0, Math.PI * 2);
                            this.ctx.stroke();
                            this.ctx.globalAlpha = 1;
                        }
                    } else if (this.layoutType === 'clustered-host') {
                        if (node.clusterRole === 'center') {
                            this.ctx.globalAlpha = nodeOpacity * 0.8;
                            this.ctx.strokeStyle = '#00d4ff';
                            this.ctx.lineWidth = 4 * proj.scale;
                            this.ctx.beginPath();
                            this.ctx.arc(proj.x, proj.y, scaledRadius + 4 * proj.scale, 0, Math.PI * 2);
                            this.ctx.stroke();
                            this.ctx.globalAlpha = 1;
                        }
                    }

                    // Node border (highlight if selected)
                    if (node.highlighted) {
                        this.ctx.globalAlpha = nodeOpacity;
                        this.ctx.strokeStyle = '#ffff00';
                        this.ctx.lineWidth = 4 * proj.scale;
                        this.ctx.shadowColor = '#ffff00';
                        this.ctx.shadowBlur = 20 * proj.scale;
                        this.ctx.stroke();
                        this.ctx.shadowBlur = 0;
                        this.ctx.globalAlpha = 1;
                    } else {
                        this.ctx.globalAlpha = nodeOpacity;
                        this.ctx.strokeStyle = color + alpha;
                        this.ctx.lineWidth = 2 * proj.scale;
                        this.ctx.stroke();
                        this.ctx.globalAlpha = 1;
                    }

                    // Node label - show hostname if available, otherwise IP
                    // Only show labels when zoomed in enough to reduce clutter
                    const showLabels = this.camera.zoom >= 0.8;

                    if (showLabels || node.highlighted) {
                        const isDarkMode = document.body.classList.contains('dark-mode');
                        this.ctx.globalAlpha = nodeOpacity;
                        this.ctx.fillStyle = isDarkMode ? '#fff' : '#333';
                        this.ctx.font = '10px monospace';
                        this.ctx.textAlign = 'center';
                        this.ctx.textBaseline = 'middle';

                        let label = node.ip;
                        if (node.hostname) {
                            // Show hostname (truncate if too long)
                            label = node.hostname.length > 20 ? node.hostname.substring(0, 17) + '...' : node.hostname;
                        } else {
                            // Show IP (truncate if too long)
                            label = node.ip.length > 15 ? node.ip.substring(0, 12) + '...' : node.ip;
                        }

                        this.ctx.fillText(label, proj.x, proj.y);
                        this.ctx.globalAlpha = 1;
                    }
                });

                // Draw line rider if active
                if (this.riderActive && this.riderPath.length > 0) {
                    const segmentIndex = Math.floor(this.riderPosition);
                    const t = this.riderPosition - segmentIndex;
                    const segment = this.riderPath[segmentIndex];

                    if (segment) {
                        const x = segment.from.x + (segment.to.x - segment.from.x) * t;
                        const y = segment.from.y + (segment.to.y - segment.from.y) * t;

                        // Draw rider
                        this.ctx.save();
                        this.ctx.translate(x, y);

                        // Rotate based on direction
                        const dx = segment.to.x - segment.from.x;
                        const dy = segment.to.y - segment.from.y;
                        const angle = Math.atan2(dy, dx);
                        this.ctx.rotate(angle);

                        // Draw sled emoji with glow
                        this.ctx.shadowColor = '#ff6600';
                        this.ctx.shadowBlur = 20;
                        this.ctx.font = '24px Arial';
                        this.ctx.textAlign = 'center';
                        this.ctx.textBaseline = 'middle';
                        this.ctx.fillText('🐵', 0, 0);

                        this.ctx.restore();
                    }
                }

                this.ctx.restore();

                // Update line rider
                if (this.riderActive) {
                    this.updateLineRider();
                }

                // Apply forces if animating
                if (this.animating) {
                    this.simulateForces();

                    // Add random particles (but limit total particles to prevent lag)
                    const MAX_PARTICLES = 50;
                    if (this.particles.length < MAX_PARTICLES && Math.random() < 0.1 && this.edges.length > 0) {
                        const edge = this.edges[Math.floor(Math.random() * this.edges.length)];
                        this.particles.push({
                            source: edge.source,
                            target: edge.target,
                            protocol: edge.protocol,
                            progress: 0,
                            speed: 0.02
                        });
                    }
                }

                // Decay attention scores and cleanup inactive nodes in live mode
                if (this.isLiveMode) {
                    const now = Date.now();
                    const nodesToRemove = [];

                    this.nodes.forEach((node, ip) => {
                        // Decay attention scores
                        if (node.attentionScore) {
                            node.attentionScore = Math.max(0, node.attentionScore - 0.5);
                        }

                        // Remove nodes after 5 minutes (300 seconds) of inactivity
                        const timeSinceActivity = (now - (node.lastActivity || now)) / 1000;
                        if (timeSinceActivity >= 300) {
                            nodesToRemove.push(ip);
                        }
                    });

                    // Remove inactive nodes
                    nodesToRemove.forEach(ip => {
                        console.log(`[Visualizer] Removing inactive node: ${ip}`);
                        this.nodes.delete(ip);

                        // Remove associated edges
                        this.edges = this.edges.filter(edge =>
                            edge.source.ip !== ip && edge.target.ip !== ip
                        );
                    });
                }

                requestAnimationFrame(() => this.animate());
            }

            getNodeColor(node) {
                // Only apply aging and attention coloring in live mode
                if (this.isLiveMode) {
                    const now = Date.now();
                    const timeSinceActivity = (now - (node.lastActivity || now)) / 1000; // seconds

                    // Mark node as inactive after 1 minute (60 seconds) - turn gray
                    if (timeSinceActivity >= 60) {
                        node.inactive = true;
                        // Fade to gray over time
                        const grayValue = Math.max(60, 160 - Math.floor((timeSinceActivity - 60) * 2));
                        const hex = grayValue.toString(16).padStart(2, '0');
                        return `#${hex}${hex}${hex}`;
                    } else {
                        node.inactive = false;
                    }

                    // Check attention score - high attention turns red
                    const attentionScore = node.attentionScore || 0;
                    if (attentionScore > 500) {
                        // Blend from orange to red based on attention
                        const redIntensity = Math.min(255, 150 + (attentionScore - 500) / 2);
                        return `#${redIntensity.toString(16).padStart(2, '0')}3030`;
                    }
                    if (attentionScore > 200) {
                        return '#ff6600'; // Orange for high attention
                    }
                }

                // Standard color based on activity level (for file mode and live mode)
                const activity = node.packetsSent + node.packetsReceived;
                if (activity > 1000) return '#ff6b6b';
                if (activity > 500) return '#ffa500';
                if (activity > 100) return '#00d4ff';
                return '#00ff00';
            }

            getProtocolColor(protocol) {
                const colors = {
                    'TCP': '#00ff00',
                    'UDP': '#0099ff',
                    'ICMP': '#ffff00',
                    'HTTP': '#ff6600',      // Orange for HTTP
                    'HTTPS': '#00ff00',
                    'SSH': '#ff00ff',       // Magenta for SSH
                    'DNS': '#9966ff',       // Purple for DNS
                    'BOOTP': '#ffcc00',     // Yellow-orange for BOOTP
                    'ARP': '#00ffff',       // Cyan for ARP
                    'FTP': '#ff3399',       // Pink for FTP
                    'TCP/IPv6': '#00ff00',
                    'UDP/IPv6': '#0099ff',
                    'IPv6': '#ff00ff'
                };
                return colors[protocol] || '#ffffff';
            }

            getDrawStyle(protocol) {
                const styles = {
                    'TCP': 'dashed',
                    'UDP': 'dotted',
                    'ICMP': 'scribble',
                    'HTTP': 'wavy',
                    'HTTPS': 'dashed',
                    'SSH': 'scribble',
                    'DNS': 'dotted',
                    'BOOTP': 'wavy',
                    'ARP': 'dotted',
                    'TCP/IPv6': 'dashed',
                    'UDP/IPv6': 'dotted',
                    'IPv6': 'scribble'
                };
                return styles[protocol] || 'dashed';
            }

            drawScribbleLine(x1, y1, x2, y2) {
                const dx = x2 - x1;
                const dy = y2 - y1;
                const dist = Math.sqrt(dx * dx + dy * dy);
                const steps = Math.floor(dist / 5);

                this.ctx.beginPath();
                this.ctx.moveTo(x1, y1);

                for (let i = 1; i <= steps; i++) {
                    const t = i / steps;
                    const x = x1 + dx * t + (Math.random() - 0.5) * 4;
                    const y = y1 + dy * t + (Math.random() - 0.5) * 4;
                    this.ctx.lineTo(x, y);
                }

                this.ctx.lineTo(x2, y2);
                this.ctx.stroke();
            }

            drawWavyLine(x1, y1, x2, y2) {
                const dx = x2 - x1;
                const dy = y2 - y1;
                const dist = Math.sqrt(dx * dx + dy * dy);
                const steps = Math.floor(dist / 8);

                this.ctx.beginPath();
                this.ctx.moveTo(x1, y1);

                for (let i = 1; i <= steps; i++) {
                    const t = i / steps;
                    const wave = Math.sin(t * Math.PI * 4) * 3;
                    const perpX = -dy / dist;
                    const perpY = dx / dist;
                    const x = x1 + dx * t + perpX * wave;
                    const y = y1 + dy * t + perpY * wave;
                    this.ctx.lineTo(x, y);
                }

                this.ctx.lineTo(x2, y2);
                this.ctx.stroke();
            }

            toggleAnimation() {
                this.animating = !this.animating;
                return this.animating;
            }

            reset() {
                this.camera = { x: 0, y: 0, zoom: 1 };
                this.rotation = { x: 0, y: 0 };
                this.applyLayout();
            }

            setLiveMode(isLive) {
                this.isLiveMode = isLive;
            }

            setRemoteMode(isRemote) {
                this.isRemoteMode = isRemote;
            }

            filterByProtocol(protocol) {
                if (!protocol) {
                    // Show all nodes and edges
                    this.nodes.forEach(node => {
                        node.hidden = false;
                    });
                    this.edges.forEach(edge => {
                        edge.hidden = false;
                    });
                } else {
                    // Get all edges with the selected protocol
                    const relevantEdges = this.edges.filter(e => e.protocol === protocol);
                    const relevantIPs = new Set();

                    relevantEdges.forEach(edge => {
                        relevantIPs.add(edge.source.ip);
                        relevantIPs.add(edge.target.ip);
                    });

                    // Hide nodes not involved in this protocol
                    this.nodes.forEach(node => {
                        node.hidden = !relevantIPs.has(node.ip);
                    });

                    // Hide edges that don't match the protocol
                    this.edges.forEach(edge => {
                        edge.hidden = edge.protocol !== protocol;
                    });
                }
            }

            startLineRider() {
                if (this.riderActive) {
                    this.stopLineRider();
                    return;
                }

                // Find the most active node (most connections)
                let mostActiveNode = null;
                let maxConnections = 0;

                this.nodes.forEach(node => {
                    const connectionCount = this.edges.filter(e =>
                        e.source === node || e.target === node
                    ).length;

                    if (connectionCount > maxConnections) {
                        maxConnections = connectionCount;
                        mostActiveNode = node;
                    }
                });

                if (!mostActiveNode || this.edges.length === 0) {
                    alert('No network activity to ride!');
                    return;
                }

                // Build a path through the network
                this.buildRiderPath(mostActiveNode);
                this.riderActive = true;
                this.riderPosition = 0;
                this.animating = false; // Disable jiggle physics during ride

                // Add active class to icon
                document.getElementById('riderIcon').classList.add('active');
            }

            stopLineRider() {
                this.riderActive = false;
                this.riderPath = [];
                this.riderPosition = 0;
                this.riderCurrentEdge = null;
                this.animating = true;

                document.getElementById('riderIcon').classList.remove('active');
            }

            buildRiderPath(startNode) {
                this.riderPath = [];
                const visited = new Set();
                let currentNode = startNode;

                // Build a path by following edges
                for (let i = 0; i < 50 && currentNode; i++) {
                    visited.add(currentNode);

                    // Find unvisited edges from current node
                    const availableEdges = this.edges.filter(e =>
                        (e.source === currentNode && !visited.has(e.target)) ||
                        (e.target === currentNode && !visited.has(e.source))
                    );

                    if (availableEdges.length === 0) break;

                    // Randomly select an edge instead of always picking the busiest
                    const edge = availableEdges[Math.floor(Math.random() * availableEdges.length)];
                    const nextNode = edge.source === currentNode ? edge.target : edge.source;

                    this.riderPath.push({
                        edge: edge,
                        from: currentNode,
                        to: nextNode,
                        reverse: edge.target === currentNode
                    });

                    currentNode = nextNode;
                }
            }

            updateLineRider() {
                if (!this.riderActive || this.riderPath.length === 0) return;

                this.riderPosition += this.riderSpeed;

                // Check if we've completed the path
                if (this.riderPosition >= this.riderPath.length) {
                    this.stopLineRider();
                    return;
                }

                // Get current segment
                const segmentIndex = Math.floor(this.riderPosition);
                const t = this.riderPosition - segmentIndex;
                const segment = this.riderPath[segmentIndex];

                if (segment) {
                    this.riderCurrentEdge = segment.edge;

                    // Calculate position along edge
                    const fromNode = segment.from;
                    const toNode = segment.to;
                    const x = fromNode.x + (toNode.x - fromNode.x) * t;
                    const y = fromNode.y + (toNode.y - fromNode.y) * t;

                    // Smoothly follow the rider with camera - center on rider position
                    const canvasWidth = this.canvas.width / window.devicePixelRatio;
                    const canvasHeight = this.canvas.height / window.devicePixelRatio;

                    const targetCameraX = canvasWidth / 2 - x * this.camera.zoom;
                    const targetCameraY = canvasHeight / 2 - y * this.camera.zoom;

                    // Smooth lerp
                    this.camera.x += (targetCameraX - this.camera.x) * 0.08;
                    this.camera.y += (targetCameraY - this.camera.y) * 0.08;

                    // Auto zoom for better view
                    const targetZoom = 1.5;
                    this.camera.zoom += (targetZoom - this.camera.zoom) * 0.03;

                    // Show info popup
                    this.showRiderInfo(segment, t);
                }
            }

            showRiderInfo(segment, progress) {
                const tooltip = document.getElementById('tooltip');
                if (!tooltip) return;

                const edge = segment.edge;
                const fromNode = segment.from;
                const toNode = segment.to;

                // Calculate screen position
                const x = fromNode.x + (toNode.x - fromNode.x) * progress;
                const y = fromNode.y + (toNode.y - fromNode.y) * progress;
                const screenX = x * this.camera.zoom + this.camera.x;
                const screenY = y * this.camera.zoom + this.camera.y;

                tooltip.style.left = `${screenX + 20}px`;
                tooltip.style.top = `${screenY + 20}px`;
                tooltip.classList.add('active');

                // Check theme for colors
                const isDarkMode = document.body.classList.contains('dark-mode');
                const textColor = isDarkMode ? '#fff' : '#333';
                const strongColor = isDarkMode ? '#fff' : '#000';

                tooltip.innerHTML = `
                    <div style="font-weight: 600; color: #ff6600; margin-bottom: 8px;">🐵 Follow Chimp!</div>
                    <div style="font-size: 11px; line-height: 1.6; color: ${textColor};">
                        <strong style="color: ${strongColor};">${fromNode.ip}</strong> → <strong style="color: ${strongColor};">${toNode.ip}</strong><br>
                        Protocol: <span style="color: ${this.getProtocolColor(edge.protocol)}">${edge.protocol}</span><br>
                        Packets: ${edge.packets.toLocaleString()}<br>
                        Data: ${(edge.bytes / 1024).toFixed(2)} KB
                    </div>
                `;
            }

            addLivePacket(packet) {
                const now = Date.now();

                // Add nodes for source and destination if they don't exist
                if (!this.nodes.has(packet.source)) {
                    this.nodes.set(packet.source, {
                        ip: packet.source,
                        x: Math.random() * this.canvas.width / window.devicePixelRatio,
                        y: Math.random() * this.canvas.height / window.devicePixelRatio,
                        z: Math.random() * 500 - 250,
                        vx: 0,
                        vy: 0,
                        vz: 0,
                        connections: 0,
                        packets: [],
                        protocols: new Set(),
                        packetsSent: 0,
                        packetsReceived: 0,
                        bytesSent: 0,
                        bytesReceived: 0,
                        radius: 15,  // Default radius, will grow with activity
                        lastActivity: now,
                        attentionScore: 0  // Track how much attention this node is getting
                    });
                    console.log(`[Visualizer] Created new node: ${packet.source} at (${this.nodes.get(packet.source).x.toFixed(0)}, ${this.nodes.get(packet.source).y.toFixed(0)})`);
                }

                if (!this.nodes.has(packet.destination)) {
                    this.nodes.set(packet.destination, {
                        ip: packet.destination,
                        x: Math.random() * this.canvas.width / window.devicePixelRatio,
                        y: Math.random() * this.canvas.height / window.devicePixelRatio,
                        z: Math.random() * 500 - 250,
                        vx: 0,
                        vy: 0,
                        vz: 0,
                        connections: 0,
                        packets: [],
                        protocols: new Set(),
                        packetsSent: 0,
                        packetsReceived: 0,
                        bytesSent: 0,
                        bytesReceived: 0,
                        radius: 15,  // Default radius, will grow with activity
                        lastActivity: now,
                        attentionScore: 0  // Track how much attention this node is getting
                    });
                    console.log(`[Visualizer] Created new node: ${packet.destination} at (${this.nodes.get(packet.destination).x.toFixed(0)}, ${this.nodes.get(packet.destination).y.toFixed(0)})`);
                }

                const sourceNode = this.nodes.get(packet.source);
                const destNode = this.nodes.get(packet.destination);

                // Update last activity timestamp
                sourceNode.lastActivity = now;
                destNode.lastActivity = now;

                // Update attention score (decays over time, increases with activity)
                sourceNode.attentionScore = Math.min(1000, (sourceNode.attentionScore || 0) + 10);
                destNode.attentionScore = Math.min(1000, (destNode.attentionScore || 0) + 5);

                // Add packet to node's packet list
                sourceNode.packets.push(packet);
                destNode.packets.push(packet);
                sourceNode.protocols.add(packet.protocol);
                destNode.protocols.add(packet.protocol);

                // Update packet and byte counts
                sourceNode.packetsSent++;
                sourceNode.bytesSent += packet.length || 0;
                destNode.packetsReceived++;
                destNode.bytesReceived += packet.length || 0;

                // Update node radius based on activity
                sourceNode.radius = Math.min(30, 10 + Math.sqrt(sourceNode.packetsSent + sourceNode.packetsReceived) * 2);
                destNode.radius = Math.min(30, 10 + Math.sqrt(destNode.packetsSent + destNode.packetsReceived) * 2);

                // Create or update edge
                const edgeKey = `${packet.source}-${packet.destination}`;
                let edge = this.edges.find(e => e.key === edgeKey || e.key === `${packet.destination}-${packet.source}`);

                if (!edge) {
                    edge = {
                        key: edgeKey,
                        source: sourceNode,
                        target: destNode,
                        packets: [],
                        protocol: packet.protocol,
                        weight: 1,
                        bytes: packet.length || 0
                    };
                    this.edges.push(edge);
                    sourceNode.connections++;
                    destNode.connections++;

                    // Limit edges in live mode to prevent performance degradation
                    const MAX_EDGES = 1000;
                    if (this.isLiveMode && this.edges.length > MAX_EDGES) {
                        // Remove oldest edge (first in array)
                        const removedEdge = this.edges.shift();
                        if (removedEdge.source.connections > 0) removedEdge.source.connections--;
                        if (removedEdge.target.connections > 0) removedEdge.target.connections--;
                        console.log(`[Visualizer] Removed oldest edge to maintain performance`);
                    }

                    console.log(`[Visualizer] Created new edge: ${packet.source} -> ${packet.destination}`);
                } else {
                    edge.weight++;
                    edge.bytes += packet.length || 0;
                }

                // Limit packets per edge to prevent memory bloat
                edge.packets.push(packet);
                if (edge.packets.length > 100) {
                    edge.packets.shift(); // Remove oldest packet from edge
                }

                // Mark edge as recently updated for visual feedback
                edge.recentlyUpdated = true;
                setTimeout(() => {
                    edge.recentlyUpdated = false;
                }, 500);
            }

            focusOnNode(ipOrNode) {
                // Support both IP string and node object
                const node = typeof ipOrNode === 'string' ? this.nodes.get(ipOrNode) : ipOrNode;
                if (!node) return;

                // Calculate canvas center
                const centerX = this.canvas.offsetWidth / 2;
                const centerY = this.canvas.offsetHeight / 2;

                // Project node position if in 3D mode
                const proj = this.project3D(node);

                // Set camera to center on node (use projected coordinates in 3D)
                if (this.layoutType === '3d') {
                    this.camera.x = centerX - proj.x * this.camera.zoom;
                    this.camera.y = centerY - proj.y * this.camera.zoom;
                } else {
                    this.camera.x = centerX - node.x * this.camera.zoom;
                    this.camera.y = centerY - node.y * this.camera.zoom;
                }

                // Zoom in for better view
                this.camera.zoom = Math.max(this.camera.zoom, 1.5);

                // Highlight the node temporarily
                node.highlighted = true;
                setTimeout(() => {
                    delete node.highlighted;
                }, 2000);

                // Show dashboard for the node
                this.showNodeDashboard(node);
            }

            searchNode(searchTerm) {
                if (!searchTerm) return;

                // Search in nodes (IP addresses)
                let node = this.nodes.get(searchTerm);

                // If no exact match, try partial match in IPs
                if (!node) {
                    const matches = Array.from(this.nodes.values()).filter(n =>
                        n.ip.includes(searchTerm)
                    );

                    if (matches.length === 1) {
                        node = matches[0];
                    } else if (matches.length > 1) {
                        alert(`Multiple IP matches found: ${matches.map(n => n.ip).join(', ')}\nPlease be more specific.`);
                        return;
                    }
                }

                // Search in packet data if no node match
                if (!node) {
                    const packetMatches = this.allPackets.filter(p => {
                        // Search in all packet fields
                        const searchFields = [
                            p.source,
                            p.destination,
                            p.protocol,
                            p.srcPort?.toString(),
                            p.dstPort?.toString(),
                            p.length?.toString()
                        ].filter(Boolean);

                        // Also search in raw packet data (hex)
                        if (p.data) {
                            const hexStr = Array.from(p.data).map(b => b.toString(16).padStart(2, '0')).join('');
                            searchFields.push(hexStr);

                            // Search in ASCII representation
                            const asciiStr = Array.from(p.data).map(b =>
                                (b >= 32 && b <= 126) ? String.fromCharCode(b) : '.'
                            ).join('');
                            searchFields.push(asciiStr);
                        }

                        return searchFields.some(field =>
                            field?.toLowerCase().includes(searchTerm.toLowerCase())
                        );
                    });

                    if (packetMatches.length > 0) {
                        // Show first matching packet's nodes
                        const firstMatch = packetMatches[0];
                        if (firstMatch.source && firstMatch.destination) {
                            // If node not visible in current timeline, jump to that time
                            if (timeline && firstMatch.timestamp) {
                                timeline.currentTime = firstMatch.timestamp;
                                timeline.updateUI();
                                timeline.filterByTime();
                            }
                            this.focusOnConnection(firstMatch.source, firstMatch.destination);
                            alert(`Found ${packetMatches.length} packet(s) matching "${searchTerm}"\nShowing connection: ${firstMatch.source} → ${firstMatch.destination}`);
                            return;
                        }
                    }
                }

                if (node) {
                    this.focusOnNode(node.ip);
                } else {
                    alert(`No matches found for "${searchTerm}"`);
                }
            }

            focusOnConnection(sourceIp, destIp) {
                const source = this.nodes.get(sourceIp);
                const dest = this.nodes.get(destIp);
                if (!source || !dest) return;

                // Calculate center point between two nodes
                const midX = (source.x + dest.x) / 2;
                const midY = (source.y + dest.y) / 2;

                // Calculate canvas center
                const centerX = this.canvas.offsetWidth / 2;
                const centerY = this.canvas.offsetHeight / 2;

                // Set camera to center on midpoint
                this.camera.x = centerX - midX * this.camera.zoom;
                this.camera.y = centerY - midY * this.camera.zoom;

                // Highlight both nodes
                source.highlighted = true;
                dest.highlighted = true;
                setTimeout(() => {
                    delete source.highlighted;
                    delete dest.highlighted;
                }, 2000);
            }
        }

        // Timeline Controller
        class TimelineController {
            constructor() {
                this.currentTime = 0;
                this.startTime = 0;
                this.endTime = 0;
                this.isDragging = false;
                this.isPlaying = false;
                this.playInterval = null;
                this.allConnections = [];
                this.allHosts = new Map();

                this.setupEventListeners();
            }

            setupEventListeners() {
                const slider = document.getElementById('timelineSlider');
                const progress = document.getElementById('timelineProgress');
                const handle = progress.querySelector('.timeline-handle');

                const updatePosition = (e) => {
                    const rect = slider.getBoundingClientRect();
                    const x = Math.max(0, Math.min(e.clientX - rect.left, rect.width));
                    const percent = x / rect.width;

                    this.currentTime = this.startTime + (this.endTime - this.startTime) * percent;
                    this.updateUI();
                    this.filterByTime();
                };

                handle.addEventListener('mousedown', (e) => {
                    e.stopPropagation();
                    this.isDragging = true;
                });

                slider.addEventListener('mousedown', (e) => {
                    updatePosition(e);
                    this.isDragging = true;
                });

                document.addEventListener('mousemove', (e) => {
                    if (this.isDragging) {
                        updatePosition(e);
                    }
                });

                document.addEventListener('mouseup', () => {
                    this.isDragging = false;
                });
            }

            setTimeRange(start, end) {
                this.startTime = start;
                this.endTime = end;
                this.currentTime = start; // Start at 0.00s to show initial state

                document.getElementById('timelineStart').textContent = this.formatTime(0);
                document.getElementById('timelineEnd').textContent = this.formatTime(end - start);
                document.getElementById('timelineContainer').classList.add('active');

                this.updateUI();
                this.filterByTime(); // Apply initial filter
            }

            formatTime(seconds) {
                if (seconds < 60) {
                    return seconds.toFixed(2) + 's';
                } else if (seconds < 3600) {
                    const mins = Math.floor(seconds / 60);
                    const secs = (seconds % 60).toFixed(0);
                    return `${mins}m ${secs}s`;
                } else {
                    const hours = Math.floor(seconds / 3600);
                    const mins = Math.floor((seconds % 3600) / 60);
                    return `${hours}h ${mins}m`;
                }
            }

            updateUI() {
                const percent = ((this.currentTime - this.startTime) / (this.endTime - this.startTime)) * 100;
                document.getElementById('timelineProgress').style.width = percent + '%';
                document.getElementById('timelineTime').textContent = this.formatTime(this.currentTime - this.startTime);
            }

            setData(connections, hosts, packets) {
                this.allConnections = connections;
                this.allHosts = hosts;
                this.allPackets = packets || [];
            }

            filterByTime() {
                if (!visualizer) return;

                // Filter connections based on current time
                const filteredConnections = this.allConnections.filter(conn => {
                    // Check if connection has started by this time
                    return conn.startTime <= this.currentTime;
                });

                // Create filtered hosts based on connections up to this time
                const filteredHostIPs = new Set();
                filteredConnections.forEach(conn => {
                    filteredHostIPs.add(conn.source);
                    filteredHostIPs.add(conn.destination);
                });

                const filteredHosts = new Map();
                this.allHosts.forEach((host, ip) => {
                    if (filteredHostIPs.has(ip)) {
                        filteredHosts.set(ip, host);
                    }
                });

                // Update visualizer with filtered data
                const tempParser = {
                    hosts: filteredHosts,
                    connections: new Map(filteredConnections.map(conn =>
                        [`${conn.source}-${conn.destination}`, conn]
                    ))
                };

                visualizer.loadData(tempParser);
            }

            play() {
                if (this.isPlaying) return;

                this.isPlaying = true;
                // Disable jiggle physics during play
                if (visualizer) {
                    visualizer.animating = false;
                }
                this.playInterval = setInterval(() => {
                    // Advance by 1 second
                    this.currentTime += 1;

                    // Stop if we reach the end
                    if (this.currentTime >= this.endTime) {
                        this.pause();
                        this.currentTime = this.endTime;
                    }

                    this.updateUI();
                    this.filterByTime();
                }, 100); // Update every 100ms for smooth animation
            }

            pause() {
                this.isPlaying = false;
                if (this.playInterval) {
                    clearInterval(this.playInterval);
                    this.playInterval = null;
                }
                // Re-enable jiggle physics when stopped
                if (visualizer) {
                    visualizer.animating = true;
                }
            }

            togglePlay() {
                if (this.isPlaying) {
                    this.pause();
                } else {
                    // Reset if at end
                    if (this.currentTime >= this.endTime) {
                        this.currentTime = this.startTime;
                    }
                    this.play();
                }
                return this.isPlaying;
            }

            seekToTime(timestamp) {
                this.currentTime = timestamp;
                this.updateUI();
                this.filterByTime();
            }
        }

        // Helper function to format hex dump
        function formatHexDump(data, bytesPerLine = 16) {
            if (!data || data.length === 0) return 'No data available';

            const lines = [];
            for (let i = 0; i < data.length; i += bytesPerLine) {
                // Offset
                const offset = i.toString(16).padStart(4, '0');

                // Hex bytes
                const hexBytes = [];
                const asciiBytes = [];
                for (let j = 0; j < bytesPerLine; j++) {
                    if (i + j < data.length) {
                        const byte = data[i + j];
                        hexBytes.push(byte.toString(16).padStart(2, '0'));
                        asciiBytes.push((byte >= 32 && byte <= 126) ? String.fromCharCode(byte) : '.');
                    } else {
                        hexBytes.push('  ');
                        asciiBytes.push(' ');
                    }
                }

                // Format: offset  hex bytes (8) (8)  |ascii|
                const firstHalf = hexBytes.slice(0, 8).join(' ');
                const secondHalf = hexBytes.slice(8).join(' ');
                const hexPart = `${firstHalf} ${secondHalf}`.padEnd(48, ' '); // 16*2 + 15 spaces + 1 extra

                lines.push(`${offset} ${hexPart} |${asciiBytes.join('')}|`);
            }
            return lines.join('\n');
        }

        // Helper function to format ASCII dump
        function formatAsciiDump(data) {
            if (!data || data.length === 0) return 'No data available';

            return Array.from(data).map(b =>
                (b >= 32 && b <= 126) ? String.fromCharCode(b) : '.'
            ).join('');
        }

        // Toggle packet data display
        function togglePacketData(packetId, packetIndex) {
            const dataDiv = document.getElementById(`${packetId}-data`);
            if (!dataDiv) return;

            if (dataDiv.style.display === 'none') {
                // Show packet data
                const packet = window.currentNodePackets?.[packetIndex];
                if (packet && packet.data) {
                    const hexDump = formatHexDump(packet.data);
                    const asciiDump = formatAsciiDump(packet.data);

                    dataDiv.innerHTML = `
                        <div class="packet-data-title">Hex Dump</div>
                        <div class="packet-hex-dump">${hexDump}</div>
                        <div class="packet-data-title">ASCII Representation</div>
                        <div class="packet-ascii-dump">${asciiDump}</div>
                    `;
                    dataDiv.style.display = 'block';
                } else {
                    dataDiv.innerHTML = '<div style="color: #888; font-size: 10px;">No raw packet data available</div>';
                    dataDiv.style.display = 'block';
                }
            } else {
                // Hide packet data
                dataDiv.style.display = 'none';
            }
        }

        // Initialize application
        let parser = new PCAPParser();
        let visualizer;
        let timeline;
        let dnsCache = {};  // Global DNS cache for IP -> hostname mapping

        // Make visualizer globally accessible for search function
        window.visualizer = null;

        window.addEventListener('DOMContentLoaded', () => {
            const canvas = document.getElementById('networkCanvas');
            visualizer = new NetworkVisualizer(canvas);
            window.visualizer = visualizer;  // Expose to global scope
            timeline = new TimelineController();
            
            // File upload handling
            const uploadArea = document.getElementById('uploadArea');
            const fileInput = document.getElementById('fileInput');
            
            uploadArea.addEventListener('click', () => fileInput.click());
            
            uploadArea.addEventListener('dragover', (e) => {
                e.preventDefault();
                uploadArea.classList.add('dragover');
            });
            
            uploadArea.addEventListener('dragleave', () => {
                uploadArea.classList.remove('dragover');
            });
            
            uploadArea.addEventListener('drop', (e) => {
                e.preventDefault();
                uploadArea.classList.remove('dragover');
                handleFile(e.dataTransfer.files[0]);
            });
            
            fileInput.addEventListener('change', (e) => {
                handleFile(e.target.files[0]);
            });
            
            // Control buttons
            document.getElementById('playBtn').addEventListener('click', () => {
                const isPlaying = timeline.togglePlay();
                document.getElementById('playBtn').textContent = isPlaying ? '⏸️ Pause' : '▶️ Play';
            });
            
            document.getElementById('resetBtn').addEventListener('click', () => {
                visualizer.reset();
            });
            
            // Layout menu management
            let currentLayout = 'force';
            const layoutBtn = document.getElementById('layoutBtn');
            const settingsMenu = document.getElementById('settingsMenu');

            // Create layout submenu
            const layoutMenu = document.createElement('div');
            layoutMenu.className = 'layout-menu';
            layoutMenu.id = 'layoutMenu';
            layoutMenu.style.display = 'none';
            layoutMenu.innerHTML = `
                <button class="layout-option" data-layout="force">Force Directed</button>
                <button class="layout-option" data-layout="clustered">Clustered Subnet</button>
                <button class="layout-option" data-layout="clustered-host">Clustered Host</button>
                <button class="layout-option" data-layout="circular">Circular</button>
                <button class="layout-option" data-layout="hierarchical">Hierarchical</button>
                <button class="layout-option" data-layout="3d">3D Force Directed</button>
            `;
            settingsMenu.appendChild(layoutMenu);

            layoutBtn.addEventListener('click', () => {
                const isVisible = layoutMenu.style.display === 'block';
                layoutMenu.style.display = isVisible ? 'none' : 'block';
            });

            // Layout option selection
            document.querySelectorAll('.layout-option').forEach(option => {
                // Mark force as selected by default
                if (option.dataset.layout === 'force') {
                    option.classList.add('selected');
                }

                option.addEventListener('click', (e) => {
                    const layout = e.target.dataset.layout;
                    currentLayout = layout;
                    visualizer.setLayout(layout);
                    layoutMenu.style.display = 'none';

                    // Update button text
                    layoutBtn.textContent = '◫ ' + e.target.textContent;

                    // Mark selected
                    document.querySelectorAll('.layout-option').forEach(o => o.classList.remove('selected'));
                    e.target.classList.add('selected');
                });
            });

            // Close layout menu when clicking outside
            document.addEventListener('click', (e) => {
                if (!layoutBtn.contains(e.target) && !layoutMenu.contains(e.target)) {
                    layoutMenu.style.display = 'none';
                }
            });
            
            document.getElementById('filterBtn').addEventListener('click', () => {
                // Filter to show only suspicious nodes
                const alerts = parser.alerts;
                const suspiciousIPs = new Set(alerts.map(a => [a.source, a.destination]).flat());

                visualizer.nodes.forEach(node => {
                    if (!suspiciousIPs.has(node.ip)) {
                        node.hidden = !node.hidden;
                    }
                });

                // Hide edges connected to hidden nodes
                visualizer.edges.forEach(edge => {
                    edge.hidden = edge.source.hidden || edge.target.hidden;
                });
            });

            // Hide low traffic nodes button
            let lowTrafficHidden = false;
            document.getElementById('hideInactiveBtn').addEventListener('click', () => {
                lowTrafficHidden = !lowTrafficHidden;
                const btn = document.getElementById('hideInactiveBtn');

                if (lowTrafficHidden) {
                    btn.textContent = '◍ Show All';
                    // Calculate median traffic to determine threshold
                    const trafficValues = Array.from(visualizer.nodes.values())
                        .map(n => (n.packetsSent || 0) + (n.packetsReceived || 0))
                        .sort((a, b) => a - b);
                    const threshold = trafficValues[Math.floor(trafficValues.length * 0.3)] || 10;

                    visualizer.nodes.forEach(node => {
                        const totalPackets = (node.packetsSent || 0) + (node.packetsReceived || 0);
                        if (totalPackets < threshold) {
                            node.hidden = true;
                        }
                    });

                    // Hide edges connected to hidden nodes
                    visualizer.edges.forEach(edge => {
                        edge.hidden = edge.source.hidden || edge.target.hidden;
                    });
                } else {
                    btn.textContent = '◌ Hide Low Traffic';
                    visualizer.nodes.forEach(node => {
                        node.hidden = false;
                    });

                    // Show all edges when showing all nodes
                    visualizer.edges.forEach(edge => {
                        edge.hidden = false;
                    });
                }
            });

            // Sidebar toggle with logo
            const headerLogo = document.getElementById('headerLogo');
            if (headerLogo) {
                headerLogo.addEventListener('click', () => {
                    const container = document.getElementById('container');
                    container.classList.toggle('sidebar-hidden');
                });
            }

            // Sidebar reopen button
            document.getElementById('sidebarReopen').addEventListener('click', () => {
                const container = document.getElementById('container');
                container.classList.remove('sidebar-hidden');
            });

            // Dashboard close button
            document.getElementById('dashboardClose').addEventListener('click', () => {
                const dashboard = document.getElementById('nodeDashboard');
                dashboard.classList.remove('active');
                dashboard.classList.remove('expanded');
            });

            // Dashboard scroll expansion
            const nodeDashboard = document.getElementById('nodeDashboard');
            let scrollTimeout = null;

            nodeDashboard.addEventListener('scroll', () => {
                // Check if scrolled to top
                if (nodeDashboard.scrollTop === 0) {
                    // User is at the top and trying to scroll up - expand
                    nodeDashboard.classList.add('expanded');
                } else if (nodeDashboard.scrollTop > 50) {
                    // Scrolled down enough - collapse back to normal
                    clearTimeout(scrollTimeout);
                    scrollTimeout = setTimeout(() => {
                        nodeDashboard.classList.remove('expanded');
                    }, 500);
                }
            });

            // Wheel event for better detection of scroll-up at top
            nodeDashboard.addEventListener('wheel', (e) => {
                // Check if the scroll is happening inside the packet-list
                const packetList = document.getElementById('dashboardPackets');
                if (packetList && packetList.contains(e.target)) {
                    // Let the packet list handle its own scrolling
                    return;
                }

                if (nodeDashboard.scrollTop === 0 && e.deltaY < 0) {
                    // Trying to scroll up at the top - expand
                    e.preventDefault();
                    nodeDashboard.classList.add('expanded');
                }
            });

            // Packet section fullscreen toggle
            const packetSectionTitle = document.getElementById('packetSectionTitle');
            packetSectionTitle.addEventListener('click', () => {
                const dashboard = document.getElementById('nodeDashboard');
                dashboard.classList.toggle('fullscreen');

                // Update title text
                if (dashboard.classList.contains('fullscreen')) {
                    packetSectionTitle.innerHTML = 'Packet Data (Full View) <span style="font-size: 10px; opacity: 0.7;">↙ Click to collapse</span>';
                } else {
                    packetSectionTitle.innerHTML = 'Packet Data (Latest 20) <span style="font-size: 10px; opacity: 0.7;">↗ Click to expand</span>';
                }
            });

            // Search functionality
            const searchInput = document.getElementById('searchInput');
            const searchResults = document.getElementById('searchResults');
            let searchTimeout = null;

            // Show examples when search box is focused and empty
            searchInput.addEventListener('focus', (e) => {
                const searchTerm = e.target.value.trim();
                if (!searchTerm) {
                    showSearchExamples();
                }
            });

            // Real-time search while typing
            searchInput.addEventListener('input', (e) => {
                const searchTerm = e.target.value.trim();

                // Clear previous timeout
                if (searchTimeout) clearTimeout(searchTimeout);

                if (!searchTerm || searchTerm.length < 1) {
                    searchResults.classList.remove('active');
                    searchResults.innerHTML = '';
                    return;
                }

                // Debounce search by 300ms
                searchTimeout = setTimeout(() => {
                    if (window.visualizer && window.visualizer.allPackets && window.visualizer.allPackets.length > 0) {
                        const searchFunc = window.performRealtimeSearchV2 || window.performRealtimeSearch;
                        if (searchFunc) {
                            searchFunc(searchTerm);
                        }
                    } else {
                        searchResults.innerHTML = '<div style="padding: 20px; color: #666;">Loading visualization data...</div>';
                        searchResults.classList.add('active');
                    }
                }, 300);
            });

            // Enter key to select first result
            searchInput.addEventListener('keypress', (e) => {
                if (e.key === 'Enter') {
                    const searchTerm = searchInput.value.trim();
                    if (visualizer && searchTerm) {
                        const searchData = getSearchResults(searchTerm);
                        const results = searchData.results || searchData; // Handle both old and new format
                        if (results.length > 0) {
                            selectSearchResult(results[0], searchTerm);
                        }
                    }
                }
            });

            // Close search results when clicking outside
            document.addEventListener('click', (e) => {
                if (!e.target.closest('.search-container')) {
                    searchResults.classList.remove('active');
                }
            });

            // Function to show search examples
            function showSearchExamples() {
                const searchResults = document.getElementById('searchResults');
                const isDarkMode = document.body.classList.contains('dark-mode');
                const bgColor = isDarkMode ? 'rgba(0,153,255,0.05)' : 'rgba(0,153,255,0.08)';

                searchResults.innerHTML = `
                    <div style="padding: 16px;">
                        <div style="font-weight: bold; margin-bottom: 12px; color: #0099ff; font-size: 14px;">🔍 Advanced Search Features</div>

                        <div style="margin-bottom: 16px;">
                            <div style="font-weight: 600; font-size: 12px; margin-bottom: 8px; opacity: 0.9;">Text Search Examples:</div>
                            <div style="display: flex; flex-direction: column; gap: 6px; font-size: 11px;">
                                <div style="background: ${bgColor}; padding: 6px 10px; border-radius: 4px; font-family: monospace;">
                                    <strong>192.168.1.1</strong> - Search for specific IP address
                                </div>
                                <div style="background: ${bgColor}; padding: 6px 10px; border-radius: 4px; font-family: monospace;">
                                    <strong>GET /api</strong> - Find HTTP requests in packet payload
                                </div>
                                <div style="background: ${bgColor}; padding: 6px 10px; border-radius: 4px; font-family: monospace;">
                                    <strong>password</strong> - Search for sensitive strings in payloads
                                </div>
                                <div style="background: ${bgColor}; padding: 6px 10px; border-radius: 4px; font-family: monospace;">
                                    <strong>8080</strong> - Find packets using specific port
                                </div>
                            </div>
                        </div>

                        <div style="margin-bottom: 12px;">
                            <div style="font-weight: 600; font-size: 12px; margin-bottom: 8px; opacity: 0.9;">Hex Pattern Search:</div>
                            <div style="display: flex; flex-direction: column; gap: 6px; font-size: 11px;">
                                <div style="background: ${bgColor}; padding: 6px 10px; border-radius: 4px; font-family: monospace;">
                                    <strong>ff d8 ff e0</strong> - Search for byte patterns (JPEG header)
                                </div>
                                <div style="background: ${bgColor}; padding: 6px 10px; border-radius: 4px; font-family: monospace;">
                                    <strong>504b0304</strong> - Find ZIP file signatures
                                </div>
                            </div>
                        </div>

                        <div style="font-size: 11px; opacity: 0.7; margin-top: 12px; padding: 8px; background: rgba(0,153,255,0.03); border-left: 3px solid #0099ff; border-radius: 2px;">
                            💡 <strong>Tip:</strong> Search works across IP addresses, hostnames, protocols, ports, and full packet payloads. Results show up to 50 matches.
                        </div>
                    </div>
                `;
                searchResults.classList.add('active');
            }

            // Search icon toggle
            const searchIcon = document.getElementById('searchIcon');
            const searchContainer = document.getElementById('searchContainer');

            searchIcon.addEventListener('click', () => {
                const wasActive = searchContainer.classList.contains('active');
                searchContainer.classList.toggle('active');

                // Focus on search input when opening
                if (!wasActive && searchContainer.classList.contains('active')) {
                    setTimeout(() => {
                        searchInput.focus();
                        // Show search examples if input is empty
                        if (!searchInput.value) {
                            showSearchExamples();
                        }
                    }, 100); // Small delay to ensure container is visible
                }
            });

            // Settings cog toggle
            const settingsCog = document.getElementById('settingsCog');

            settingsCog.addEventListener('click', () => {
                settingsMenu.classList.toggle('active');
            });

            // Stream panel toggle
            const streamIcon = document.getElementById('streamIcon');
            const streamPanel = document.getElementById('streamPanel');

            streamIcon.addEventListener('click', () => {
                streamPanel.classList.toggle('active');
            });

            // Alerts panel
            const alertsIcon = document.getElementById('alertsIcon');
            const alertsPanel = document.getElementById('alertsPanel');
            const alertsPanelClose = document.getElementById('alertsPanelClose');
            const alertsHeaderBtn = document.getElementById('alertsHeaderBtn');
            const alertsSearchInput = document.getElementById('alertsSearchInput');
            const alertsPanelList = document.getElementById('alertsPanelList');
            let selectedAlert = null;

            function updateAlertsPanel() {
                alertsPanelList.innerHTML = '';
                const alerts = parser.alerts || [];

                alerts.forEach((alert, index) => {
                    const item = document.createElement('div');
                    item.className = 'alerts-panel-item';
                    item.dataset.index = index;

                    item.innerHTML = `
                        <div class="alert-panel-type">${alert.type}</div>
                        <div class="alert-panel-details">${alert.details}</div>
                        <div class="alert-panel-meta">
                            <span>Source: ${alert.source}</span>
                            <span>Dest: ${alert.destination || 'N/A'}</span>
                        </div>
                    `;

                    item.addEventListener('click', () => {
                        // Deselect previous
                        document.querySelectorAll('.alerts-panel-item').forEach(i => i.classList.remove('selected'));
                        item.classList.add('selected');
                        selectedAlert = alert;

                        // Show only nodes involved in alert
                        const involvedIPs = new Set([alert.source, alert.destination].filter(ip => ip));

                        visualizer.nodes.forEach(node => {
                            node.hidden = !involvedIPs.has(node.ip);
                        });

                        visualizer.edges.forEach(edge => {
                            edge.hidden = !involvedIPs.has(edge.source.ip) || !involvedIPs.has(edge.target.ip);
                        });

                        // Move timeline to alert timestamp if available
                        if (alert.timestamp && timeline) {
                            timeline.seekToTime(alert.timestamp);
                        }
                    });

                    alertsPanelList.appendChild(item);
                });
            }

            alertsIcon.addEventListener('click', () => {
                alertsPanel.classList.toggle('active');
                if (alertsPanel.classList.contains('active')) {
                    updateAlertsPanel();
                }
            });

            alertsHeaderBtn.addEventListener('click', () => {
                alertsPanel.classList.add('active');
                updateAlertsPanel();
            });

            alertsPanelClose.addEventListener('click', () => {
                alertsPanel.classList.remove('active');
                // Clear selection and show all nodes
                if (selectedAlert) {
                    selectedAlert = null;
                    visualizer.nodes.forEach(node => node.hidden = false);
                    visualizer.edges.forEach(edge => edge.hidden = false);
                }
            });

            // ========================================
            // Network Inventory Panel
            // ========================================

            const inventoryIcon = document.getElementById('inventoryIcon');
            const inventoryPanel = document.getElementById('inventoryPanel');
            const inventoryPanelClose = document.getElementById('inventoryPanelClose');
            const inventoryPanelList = document.getElementById('inventoryPanelList');
            const inventorySearchInput = document.getElementById('inventorySearchInput');
            const inventoryTotalHosts = document.getElementById('inventoryTotalHosts');
            const inventoryTotalTraffic = document.getElementById('inventoryTotalTraffic');

            function updateInventoryPanel(searchTerm = '') {
                if (!visualizer || !visualizer.nodes) return;

                // Collect and sort nodes by total traffic (noisiest first)
                const nodes = Array.from(visualizer.nodes.values())
                    .map(node => {
                        const totalTraffic = (node.bytesSent || 0) + (node.bytesReceived || 0);
                        const totalPackets = (node.packetsSent || 0) + (node.packetsReceived || 0);

                        // Get top 5 protocols by packet count
                        const protocolCounts = {};
                        node.packets?.forEach(packet => {
                            const proto = packet.protocol || 'Unknown';
                            protocolCounts[proto] = (protocolCounts[proto] || 0) + 1;
                        });

                        const topProtocols = Object.entries(protocolCounts)
                            .sort((a, b) => b[1] - a[1])
                            .slice(0, 5)
                            .map(([proto, count]) => ({ protocol: proto, count }));

                        // If no packets, use protocols from the Set
                        if (topProtocols.length === 0 && node.protocols) {
                            node.protocols.forEach(proto => {
                                topProtocols.push({ protocol: proto, count: 0 });
                            });
                        }

                        return {
                            ...node,
                            totalTraffic,
                            totalPackets,
                            topProtocols: topProtocols.slice(0, 5)
                        };
                    })
                    .filter(node => {
                        if (!searchTerm) return true;
                        const term = searchTerm.toLowerCase();
                        return node.ip.toLowerCase().includes(term) ||
                               (node.mac && node.mac.toLowerCase().includes(term));
                    })
                    .sort((a, b) => b.totalTraffic - a.totalTraffic);

                // Update stats
                inventoryTotalHosts.textContent = nodes.length;
                const totalTrafficMB = nodes.reduce((sum, n) => sum + n.totalTraffic, 0) / (1024 * 1024);
                inventoryTotalTraffic.textContent = totalTrafficMB.toFixed(2) + ' MB';

                // Clear and populate list
                inventoryPanelList.innerHTML = '';

                nodes.forEach(node => {
                    const item = document.createElement('div');
                    item.className = 'inventory-item';
                    item.dataset.ip = node.ip;

                    const trafficMB = (node.totalTraffic / (1024 * 1024)).toFixed(2);
                    const activityLevel = node.totalPackets > 1000 ? 'High' :
                                         node.totalPackets > 100 ? 'Medium' : 'Low';

                    const protocolBadges = node.topProtocols
                        .map(p => `<span class="inventory-protocol-badge">${p.protocol}</span>`)
                        .join('');

                    const macAddress = node.mac || 'N/A (No Layer 2 data)';

                    item.innerHTML = `
                        <div class="inventory-item-header">
                            <div class="inventory-item-ip">${node.ip}</div>
                            <div class="inventory-item-activity">${trafficMB} MB</div>
                        </div>
                        <div class="inventory-item-mac">MAC: ${macAddress}</div>
                        <div class="inventory-item-protocols">
                            ${protocolBadges || '<span class="inventory-protocol-badge">No protocols</span>'}
                        </div>
                    `;

                    // Click to highlight and zoom to node
                    item.addEventListener('click', () => {
                        if (visualizer) {
                            visualizer.focusOnNode(node);
                        }
                    });

                    inventoryPanelList.appendChild(item);
                });
            }

            inventoryIcon.addEventListener('click', () => {
                inventoryPanel.classList.toggle('active');
                if (inventoryPanel.classList.contains('active')) {
                    updateInventoryPanel();
                }
            });

            inventoryPanelClose.addEventListener('click', () => {
                inventoryPanel.classList.remove('active');
            });

            // Search inventory
            inventorySearchInput.addEventListener('input', (e) => {
                updateInventoryPanel(e.target.value);
            });

            // Update inventory when data changes
            window.addEventListener('visualizerUpdated', () => {
                if (inventoryPanel.classList.contains('active')) {
                    updateInventoryPanel(inventorySearchInput.value);
                }
            });

            // Search alerts
            alertsSearchInput.addEventListener('input', (e) => {
                const searchTerm = e.target.value.toLowerCase();
                const items = alertsPanelList.querySelectorAll('.alerts-panel-item');

                items.forEach(item => {
                    const text = item.textContent.toLowerCase();
                    if (text.includes(searchTerm)) {
                        item.style.display = 'block';
                    } else {
                        item.style.display = 'none';
                    }
                });
            });

            // Legend toggle
            const legendIcon = document.getElementById('legendIcon');
            const protocolLegend = document.getElementById('protocolLegend');

            legendIcon.addEventListener('click', () => {
                protocolLegend.classList.toggle('active');
            });

            // Protocol filter
            let selectedProtocol = null;
            const legendItems = document.querySelectorAll('.legend-item');

            legendItems.forEach(item => {
                item.addEventListener('click', (e) => {
                    e.stopPropagation();
                    const protocol = item.dataset.protocol;

                    // Toggle selection
                    if (selectedProtocol === protocol) {
                        // Deselect - show all
                        selectedProtocol = null;
                        legendItems.forEach(i => {
                            i.classList.remove('selected', 'dimmed');
                        });
                        visualizer.filterByProtocol(null);
                    } else {
                        // Select this protocol
                        selectedProtocol = protocol;
                        legendItems.forEach(i => {
                            if (i.dataset.protocol === protocol) {
                                i.classList.add('selected');
                                i.classList.remove('dimmed');
                            } else {
                                i.classList.remove('selected');
                                i.classList.add('dimmed');
                            }
                        });
                        visualizer.filterByProtocol(protocol);
                    }
                });
            });

            // Line rider toggle
            const riderIcon = document.getElementById('riderIcon');
            riderIcon.addEventListener('click', () => {
                if (visualizer) {
                    visualizer.startLineRider();
                }
            });

            // Close menus when clicking outside
            document.addEventListener('click', (e) => {
                if (!searchIcon.contains(e.target) && !searchContainer.contains(e.target)) {
                    searchContainer.classList.remove('active');
                }
                if (!settingsCog.contains(e.target) && !settingsMenu.contains(e.target)) {
                    settingsMenu.classList.remove('active');
                }
                if (!streamIcon.contains(e.target) && !streamPanel.contains(e.target)) {
                    streamPanel.classList.remove('active');
                }
                if (!legendIcon.contains(e.target) && !protocolLegend.contains(e.target)) {
                    protocolLegend.classList.remove('active');
                }
                if (!alertsIcon.contains(e.target) && !alertsPanel.contains(e.target) && !alertsHeaderBtn.contains(e.target)) {
                    if (alertsPanel.classList.contains('active')) {
                        alertsPanel.classList.remove('active');
                        // Clear selection and show all nodes
                        if (selectedAlert) {
                            selectedAlert = null;
                            visualizer.nodes.forEach(node => node.hidden = false);
                            visualizer.edges.forEach(edge => edge.hidden = false);
                        }
                    }
                }
            });

            // Jiggle toggle
            const jiggleBtn = document.getElementById('jiggleBtn');
            jiggleBtn.addEventListener('click', () => {
                visualizer.animating = !visualizer.animating;
                jiggleBtn.textContent = visualizer.animating ? '◎ Jiggle Off' : '◉ Jiggle On';

                // Save preference
                localStorage.setItem('jiggle', visualizer.animating ? 'on' : 'off');
            });

            // Save capture button (only visible in live mode)
            document.getElementById('saveCaptureBtn').addEventListener('click', () => {
                if (confirm('Save current capture to file and start a new capture session?')) {
                    console.log('[Frontend] Requesting save and restart of capture');
                    socket.emit('save_and_restart_capture', {});
                }
            });

            // Load saved jiggle preference (default to on)
            const savedJiggle = localStorage.getItem('jiggle') || 'on';
            if (savedJiggle === 'off') {
                visualizer.animating = false;
                jiggleBtn.textContent = '◉ Jiggle On';
            }

            // Theme toggle
            const themeBtn = document.getElementById('themeBtn');
            themeBtn.addEventListener('click', () => {
                document.body.classList.toggle('dark-mode');
                const isDark = document.body.classList.contains('dark-mode');
                themeBtn.textContent = isDark ? '◑ Light Mode' : '◐ Dark Mode';

                // Save preference
                localStorage.setItem('theme', isDark ? 'dark' : 'light');
            });

            // Load saved theme preference (default to light mode)
            const savedTheme = localStorage.getItem('theme') || 'light';
            if (savedTheme === 'dark') {
                document.body.classList.add('dark-mode');
                themeBtn.textContent = '◑ Light Mode';
            }

            // Check for autoload file
            fetch('/autoload')
                .then(response => response.json())
                .then(data => {
                    if (data.autoload !== false) {
                        // File was autoloaded, process it
                        console.log('Auto-loading PCAP file...');
                        processBackendData(data);
                    }
                })
                .catch(err => {
                    console.log('No autoload file or error:', err);
                });
        });
        
        function handleFile(file) {
            if (!file) return;

            const loadingOverlay = document.getElementById('loadingOverlay');
            loadingOverlay.classList.add('active');
            document.getElementById('loadingProgress').textContent = 'Uploading...';

            // Create FormData and upload to backend
            const formData = new FormData();
            formData.append('file', file);

            fetch('/upload', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                if (data.error) {
                    throw new Error(data.error);
                }

                document.getElementById('loadingProgress').textContent = '100%';

                // Process the backend response
                processBackendData(data);

                loadingOverlay.classList.remove('active');
            })
            .catch(error => {
                console.error('Error processing PCAP:', error);
                alert('Error processing PCAP file: ' + error.message);
                loadingOverlay.classList.remove('active');
            });
        }

        function processBackendData(data) {
            // Convert backend data to parser format
            parser = new PCAPParser();

            // Store packets if available from backend
            parser.packets = data.packets || [];
            console.log(`[Backend] Loaded ${parser.packets.length} packets, ${data.hosts.length} hosts, ${data.connections.length} connections`);

            parser.hosts = new Map();
            parser.connections = new Map();
            parser.protocols = new Map();
            parser.alerts = data.alerts || [];

            // Convert hosts array to Map
            data.hosts.forEach(host => {
                parser.hosts.set(host.ip, {
                    ...host,
                    protocols: new Set(host.protocols),
                    connections: new Set(host.connections)
                });
            });

            // Convert connections array to Map and track timestamps
            let minTime = Infinity;
            let maxTime = -Infinity;

            data.connections.forEach(conn => {
                const key = `${conn.source}-${conn.destination}`;
                parser.connections.set(key, conn);

                // Track time range
                if (conn.startTime) {
                    minTime = Math.min(minTime, conn.startTime);
                    maxTime = Math.max(maxTime, conn.lastTime || conn.startTime);
                }
            });

            // Build protocol counts from connections
            data.connections.forEach(conn => {
                if (conn.protocol) {
                    parser.protocols.set(
                        conn.protocol,
                        (parser.protocols.get(conn.protocol) || 0) + conn.packets
                    );
                }
            });

            // Store summary stats for UI update
            parser.summary = data.summary;

            // Update UI with parsed data
            updateStats();
            updateAlerts();

            // Load data into visualizer (pass parser with packets)
            visualizer.loadData(parser);

            // Initialize timeline if we have time data
            if (minTime !== Infinity && maxTime !== -Infinity) {
                timeline.setData(data.connections, parser.hosts, parser.packets);
                timeline.setTimeRange(minTime, maxTime);
            }

            // Populate TCP/HTTP streams
            populateStreamList(data.connections);
        }

        function populateStreamList(connections) {
            const streamList = document.getElementById('streamList');

            // Filter for TCP and HTTP streams
            const tcpHttpStreams = connections.filter(conn =>
                conn.protocol === 'TCP' ||
                conn.protocol === 'HTTP' ||
                conn.protocol === 'HTTPS' ||
                conn.protocol === 'SSH' ||
                conn.protocol === 'FTP'
            );

            if (tcpHttpStreams.length === 0) {
                streamList.innerHTML = '<div style="color: #666; text-align: center; padding: 20px;">No TCP/HTTP/FTP streams found</div>';
                return;
            }

            // Sort by packet count (most active first)
            tcpHttpStreams.sort((a, b) => b.packets - a.packets);

            let streamsHtml = '';
            tcpHttpStreams.forEach((stream, idx) => {
                const duration = ((stream.lastTime - stream.startTime) || 0).toFixed(2);
                streamsHtml += `
                    <div class="stream-item" onclick="selectStream(${idx})">
                        <div class="stream-item-header">${stream.protocol} Stream #${idx + 1}</div>
                        <div class="stream-item-detail">
                            ${stream.source} → ${stream.destination}<br>
                            Packets: ${stream.packets.toLocaleString()} |
                            Bytes: ${(stream.bytes / 1024).toFixed(2)} KB<br>
                            Duration: ${duration}s
                        </div>
                    </div>
                `;
            });
            streamList.innerHTML = streamsHtml;

            // Store streams for later selection
            window.currentStreams = tcpHttpStreams;
        }

        function populateLiveStreamList(edges) {
            const streamList = document.getElementById('streamList');

            // Convert edges Map to array and filter for TCP/HTTP/FTP streams
            const edgeArray = Array.from(edges.values());
            const tcpHttpStreams = edgeArray.filter(edge =>
                edge.protocol === 'TCP' ||
                edge.protocol === 'HTTP' ||
                edge.protocol === 'HTTPS' ||
                edge.protocol === 'SSH' ||
                edge.protocol === 'FTP'
            );

            if (tcpHttpStreams.length === 0) {
                streamList.innerHTML = '<div style="color: #666; text-align: center; padding: 20px;">No TCP/HTTP/FTP streams found</div>';
                return;
            }

            // Sort by packet count (most active first)
            tcpHttpStreams.sort((a, b) => (b.packets || 0) - (a.packets || 0));

            let streamsHtml = '';
            tcpHttpStreams.forEach((edge, idx) => {
                const sourceIP = edge.source?.ip || edge.source || 'Unknown';
                const destIP = edge.target?.ip || edge.target || 'Unknown';
                const packets = edge.packets || 0;
                const bytes = edge.bytes || 0;

                streamsHtml += `
                    <div class="stream-item" onclick="selectLiveStream(${idx})">
                        <div class="stream-item-header">${edge.protocol} Stream #${idx + 1}</div>
                        <div class="stream-item-detail">
                            ${sourceIP} → ${destIP}<br>
                            Packets: ${packets.toLocaleString()} |
                            Bytes: ${(bytes / 1024).toFixed(2)} KB
                        </div>
                    </div>
                `;
            });
            streamList.innerHTML = streamsHtml;

            // Store streams for later selection
            window.currentLiveStreams = tcpHttpStreams;
        }

        function selectStream(streamIndex) {
            if (!window.currentStreams || !window.currentStreams[streamIndex]) return;

            const stream = window.currentStreams[streamIndex];

            // Find the edge in the visualizer that matches this stream
            const edge = Array.from(visualizer.edges.values()).find(e =>
                (e.source.ip === stream.source && e.target.ip === stream.destination) ||
                (e.source.ip === stream.destination && e.target.ip === stream.source)
            );

            if (edge) {
                // Show edge dashboard with stream details
                visualizer.showEdgePackets(edge);
                // Close stream panel
                document.getElementById('streamPanel').classList.remove('active');
            }
        }

        function selectLiveStream(streamIndex) {
            if (!window.currentLiveStreams || !window.currentLiveStreams[streamIndex]) return;

            const edge = window.currentLiveStreams[streamIndex];

            if (edge) {
                // Show edge dashboard with stream details
                visualizer.showEdgePackets(edge);
                // Close stream panel
                document.getElementById('streamPanel').classList.remove('active');
            }
        }

        // getSearchResults is now defined in search-handler.js with full payload search
        // performRealtimeSearch is now defined in search-handler.js
        // selectSearchResultByIndex and selectSearchResult are also in search-handler.js

        // OLD FUNCTIONS REMOVED - Now using versions from search-handler.js
        // which include better packet detail display and highlighting

        function updateStats() {
            // Use summary data from backend if available
            if (parser.summary) {
                document.getElementById('totalPackets').textContent = parser.summary.totalPackets.toLocaleString();
                document.getElementById('uniqueHosts').textContent = parser.summary.uniqueHosts;
                document.getElementById('activeConnections').textContent = parser.summary.activeConnections;
                document.getElementById('dataVolume').textContent = parser.summary.dataVolumeMB;
                document.getElementById('avgPacketSize').textContent = parser.summary.avgPacketSize;
                document.getElementById('protocolCount').textContent = parser.summary.protocolCount;
                document.getElementById('packetsPerSec').textContent = parser.summary.packetsPerSec;
                document.getElementById('bandwidth').textContent = parser.summary.bandwidthMbps + ' Mbps';
                document.getElementById('activeFlows').textContent = parser.summary.activeConnections;
                document.getElementById('threats').textContent = parser.summary.threatsFound;
                document.getElementById('alertCount').textContent = parser.summary.threatsFound;
            } else {
                // Fallback to client-side calculation (legacy support)
                document.getElementById('totalPackets').textContent = parser.packets.length.toLocaleString();
                document.getElementById('uniqueHosts').textContent = parser.hosts.size;
                document.getElementById('activeConnections').textContent = parser.connections.size;

                let totalBytes = 0;
                parser.packets.forEach(p => totalBytes += p.length);
                document.getElementById('dataVolume').textContent = (totalBytes / 1048576).toFixed(2);

                document.getElementById('avgPacketSize').textContent = Math.round(totalBytes / parser.packets.length);
                document.getElementById('protocolCount').textContent = parser.protocols.size;

                // Update real-time metrics
                const duration = parser.packets.length > 0 ?
                    parser.packets[parser.packets.length - 1].timestamp - parser.packets[0].timestamp : 1;

                document.getElementById('packetsPerSec').textContent = Math.round(parser.packets.length / duration);
                document.getElementById('bandwidth').textContent = ((totalBytes * 8 / duration) / 1000000).toFixed(2) + ' Mbps';
                document.getElementById('activeFlows').textContent = parser.connections.size;
                document.getElementById('threats').textContent = parser.alerts.length;
                document.getElementById('alertCount').textContent = parser.alerts.length;
            }
        }
        
        function updateAlerts() {
            const alertsList = document.getElementById('alertsList');
            alertsList.innerHTML = '';

            // Show only recent alerts
            parser.alerts.slice(-10).reverse().forEach(alert => {
                const alertItem = document.createElement('div');
                alertItem.className = 'alert-item';
                alertItem.innerHTML = `
                    <div class="alert-type">${alert.type}</div>
                    <div class="alert-details">
                        ${alert.source} → ${alert.destination}<br>
                        ${alert.details}
                    </div>
                `;

                // Add click handler to jump to the nodes in the graph
                alertItem.addEventListener('click', () => {
                    if (visualizer && alert.source && alert.destination) {
                        visualizer.focusOnConnection(alert.source, alert.destination);
                    }
                });

                alertsList.appendChild(alertItem);
            });

            // Update alerts panel if it's open
            const alertsPanel = document.getElementById('alertsPanel');
            if (alertsPanel && alertsPanel.classList.contains('active')) {
                updateAlertsPanel();
            }
        }

        // ========================================
        // WebSocket / Live Capture Support
        // ========================================

        let socket = null;
        let liveMode = false;

        function initWebSocket() {
            // Initialize Socket.IO connection
            console.log('[Frontend] Initializing WebSocket connection...');
            socket = io();

            socket.on('connect', () => {
                console.log('[Frontend] WebSocket connected, socket ID:', socket.id);
            });

            socket.on('disconnect', () => {
                console.log('[Frontend] WebSocket disconnected');
            });

            // When interface is ready for live capture
            socket.on('interface_ready', (data) => {
                console.log('[Frontend] Live capture interface ready:', data.interface);

                // Auto-start capture (only sent when no capture is running)
                console.log('[Frontend] Auto-starting live capture');
                startLiveCapture();
            });

            // When capture starts
            socket.on('capture_started', (data) => {
                console.log('[Frontend] Live capture started on interface:', data.interface);
                console.log('[Frontend] Setting liveMode to true');
                liveMode = true;

                // Show save capture button
                document.getElementById('saveCaptureBtn').style.display = 'block';

                // Initialize visualizer if not already created
                if (!visualizer) {
                    console.log('[Frontend] Creating new NetworkVisualizer');
                    const canvas = document.getElementById('networkCanvas');
                    visualizer = new NetworkVisualizer(canvas);
                    window.visualizer = visualizer;  // Expose to global scope
                    console.log('[Frontend] Visualizer started (animation loop auto-runs)');
                } else {
                    console.log('[Frontend] Visualizer already exists');
                }

                // Enable live mode aging/fading
                if (visualizer) {
                    visualizer.setLiveMode(true);
                }

                // Show a notification or update UI
                const loadingOverlay = document.getElementById('loadingOverlay');
                const loadingText = document.querySelector('.loading-text');
                loadingOverlay.classList.add('active');
                loadingText.textContent = `Capturing packets on ${data.interface}...`;

                // Hide after 2 seconds
                setTimeout(() => {
                    loadingOverlay.classList.remove('active');
                }, 2000);
            });

            // When capture stops
            socket.on('capture_stopped', () => {
                console.log('Live capture stopped');
                liveMode = false;

                // Hide save capture button
                document.getElementById('saveCaptureBtn').style.display = 'none';

                // Disable live mode aging/fading
                if (visualizer) {
                    visualizer.setLiveMode(false);
                }
            });

            // When capture is saved and restarted
            socket.on('capture_restarted', (data) => {
                console.log('[Frontend] Capture saved and restarted on interface:', data.interface);

                // Clear current visualization for new session
                if (visualizer) {
                    visualizer.nodes.clear();
                    visualizer.edges = [];
                    visualizer.allPackets = [];
                }

                // Clear parser data
                if (parser) {
                    parser.packets = [];
                    parser.hosts.clear();
                    parser.connections = [];
                    parser.alerts = [];
                }

                // Show notification
                alert('Previous capture saved! Starting new capture session...');
            });

            // When there's a PCAP save notification
            socket.on('pcap_saved', (data) => {
                console.log(`[Frontend] PCAP saved: ${data.filename} (${data.packet_count} packets)`);
            });

            // Packet processing with limits
            const MAX_PACKETS_STORED = 10000; // Limit stored packets to prevent memory issues
            const MAX_NODES = 500; // Limit nodes to prevent performance degradation
            let lastUIUpdate = 0;
            let updateScheduled = false;

            function scheduleUIUpdate() {
                if (updateScheduled) return;
                updateScheduled = true;

                requestAnimationFrame(() => {
                    updateStats();
                    if (parser.alerts.length > 0) {
                        updateAlerts();
                    }
                    updateScheduled = false;
                });
            }

            // When a batch of packets arrives (every 2 seconds)
            socket.on('packet_batch', (data) => {
                console.log(`[Frontend] Received packet_batch. Packets: ${data.count}, Nodes: ${data.nodes?.length}, Edges: ${data.edges?.length}`);

                // If we're receiving packets but not in live mode, it means capture is running from before page refresh
                if (!liveMode) {
                    console.log('[Frontend] Packets arriving but not in live mode - capture must be running, enabling live mode');
                    liveMode = true;

                    // Show save capture button
                    document.getElementById('saveCaptureBtn').style.display = 'block';

                    // Initialize visualizer if needed
                    if (!visualizer) {
                        const canvas = document.getElementById('networkCanvas');
                        visualizer = new NetworkVisualizer(canvas);
                        window.visualizer = visualizer;  // Expose to global scope
                    }

                    if (visualizer) {
                        visualizer.setLiveMode(true);
                    }
                }

                // Use pre-aggregated nodes and edges from backend
                if (data.nodes && data.edges && visualizer) {
                    console.log(`[Frontend] Using pre-aggregated data from backend`);

                    // Update visualizer with backend-computed nodes
                    data.nodes.forEach(nodeData => {
                        if (!visualizer.nodes.has(nodeData.ip) && visualizer.nodes.size < MAX_NODES) {
                            // Create new node with backend data
                            visualizer.nodes.set(nodeData.ip, {
                                ip: nodeData.ip,
                                hostname: nodeData.hostname || null,  // Add hostname
                                mac: nodeData.mac || null,  // Add MAC address
                                x: Math.random() * visualizer.canvas.width / window.devicePixelRatio,
                                y: Math.random() * visualizer.canvas.height / window.devicePixelRatio,
                                z: Math.random() * 500 - 250,
                                vx: 0,
                                vy: 0,
                                vz: 0,
                                connections: nodeData.connections,
                                packets: [],
                                protocols: new Set(nodeData.protocols),
                                packetsSent: nodeData.packetsSent,
                                packetsReceived: nodeData.packetsReceived,
                                bytesSent: nodeData.bytesSent,
                                bytesReceived: nodeData.bytesReceived,
                                radius: Math.min(30, 10 + Math.sqrt(nodeData.packetsSent + nodeData.packetsReceived) * 2),
                                lastActivity: Date.now(),
                                attentionScore: 0
                            });
                        } else if (visualizer.nodes.has(nodeData.ip)) {
                            // Update existing node
                            const node = visualizer.nodes.get(nodeData.ip);
                            node.hostname = nodeData.hostname || node.hostname;  // Update hostname if resolved
                            node.mac = nodeData.mac || node.mac;  // Update MAC address if available
                            node.packetsSent = nodeData.packetsSent;
                            node.packetsReceived = nodeData.packetsReceived;
                            node.bytesSent = nodeData.bytesSent;
                            node.bytesReceived = nodeData.bytesReceived;
                            node.connections = nodeData.connections;
                            node.protocols = new Set(nodeData.protocols);
                            node.radius = Math.min(30, 10 + Math.sqrt(nodeData.packetsSent + nodeData.packetsReceived) * 2);
                            node.lastActivity = Date.now();
                        }
                    });

                    // Update edges with backend data
                    data.edges.forEach(edgeData => {
                        const sourceNode = visualizer.nodes.get(edgeData.source);
                        const targetNode = visualizer.nodes.get(edgeData.destination);

                        if (sourceNode && targetNode) {
                            const edgeKey = `${edgeData.source}-${edgeData.destination}`;
                            let edge = visualizer.edges.find(e => e.key === edgeKey || e.key === `${edgeData.destination}-${edgeData.source}`);

                            if (!edge) {
                                visualizer.edges.push({
                                    key: edgeKey,
                                    source: sourceNode,
                                    target: targetNode,
                                    packets: [],
                                    protocol: edgeData.protocol,
                                    weight: edgeData.packets,
                                    bytes: edgeData.bytes
                                });
                            } else {
                                edge.weight = edgeData.packets;
                                edge.bytes = edgeData.bytes;
                            }
                        }
                    });
                }

                // Update global DNS cache
                if (data.dnsCache) {
                    Object.assign(dnsCache, data.dnsCache);
                }

                // Process packets for threat detection and packet details
                data.packets.forEach((packet) => {
                    parser.packets.push(packet);

                    // Add to visualizer's allPackets for stream/packet detail views
                    if (visualizer && visualizer.allPackets) {
                        visualizer.allPackets.push(packet);

                        // Limit stored packets in visualizer too
                        if (visualizer.allPackets.length > MAX_PACKETS_STORED) {
                            visualizer.allPackets.splice(0, 1000);
                        }
                    }

                    // Store packets on edges for edge-specific packet display
                    if (visualizer) {
                        const edge = visualizer.edges.find(e =>
                            (e.source.ip === packet.source && e.target.ip === packet.destination) ||
                            (e.source.ip === packet.destination && e.target.ip === packet.source)
                        );
                        if (edge) {
                            if (!edge.packets) edge.packets = [];
                            edge.packets.push(packet);
                            // Limit packets per edge
                            if (edge.packets.length > 100) {
                                edge.packets.shift();
                            }
                        }
                    }

                    // Store packets on nodes for node-specific packet display
                    if (visualizer) {
                        const srcNode = visualizer.nodes.get(packet.source);
                        const dstNode = visualizer.nodes.get(packet.destination);

                        if (srcNode) {
                            if (!srcNode.packets) srcNode.packets = [];
                            srcNode.packets.push(packet);
                            if (srcNode.packets.length > 100) {
                                srcNode.packets.shift();
                            }
                        }

                        if (dstNode) {
                            if (!dstNode.packets) dstNode.packets = [];
                            dstNode.packets.push(packet);
                            if (dstNode.packets.length > 100) {
                                dstNode.packets.shift();
                            }
                        }
                    }

                    // Run threat detection on packets
                    parser.updateStats(packet);

                    // Limit stored packets in parser
                    if (parser.packets.length > MAX_PACKETS_STORED) {
                        parser.packets.splice(0, 1000);
                    }
                });

                // Update parser's host and connection data from backend
                if (data.nodes) {
                    data.nodes.forEach(nodeData => {
                        if (!parser.hosts.has(nodeData.ip)) {
                            parser.hosts.set(nodeData.ip, {
                                ip: nodeData.ip,
                                packetsSent: nodeData.packetsSent,
                                packetsReceived: nodeData.packetsReceived,
                                bytesSent: nodeData.bytesSent,
                                bytesReceived: nodeData.bytesReceived,
                                protocols: new Set(nodeData.protocols),
                                ports: new Set(),
                                connections: nodeData.connections
                            });
                        } else {
                            const host = parser.hosts.get(nodeData.ip);
                            host.packetsSent = nodeData.packetsSent;
                            host.packetsReceived = nodeData.packetsReceived;
                            host.bytesSent = nodeData.bytesSent;
                            host.bytesReceived = nodeData.bytesReceived;
                            host.protocols = new Set(nodeData.protocols);
                            host.connections = nodeData.connections;
                        }
                    });
                }

                console.log(`[Frontend] Visualizer state: ${visualizer.nodes.size} nodes, ${visualizer.edges.length} edges`);

                // Update stream list in live mode (always update to keep it fresh)
                if (visualizer && visualizer.edges) {
                    populateLiveStreamList(visualizer.edges);
                }

                // Schedule UI update
                scheduleUIUpdate();
            });

            // Additional periodic stream list update for live mode (every 1 second)
            let streamUpdateInterval = null;
            socket.on('capture_started', () => {
                if (streamUpdateInterval) clearInterval(streamUpdateInterval);

                streamUpdateInterval = setInterval(() => {
                    if (liveMode && visualizer && visualizer.edges) {
                        populateLiveStreamList(visualizer.edges);
                    }
                }, 1000); // Update every second
            });

            socket.on('capture_stopped', () => {
                if (streamUpdateInterval) {
                    clearInterval(streamUpdateInterval);
                    streamUpdateInterval = null;
                }
            });

            socket.on('capture_restarted', () => {
                if (streamUpdateInterval) clearInterval(streamUpdateInterval);

                streamUpdateInterval = setInterval(() => {
                    if (liveMode && visualizer && visualizer.edges) {
                        populateLiveStreamList(visualizer.edges);
                    }
                }, 1000);
            });

            // Also keep individual packet handler for backwards compatibility
            socket.on('live_packet', (packet) => {
                if (!liveMode) return;

                parser.packets.push(packet);

                // Limit stored packets
                if (parser.packets.length > MAX_PACKETS_STORED) {
                    parser.packets.shift();
                }

                parser.updateStats(packet);

                if (visualizer && visualizer.nodes.size < MAX_NODES) {
                    visualizer.addLivePacket(packet);
                }

                // Update UI every 10 packets
                if (parser.packets.length % 10 === 0) {
                    scheduleUIUpdate();
                }

                if (parser.alerts.length > 0) {
                    updateAlerts();
                }
            });

            // Handle errors
            socket.on('capture_error', (data) => {
                console.error('Capture error:', data.error);
                alert(`Live capture error: ${data.error}`);
                liveMode = false;

                // Disable live mode aging/fading
                if (visualizer) {
                    visualizer.setLiveMode(false);
                }
            });

            // When PCAP is saved
            socket.on('pcap_saved', (data) => {
                console.log(`Saved ${data.packet_count} packets to ${data.filename}`);
                alert(`Live capture saved: ${data.filename} (${data.packet_count} packets)`);
            });
        }

        function startLiveCapture() {
            if (!socket) {
                initWebSocket();
            }
            socket.emit('start_capture', {});
        }

        function stopLiveCapture() {
            if (socket) {
                socket.emit('stop_capture', {});
            }
        }

        // Initialize WebSocket connection on page load
        window.addEventListener('DOMContentLoaded', () => {
            initWebSocket();
        });

