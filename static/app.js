// Protocol color mapping (must match server-side)
const PROTOCOL_COLORS = {
    'TCP': '#3498db',
    'UDP': '#2ecc71',
    'ICMP': '#f39c12',
    'HTTP': '#e67e22',
    'HTTPS': '#9b59b6',
    'DNS': '#1abc9c',
    'SSH': '#e74c3c',
    'FTP': '#ff6b9d',
    'SMTP': '#8b4513',
    'MySQL': '#34495e',
    'PostgreSQL': '#16a085',
    'InfluxDB': '#22ADF6',
    'Slurm': '#ff7f50',
    'ARP': '#95a5a6',
    'IPv6': '#7f8c8d',
    'Other': '#ecf0f1'
};

// Global state
let network = null;
let nodes = new vis.DataSet();
let edges = new vis.DataSet();
let ws = null;
let protocolFilters = new Set();
let packets = []; // Store captured packets
let packetCache = new Map(); // Persistent packet cache by ID
let selectedPacketId = null;
let selectedPacketIndex = -1; // Track selected packet index for keyboard navigation
let currentClusterLayout = 'force'; // Track current cluster layout
const MAX_CACHED_PACKETS = 5000; // Keep last 5000 packets in memory

// Performance optimization settings
const MAX_NODES = 100; // Maximum nodes to display
const MAX_EDGES = 200; // Maximum edges to display
let UPDATE_THROTTLE_MS = 150; // Base throttle (dynamically adjusted)
let lastUpdateTime = 0;
let pendingUpdate = null;
let updateScheduled = false;

// Delta update tracking - only update nodes/edges that actually changed
const nodeStateCache = new Map(); // id -> { packetCount, byteCount, colorTier }
const edgeStateCache = new Map(); // id -> { packetCount, byteCount }
let lastPacketPanelRefresh = 0;

// Physics damping control for burst node additions
let physicsDampingTimeout = null;


// Replay mode state
let replayMode = {
    active: false,
    currentFile: null,
    startTime: null,
    endTime: null,
    durationSeconds: 0,
    currentOffset: 0
};

// Initialize the application
function init() {
    setupNetwork();
    setupLegend();
    setupDropdowns();
    setupModalHandlers();
    setupHeaderToggle();
    setupSearch();
    setupPacketPanel();
    setupTheme();
    setupClusterLayout();
    setupChimpyMode();
    setupGameMode();
    setupReplayMode();
    setupStreams();
    connectWebSocket();
}

// Performance tier thresholds
const PERF_TIER_LOW = 30;      // Below this: full quality
const PERF_TIER_MEDIUM = 100;  // Below this: reduced quality
const PERF_TIER_HIGH = 300;    // Below this: performance mode
const PERF_TIER_EXTREME = 500; // Above this: maximum performance

// Get performance tier based on node count
function getPerformanceTier(nodeCount) {
    if (nodeCount <= PERF_TIER_LOW) return 'low';
    if (nodeCount <= PERF_TIER_MEDIUM) return 'medium';
    if (nodeCount <= PERF_TIER_HIGH) return 'high';
    if (nodeCount <= PERF_TIER_EXTREME) return 'extreme';
    return 'maximum';
}

// Get physics settings based on performance tier
// Tuned for orbital spacing - popular nodes repel strongly, spread into orbits
function getPhysicsSettings(tier) {
    const settings = {
        low: {
            stabilization: { iterations: 100, updateInterval: 25 },
            barnesHut: {
                gravitationalConstant: -10000,  // Very strong repulsion - nodes push apart
                centralGravity: 0.1,            // Weak center pull - allows spreading
                springLength: 300,              // Very long springs
                springConstant: 0.005,          // Extremely soft springs - repulsion wins
                damping: 0.15,                  // Smooth movement
                avoidOverlap: 1.0
            },
            timestep: 0.35,
            minVelocity: 0.1
        },
        medium: {
            stabilization: { iterations: 80, updateInterval: 50 },
            barnesHut: {
                gravitationalConstant: -8000,
                centralGravity: 0.1,
                springLength: 280,
                springConstant: 0.005,
                damping: 0.15,
                avoidOverlap: 1.0
            },
            timestep: 0.35,
            minVelocity: 0.1
        },
        high: {
            stabilization: { iterations: 50, updateInterval: 100 },
            barnesHut: {
                gravitationalConstant: -6000,
                centralGravity: 0.15,
                springLength: 250,
                springConstant: 0.008,
                damping: 0.18,
                avoidOverlap: 0.9
            },
            timestep: 0.4,
            minVelocity: 0.15
        },
        extreme: {
            stabilization: { iterations: 30, updateInterval: 100 },
            barnesHut: {
                gravitationalConstant: -5000,
                centralGravity: 0.2,
                springLength: 220,
                springConstant: 0.01,
                damping: 0.2,
                avoidOverlap: 0.8
            },
            timestep: 0.45,
            minVelocity: 0.2
        },
        maximum: {
            stabilization: { iterations: 20, updateInterval: 200 },
            barnesHut: {
                gravitationalConstant: -4000,
                centralGravity: 0.25,
                springLength: 180,
                springConstant: 0.015,
                damping: 0.25,
                avoidOverlap: 0.7
            },
            timestep: 0.5,
            minVelocity: 0.3
        }
    };
    return settings[tier] || settings.medium;
}

// Get theme-aware network options
function getNetworkOptions() {
    const isLightTheme = document.body.classList.contains('light-theme');
    const nodeCount = nodes.getIds().length;

    // Adaptive performance settings based on node count
    const tier = getPerformanceTier(nodeCount);
    const physicsSettings = getPhysicsSettings(tier);

    // Visual quality settings based on tier
    const shadowsEnabled = tier === 'low';
    const smoothEdges = tier === 'low' || tier === 'medium';
    const hoverEnabled = tier !== 'maximum';
    const hideLabelsOnZoom = tier === 'extreme' || tier === 'maximum';

    return {
        nodes: {
            shape: 'dot',
            size: 20,
            font: {
                size: 14,
                color: isLightTheme ? '#2c3e50' : '#ffffff',
                face: 'monospace'
            },
            borderWidth: tier === 'maximum' ? 1 : 2,
            borderWidthSelected: 4,
            color: {
                border: isLightTheme ? '#7f8c8d' : '#2c3e50',
                background: isLightTheme ? '#bdc3c7' : '#34495e',
                highlight: {
                    border: isLightTheme ? '#2980b9' : '#3498db',
                    background: isLightTheme ? '#3498db' : '#2980b9'
                }
            },
            shadow: {
                enabled: shadowsEnabled,
                color: isLightTheme ? 'rgba(0,0,0,0.15)' : 'rgba(0,0,0,0.5)',
                size: 10,
                x: 5,
                y: 5
            },
            scaling: {
                min: 15,          // Minimum node size
                max: 50,          // Maximum node size (high traffic nodes)
                label: {
                    enabled: !hideLabelsOnZoom,
                    min: hideLabelsOnZoom ? 0 : 10,
                    max: 24
                }
            }
        },
        edges: {
            width: tier === 'maximum' ? 1 : 2,
            arrows: {
                to: { enabled: false },
                from: { enabled: false }
            },
            smooth: smoothEdges ? {
                type: 'continuous',
                roundness: 0.5
            } : false,
            font: {
                size: 11,
                color: isLightTheme ? '#2c3e50' : '#ecf0f1',
                strokeWidth: 3,
                strokeColor: isLightTheme ? '#ffffff' : '#2c3e50'
            },
            shadow: {
                enabled: shadowsEnabled,
                color: isLightTheme ? 'rgba(0,0,0,0.1)' : 'rgba(0,0,0,0.3)',
                size: 5,
                x: 3,
                y: 3
            }
        },
        physics: {
            stabilization: physicsSettings.stabilization,
            barnesHut: physicsSettings.barnesHut,
            adaptiveTimestep: true,
            timestep: physicsSettings.timestep,
            minVelocity: physicsSettings.minVelocity,
            maxVelocity: tier === 'maximum' ? 30 : 50
        },
        interaction: {
            hover: true,
            tooltipDelay: 100,
            zoomSpeed: 0.5,
            zoomView: true,
            navigationButtons: false,
            keyboard: {
                enabled: true,
                speed: {
                    x: 10,
                    y: 10,
                    zoom: 0.02
                }
            }
        },
        manipulation: {
            enabled: false
        },
        configure: {
            enabled: false
        }
    };
}

// Setup vis.js network
function setupNetwork() {
    const container = document.getElementById('network');
    const data = { nodes: nodes, edges: edges };
    const options = getNetworkOptions();

    network = new vis.Network(container, data, options);

    // After initial stabilization, apply saved layout if any
    network.on('stabilizationIterationsDone', function() {
        // Apply saved cluster layout after initial stabilization
        if (nodes.length > 0) {
            const savedLayout = localStorage.getItem('clusterLayout') || 'force';
            if (savedLayout !== 'force') {
                applyClusterLayout(savedLayout);
            }
        }
    });

    // Handle node/edge selection
    network.on('click', function(params) {
        if (params.nodes.length > 0) {
            showNodeDetails(params.nodes[0]);
        } else if (params.edges.length > 0) {
            showEdgeDetails(params.edges[0]);
        } else {
            hideDetails();
        }
    });
}

// Setup protocol legend and filters
function setupLegend() {
    const legendContainer = document.getElementById('protocolLegend');
    const filtersContainer = document.getElementById('protocolFilters');

    Object.entries(PROTOCOL_COLORS).forEach(([protocol, color]) => {
        // Add to legend
        const legendItem = document.createElement('div');
        legendItem.className = 'legend-item';
        legendItem.innerHTML = `
            <span class="color-box" style="background-color: ${color}"></span>
            <span>${protocol}</span>
        `;
        legendContainer.appendChild(legendItem);

        // Add to filters
        const filterItem = document.createElement('label');
        filterItem.className = 'filter-item';
        filterItem.innerHTML = `
            <input type="checkbox" value="${protocol}" checked>
            <span>${protocol}</span>
        `;
        filterItem.querySelector('input').addEventListener('change', handleFilterChange);
        filtersContainer.appendChild(filterItem);
    });
}

// Setup dropdown toggles (submenus)
function setupDropdowns() {
    const statsToggle = document.getElementById('statsToggle');
    const filterToggle = document.getElementById('filterToggle');
    const legendToggle = document.getElementById('legendToggle');
    const settingsToggle = document.getElementById('settingsToggle');
    const replayToggle = document.getElementById('replayToggle');

    const statsSubmenu = document.getElementById('statsSubmenu');
    const filterContent = document.getElementById('protocolFilters');
    const legendContent = document.getElementById('protocolLegend');
    const settingsContent = document.getElementById('settingsContent');
    const replaySubmenu = document.getElementById('replaySubmenu');

    // Toggle submenu function
    function toggleSubmenu(button, submenu) {
        const isActive = button.classList.contains('active');

        // Close all other submenus
        document.querySelectorAll('.nav-link').forEach(btn => {
            if (btn !== button) {
                btn.classList.remove('active');
            }
        });
        document.querySelectorAll('.submenu').forEach(sub => {
            if (sub !== submenu) {
                sub.classList.remove('show');
            }
        });

        // Toggle current submenu
        button.classList.toggle('active');
        submenu.classList.toggle('show');
    }

    // Add event listeners
    if (statsToggle && statsSubmenu) {
        statsToggle.addEventListener('click', function(e) {
            e.stopPropagation();
            toggleSubmenu(statsToggle, statsSubmenu);
        });
    }

    if (filterToggle && filterContent) {
        filterToggle.addEventListener('click', function(e) {
            e.stopPropagation();
            toggleSubmenu(filterToggle, filterContent);
        });
    }

    if (legendToggle && legendContent) {
        legendToggle.addEventListener('click', function(e) {
            e.stopPropagation();
            toggleSubmenu(legendToggle, legendContent);
        });
    }

    if (settingsToggle && settingsContent) {
        settingsToggle.addEventListener('click', function(e) {
            e.stopPropagation();
            toggleSubmenu(settingsToggle, settingsContent);
        });
    }

    if (replayToggle && replaySubmenu) {
        replayToggle.addEventListener('click', function(e) {
            e.stopPropagation();
            toggleSubmenu(replayToggle, replaySubmenu);
        });
    }

    // Streams toggle
    const streamsToggle = document.getElementById('streamsToggle');
    const streamsSubmenu = document.getElementById('streamsSubmenu');

    if (streamsToggle && streamsSubmenu) {
        streamsToggle.addEventListener('click', function(e) {
            e.stopPropagation();
            toggleSubmenu(streamsToggle, streamsSubmenu);
            // Load streams when opening - use saved protocol filter
            if (streamsSubmenu.classList.contains('show')) {
                const filter = document.getElementById('streamProtocolFilter');
                loadStreams(filter?.value || '');
            }
        });
    }

    // Settings sub-toggles
    const themeSubToggle = document.getElementById('themeSubToggle');
    const themeSubmenu = document.getElementById('themeSubmenu');
    const clustersSubToggle = document.getElementById('clustersSubToggle');
    const clustersSubmenu = document.getElementById('clustersSubmenu');

    if (themeSubToggle && themeSubmenu) {
        themeSubToggle.addEventListener('click', function(e) {
            e.stopPropagation();
            themeSubToggle.classList.toggle('active');
            themeSubmenu.classList.toggle('show');
        });
    }

    if (clustersSubToggle && clustersSubmenu) {
        clustersSubToggle.addEventListener('click', function(e) {
            e.stopPropagation();
            clustersSubToggle.classList.toggle('active');
            clustersSubmenu.classList.toggle('show');
        });
    }

    // Close submenus when clicking outside sidebar
    document.addEventListener('click', function(e) {
        if (!e.target.closest('.sidebar')) {
            document.querySelectorAll('.nav-link').forEach(btn => {
                btn.classList.remove('active');
            });
            document.querySelectorAll('.submenu').forEach(sub => {
                sub.classList.remove('show');
            });
            document.querySelectorAll('.settings-sublink').forEach(btn => {
                btn.classList.remove('active');
            });
            document.querySelectorAll('.settings-submenu').forEach(sub => {
                sub.classList.remove('show');
            });
        }
    });

    // Prevent submenu from closing when clicking inside
    document.querySelectorAll('.submenu').forEach(submenu => {
        submenu.addEventListener('click', function(e) {
            e.stopPropagation();
        });
    });
}

// Setup modal handlers
function setupModalHandlers() {
    const closeButton = document.getElementById('closeButton');
    const modalBackdrop = document.getElementById('modalBackdrop');

    // Close button click
    closeButton.addEventListener('click', hideDetails);

    // Backdrop click
    modalBackdrop.addEventListener('click', hideDetails);

    // Escape key to close modal and Chimpy mode
    document.addEventListener('keydown', function(e) {
        if (e.key === 'Escape') {
            // Close Chimpy mode if active
            if (chimpyMode.active) {
                toggleChimpyMode();
            }
            // Close details panel
            hideDetails();
        }
    });

    // Global keyboard shortcuts
    document.addEventListener('keydown', function(e) {
        const searchInput = document.getElementById('searchInput');
        const packetPanel = document.getElementById('packetPanel');
        const isPanelOpen = packetPanel.classList.contains('show');

        // Don't handle shortcuts if user is typing in an input
        const isTyping = e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA';

        // "/" to focus search (unless already typing)
        if (e.key === '/' && !isTyping) {
            e.preventDefault();
            searchInput.focus();
            return;
        }

        // Arrow keys for packet navigation when packet panel is open
        if (isPanelOpen && (e.key === 'ArrowUp' || e.key === 'ArrowDown')) {
            // Don't interfere if user is in search input
            if (e.target === searchInput) {
                return;
            }

            e.preventDefault();

            if (packets.length === 0) return;

            if (e.key === 'ArrowDown') {
                selectedPacketIndex = Math.min(selectedPacketIndex + 1, packets.length - 1);
            } else if (e.key === 'ArrowUp') {
                selectedPacketIndex = Math.max(selectedPacketIndex - 1, 0);
            }

            // Select and display the packet
            if (selectedPacketIndex >= 0 && selectedPacketIndex < packets.length) {
                const packet = packets[selectedPacketIndex];
                selectPacket(packet.id);
            }
        }
    });
}

// Setup sidebar toggle for collapse/expand
function setupHeaderToggle() {
    const sidebarToggle = document.getElementById('sidebarToggle');
    const sidebarLogo = document.querySelector('.sidebar-logo');
    const sidebar = document.querySelector('.sidebar');
    const container = document.getElementById('network');

    // Function to toggle sidebar
    function toggleSidebar() {
        sidebar.classList.toggle('collapsed');

        // Close all submenus when collapsing
        if (sidebar.classList.contains('collapsed')) {
            document.querySelectorAll('.nav-link').forEach(btn => {
                btn.classList.remove('active');
            });
            document.querySelectorAll('.submenu').forEach(sub => {
                sub.classList.remove('show');
            });
        }
    }

    if (sidebarToggle && sidebar) {
        // Toggle button click (only when sidebar is expanded)
        sidebarToggle.addEventListener('click', function(e) {
            e.stopPropagation();
            toggleSidebar();
        });

        // Logo click to reopen sidebar when collapsed
        if (sidebarLogo) {
            sidebarLogo.addEventListener('click', function(e) {
                if (sidebar.classList.contains('collapsed')) {
                    e.stopPropagation();
                    toggleSidebar();
                }
            });
        }

        // Handle the end of the CSS transition to update canvas size
        sidebar.addEventListener('transitionend', function(e) {
            // Only respond to width transitions on the sidebar itself
            if (e.propertyName === 'width' && e.target === sidebar) {
                if (network && container) {
                    // Update canvas size without repositioning nodes
                    const width = container.offsetWidth;
                    const height = container.offsetHeight;
                    network.setSize(width + 'px', height + 'px');
                }
            }
        });
    }
}

// Setup search functionality
function setupSearch() {
    const searchInput = document.getElementById('searchInput');
    const searchClear = document.getElementById('searchClear');
    const searchResults = document.getElementById('searchResults');
    let searchTimeout = null;

    // Handle input changes
    searchInput.addEventListener('input', function(e) {
        const query = e.target.value.trim();

        // Show/hide clear button
        searchClear.style.display = query ? 'flex' : 'none';

        // Debounce search
        clearTimeout(searchTimeout);
        if (query.length === 0) {
            searchResults.classList.remove('show');
            return;
        }

        searchTimeout = setTimeout(() => {
            performSearch(query);
        }, 300);
    });

    // Handle clear button
    searchClear.addEventListener('click', function() {
        searchInput.value = '';
        searchClear.style.display = 'none';
        searchResults.classList.remove('show');
        searchInput.focus();
    });

    // Close results and clear input when clicking outside
    document.addEventListener('click', function(e) {
        if (!e.target.closest('.search-container')) {
            searchInput.value = '';
            searchClear.style.display = 'none';
            searchResults.classList.remove('show');
        }
    });

    // Keyboard navigation
    searchInput.addEventListener('keydown', function(e) {
        if (e.key === 'Escape') {
            searchInput.value = '';
            searchClear.style.display = 'none';
            searchResults.classList.remove('show');
        }
    });
}

// Perform search across nodes, edges, and packet payloads
function performSearch(query) {
    const searchResults = document.getElementById('searchResults');
    const results = [];
    const queryLower = query.toLowerCase();
    const isHexQuery = /^[0-9a-f\s]+$/i.test(query);

    // Search through nodes
    const allNodes = nodes.get();
    allNodes.forEach(node => {
        const matches = [];

        // Search IP address (node.id)
        if (node.id && node.id.toLowerCase().includes(queryLower)) {
            matches.push({ type: 'IP', value: node.id });
        }

        // Search hostname (node.label)
        if (node.label && node.label.toLowerCase().includes(queryLower)) {
            matches.push({ type: 'Hostname', value: node.label });
        }

        // Search through all IPs in the node's ips array (IPv4 and IPv6)
        if (node.ips && Array.isArray(node.ips)) {
            node.ips.forEach(ip => {
                if (ip && ip.toLowerCase().includes(queryLower)) {
                    matches.push({ type: 'IP Address', value: ip });
                }
            });
        }

        // Search in tooltip data (contains packets, bytes, etc.)
        if (node.title && node.title.toLowerCase().includes(queryLower)) {
            const titleMatches = extractTitleMatches(node.title, query);
            matches.push(...titleMatches);
        }

        if (matches.length > 0) {
            results.push({
                nodeId: node.id,
                label: node.label || node.id,
                ip: node.id,
                matches: matches,
                packetCount: extractPacketCount(node.title),
                byteCount: extractByteCount(node.title)
            });
        }
    });

    // Search through edges for packet data
    const allEdges = edges.get();
    const edgeMatches = new Map(); // Group by node

    allEdges.forEach(edge => {
        // Search protocol name
        if (edge.protocol && edge.protocol.Name &&
            edge.protocol.Name.toLowerCase().includes(queryLower)) {
            addEdgeMatch(edgeMatches, edge, 'Protocol', edge.protocol.Name);
        }

        // Search edge label (contains packet count)
        if (edge.label && edge.label.toLowerCase().includes(queryLower)) {
            addEdgeMatch(edgeMatches, edge, 'Data', edge.label);
        }
    });

    // Add edge matches to results
    edgeMatches.forEach((matches, nodeId) => {
        const node = nodes.get(nodeId);
        if (node) {
            const existingResult = results.find(r => r.nodeId === nodeId);
            if (existingResult) {
                existingResult.matches.push(...matches);
            } else {
                results.push({
                    nodeId: nodeId,
                    label: node.label || node.id,
                    ip: node.id,
                    matches: matches,
                    packetCount: extractPacketCount(node.title),
                    byteCount: extractByteCount(node.title)
                });
            }
        }
    });

    // Search through packet payloads (case-insensitive)
    // Use packetCache to search all cached packets (up to 5000), not just current batch
    const allCachedPackets = Array.from(packetCache.values());
    if (allCachedPackets && allCachedPackets.length > 0) {
        allCachedPackets.forEach(packet => {
            if (!packet.payload) return;

            try {
                // Decode base64 payload
                const payloadBytes = base64ToBytes(packet.payload);

                // Convert query to bytes for searching
                const queryBytes = stringToBytes(queryLower);

                // Search for query in payload (case-insensitive ASCII search)
                if (searchInPayload(payloadBytes, queryBytes)) {
                    // Find or create result for this packet's source node
                    let result = results.find(r => r.nodeId === packet.src);
                    if (!result) {
                        const node = nodes.get(packet.src);
                        result = {
                            nodeId: packet.src,
                            label: node ? (node.label || packet.src) : packet.src,
                            ip: packet.src,
                            matches: [],
                            packetCount: node ? extractPacketCount(node.title) : 0,
                            byteCount: node ? extractByteCount(node.title) : ''
                        };
                        results.push(result);
                    }

                    // Add payload match indicator
                    const payloadPreview = getPayloadPreview(payloadBytes, queryBytes);
                    result.matches.push({
                        type: 'Payload',
                        value: `Found in packet #${packet.id}: "${payloadPreview}"`,
                        packetId: packet.id
                    });

                    // Mark that this result has packet matches
                    if (!result.packetIds) {
                        result.packetIds = [];
                    }
                    result.packetIds.push(packet.id);
                }
            } catch (e) {
                console.error('Error searching packet payload:', e);
            }
        });
    }

    // Display results
    displaySearchResults(results, query);
}

// Helper to convert string to bytes (lowercased for case-insensitive search)
function stringToBytes(str) {
    const bytes = new Uint8Array(str.length);
    for (let i = 0; i < str.length; i++) {
        bytes[i] = str.charCodeAt(i);
    }
    return bytes;
}

// Case-insensitive search in payload bytes
function searchInPayload(payloadBytes, queryBytes) {
    if (queryBytes.length === 0 || queryBytes.length > payloadBytes.length) {
        return false;
    }

    // Convert payload to lowercase for case-insensitive search
    const payloadLower = new Uint8Array(payloadBytes.length);
    for (let i = 0; i < payloadBytes.length; i++) {
        const byte = payloadBytes[i];
        // Convert A-Z to lowercase
        if (byte >= 65 && byte <= 90) {
            payloadLower[i] = byte + 32;
        } else {
            payloadLower[i] = byte;
        }
    }

    // Search for query bytes in payload
    for (let i = 0; i <= payloadLower.length - queryBytes.length; i++) {
        let found = true;
        for (let j = 0; j < queryBytes.length; j++) {
            if (payloadLower[i + j] !== queryBytes[j]) {
                found = false;
                break;
            }
        }
        if (found) return true;
    }
    return false;
}

// Get a preview of the payload around the matched query
function getPayloadPreview(payloadBytes, queryBytes) {
    // Find the match position
    const payloadLower = new Uint8Array(payloadBytes.length);
    for (let i = 0; i < payloadBytes.length; i++) {
        const byte = payloadBytes[i];
        if (byte >= 65 && byte <= 90) {
            payloadLower[i] = byte + 32;
        } else {
            payloadLower[i] = byte;
        }
    }

    let matchPos = -1;
    for (let i = 0; i <= payloadLower.length - queryBytes.length; i++) {
        let found = true;
        for (let j = 0; j < queryBytes.length; j++) {
            if (payloadLower[i + j] !== queryBytes[j]) {
                found = false;
                break;
            }
        }
        if (found) {
            matchPos = i;
            break;
        }
    }

    if (matchPos === -1) return '';

    // Get context around the match (20 chars before and after)
    const contextStart = Math.max(0, matchPos - 20);
    const contextEnd = Math.min(payloadBytes.length, matchPos + queryBytes.length + 20);

    let preview = '';
    for (let i = contextStart; i < contextEnd; i++) {
        const byte = payloadBytes[i];
        if (byte >= 32 && byte <= 126) {
            preview += String.fromCharCode(byte);
        } else {
            preview += '.';
        }
    }

    // Truncate if too long
    if (preview.length > 50) {
        preview = preview.substring(0, 47) + '...';
    }

    return preview;
}

// Helper to add edge match
function addEdgeMatch(edgeMatches, edge, type, value) {
    const nodeId = edge.from; // Associate with source node
    if (!edgeMatches.has(nodeId)) {
        edgeMatches.set(nodeId, []);
    }
    edgeMatches.get(nodeId).push({ type, value });
}

// Extract matches from title
function extractTitleMatches(title, query) {
    const matches = [];
    const lines = title.split('\n');
    const queryLower = query.toLowerCase();

    lines.forEach(line => {
        if (line.toLowerCase().includes(queryLower)) {
            const parts = line.split(':');
            if (parts.length === 2) {
                matches.push({ type: parts[0].trim(), value: parts[1].trim() });
            }
        }
    });

    return matches;
}

// Extract packet count from title
function extractPacketCount(title) {
    if (!title) return 0;
    const match = title.match(/Packets:\s*(\d+)/);
    return match ? parseInt(match[1]) : 0;
}

// Extract byte count from title
function extractByteCount(title) {
    if (!title) return '';
    const match = title.match(/Bytes:\s*([\d\.]+ [A-Z]+)/);
    return match ? match[1] : '';
}

// Display search results
function displaySearchResults(results, query) {
    const searchResults = document.getElementById('searchResults');

    if (results.length === 0) {
        searchResults.innerHTML = '<div class="search-no-results">No results found</div>';
        searchResults.classList.add('show');
        return;
    }

    // Sort by relevance (packet count)
    results.sort((a, b) => b.packetCount - a.packetCount);

    // Limit to top 10 results
    const topResults = results.slice(0, 10);

    const html = topResults.map(result => {
        const matchTags = result.matches
            .slice(0, 3) // Limit tags
            .map(m => `<span class="search-result-tag">${highlightMatch(m.value, query)}</span>`)
            .join('');

        const packetIdsAttr = result.packetIds && result.packetIds.length > 0
            ? `data-packet-ids="${result.packetIds.join(',')}"`
            : '';

        // Check if the first matching packet is part of a stream
        let streamIdAttr = '';
        let streamsTag = '';
        if (result.packetIds && result.packetIds.length > 0) {
            const firstPacket = packetCache.get(result.packetIds[0]);
            if (firstPacket && firstPacket.srcPort && firstPacket.dstPort && isStreamProtocol(firstPacket.protocol)) {
                const streamId = generateStreamId(firstPacket.src, firstPacket.srcPort, firstPacket.dst, firstPacket.dstPort, firstPacket.protocol);
                streamIdAttr = `data-stream-id="${streamId}"`;
                streamsTag = '<span class="search-result-tag search-stream-tag" style="background: rgba(155, 89, 182, 0.3); cursor: pointer;">Streams</span>';
            }
        }

        return `
            <div class="search-result-item" data-node-id="${result.nodeId}" ${packetIdsAttr} ${streamIdAttr}>
                <div class="search-result-title">
                    ${highlightMatch(result.label, query)}
                    ${result.packetIds && result.packetIds.length > 0 ? '<span class="search-result-tag" style="background: rgba(52, 152, 219, 0.3);">Packets</span>' : ''}
                    ${streamsTag}
                </div>
                <div class="search-result-subtitle">
                    <span class="search-result-tag">IP: ${highlightMatch(result.ip, query)}</span>
                    ${matchTags}
                    ${result.packetCount > 0 ? `<span class="search-result-tag">${result.packetCount} packets</span>` : ''}
                </div>
            </div>
        `;
    }).join('');

    searchResults.innerHTML = html;
    searchResults.classList.add('show');

    // Helper to clear search
    const clearSearch = () => {
        const searchInput = document.getElementById('searchInput');
        const searchClear = document.getElementById('searchClear');
        searchInput.value = '';
        searchClear.style.display = 'none';
        searchResults.classList.remove('show');
    };

    // Add click handlers for Streams tags
    searchResults.querySelectorAll('.search-stream-tag').forEach(tag => {
        tag.addEventListener('click', function(event) {
            event.stopPropagation(); // Prevent parent item click
            const item = this.closest('.search-result-item');
            const streamId = item.getAttribute('data-stream-id');
            if (streamId) {
                openStreamDetail(streamId);
                clearSearch();
            }
        });
    });

    // Add click handlers for result items
    searchResults.querySelectorAll('.search-result-item').forEach(item => {
        item.addEventListener('click', function() {
            const nodeId = this.getAttribute('data-node-id');
            const packetIdsStr = this.getAttribute('data-packet-ids');

            // If this result has packet matches, open packet panel and select first packet
            if (packetIdsStr) {
                const packetIds = packetIdsStr.split(',').map(id => parseInt(id));

                // Open packet panel
                const packetPanel = document.getElementById('packetPanel');
                if (!packetPanel.classList.contains('show')) {
                    packetPanel.classList.add('show');
                    // Load packets when opening panel via search
                    loadPackets();
                }

                // Select the first matching packet
                if (packetIds.length > 0) {
                    setTimeout(() => {
                        selectPacket(packetIds[0]);
                    }, 100);
                }
            }

            // Also focus on the node in the graph
            focusOnNode(nodeId);

            clearSearch();
        });
    });
}

// Highlight matching text
function highlightMatch(text, query) {
    if (!text || !query) return text;

    const regex = new RegExp(`(${escapeRegex(query)})`, 'gi');
    return text.replace(regex, '<span class="search-highlight">$1</span>');
}

// Escape regex special characters
function escapeRegex(string) {
    return string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// Focus on a specific node
function focusOnNode(nodeId) {
    if (!network) return;

    // Select the node
    network.selectNodes([nodeId]);

    // Move to the node with animation
    network.focus(nodeId, {
        scale: 1.5,
        animation: {
            duration: 500,
            easingFunction: 'easeInOutQuad'
        }
    });

    // Show node details
    setTimeout(() => {
        showNodeDetails(nodeId);
    }, 500);

    // Clear search and hide results
    const searchInput = document.getElementById('searchInput');
    const searchClear = document.getElementById('searchClear');
    const searchResults = document.getElementById('searchResults');

    searchInput.value = '';
    searchClear.style.display = 'none';
    searchResults.classList.remove('show');
}

// Setup theme switching
function setupTheme() {
    const themeButtons = document.querySelectorAll('.theme-button');

    // Load saved theme from localStorage (default to light)
    const savedTheme = localStorage.getItem('theme') || 'light';
    applyTheme(savedTheme);

    // Add click handlers to theme buttons
    themeButtons.forEach(button => {
        button.addEventListener('click', function() {
            const theme = this.getAttribute('data-theme');
            applyTheme(theme);
            localStorage.setItem('theme', theme);
        });
    });
}

// Apply theme to the page
function applyTheme(theme) {
    const body = document.body;
    const html = document.documentElement;
    const themeButtons = document.querySelectorAll('.theme-button');

    // Remove/add light-theme class to both html and body
    if (theme === 'light') {
        body.classList.add('light-theme');
        html.classList.add('light-theme');
    } else {
        body.classList.remove('light-theme');
        html.classList.remove('light-theme');
    }

    // Update button active states
    themeButtons.forEach(button => {
        const buttonTheme = button.getAttribute('data-theme');
        if (buttonTheme === theme) {
            button.classList.add('active');
        } else {
            button.classList.remove('active');
        }
    });

    // Update network graph with new theme colors
    if (network) {
        const options = getNetworkOptions();
        network.setOptions(options);
    }
}

// Setup packet panel functionality
function setupPacketPanel() {
    const packetToggle = document.getElementById('packetDataToggle');
    const packetPanel = document.getElementById('packetPanel');
    const packetPanelClose = document.getElementById('packetPanelClose');
    const packetPanelResize = document.getElementById('packetPanelResize');
    const hexTab = document.getElementById('hexTab');
    const asciiTab = document.getElementById('asciiTab');

    let isResizing = false;
    let startY = 0;
    let startHeight = 0;
    let currentView = 'hex';

    // Toggle packet panel
    packetToggle.addEventListener('click', function() {
        packetPanel.classList.toggle('show');
        const timeline = document.getElementById('timelineContainer');
        if (packetPanel.classList.contains('show')) {
            loadPackets();
            if (timeline) {
                timeline.classList.add('packet-panel-open');
                // Clear inline styles that override CSS
                timeline.style.opacity = '';
                timeline.style.visibility = '';
            }
        } else {
            if (timeline) {
                timeline.classList.remove('packet-panel-open');
                // Restore timeline visibility if in replay mode
                if (replayMode.active) {
                    timeline.style.opacity = '1';
                    timeline.style.visibility = 'visible';
                }
            }
        }
    });

    // Close packet panel
    packetPanelClose.addEventListener('click', function(e) {
        e.stopPropagation();
        e.preventDefault();
        packetPanel.classList.remove('show');
        const timeline = document.getElementById('timelineContainer');
        if (timeline) {
            timeline.classList.remove('packet-panel-open');
            // Restore timeline visibility if in replay mode
            if (replayMode.active) {
                timeline.style.opacity = '1';
                timeline.style.visibility = 'visible';
            }
        }
    }, true); // Use capture phase to ensure it fires first

    // Escape key to close packet panel
    document.addEventListener('keydown', function(e) {
        if (e.key === 'Escape' && packetPanel.classList.contains('show')) {
            packetPanel.classList.remove('show');
            const timeline = document.getElementById('timelineContainer');
            if (timeline) {
                timeline.classList.remove('packet-panel-open');
                // Restore timeline visibility if in replay mode
                if (replayMode.active) {
                    timeline.style.opacity = '1';
                    timeline.style.visibility = 'visible';
                }
            }
        }
    });

    // Resize functionality
    packetPanelResize.addEventListener('mousedown', function(e) {
        // Don't start resize if clicking on interactive elements
        if (e.target.closest('button') || e.target.closest('.packet-tab')) {
            return;
        }

        isResizing = true;
        startY = e.clientY;
        startHeight = packetPanel.offsetHeight;
        document.body.style.cursor = 'ns-resize';
        e.preventDefault();
        e.stopPropagation();
    });

    const handleMouseMove = function(e) {
        if (!isResizing) return;

        e.preventDefault();
        const deltaY = startY - e.clientY;
        const newHeight = Math.max(200, Math.min(window.innerHeight - 100, startHeight + deltaY));
        packetPanel.style.height = newHeight + 'px';
    };

    const handleMouseUp = function(e) {
        if (isResizing) {
            isResizing = false;
            document.body.style.cursor = '';
            // Only prevent default if mouseup happened during active resize
            // Don't stop propagation to allow click events to work
        }
    };

    document.addEventListener('mousemove', handleMouseMove);
    document.addEventListener('mouseup', handleMouseUp);

    // Tab switching
    hexTab.addEventListener('click', function() {
        window.currentPacketView = 'hex';
        hexTab.classList.add('active');
        asciiTab.classList.remove('active');
        updatePacketView();
    });

    asciiTab.addEventListener('click', function() {
        window.currentPacketView = 'ascii';
        asciiTab.classList.add('active');
        hexTab.classList.remove('active');
        updatePacketView();
    });

    // Initialize current view globally
    if (!window.currentPacketView) {
        window.currentPacketView = 'hex';
    }
}

// Update packet view based on selected tab
function updatePacketView() {
    const hexView = document.getElementById('hexView');
    const asciiView = document.getElementById('asciiView');

    if (!hexView || !asciiView) return;

    if (window.currentPacketView === 'hex') {
        hexView.classList.add('active');
        asciiView.classList.remove('active');
    } else {
        hexView.classList.remove('active');
        asciiView.classList.add('active');
    }
}

// Load and display packets
function loadPackets() {
    const packetList = document.getElementById('packetList');

    if (!packets || packets.length === 0) {
        packetList.innerHTML = '<div class="packet-list-placeholder">No packets captured yet</div>';
        return;
    }

    // Sort by timestamp (newest first)
    const sortedPackets = [...packets].sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));

    const html = sortedPackets.map(packet => {
        const time = new Date(packet.timestamp).toLocaleTimeString();
        const srcDisplay = packet.srcPort ? `${packet.src}:${packet.srcPort}` : packet.src;
        const dstDisplay = packet.dstPort ? `${packet.dst}:${packet.dstPort}` : packet.dst;
        return `
            <div class="packet-item" data-packet-id="${packet.id}">
                <div class="packet-item-number">#${packet.id}</div>
                <div class="packet-item-info">
                    <div class="packet-item-time">${time}</div>
                    <div class="packet-item-src">${srcDisplay}</div>
                    <div>→</div>
                    <div class="packet-item-dst">${dstDisplay}</div>
                    <div class="packet-item-protocol">${packet.protocol}</div>
                    <div class="packet-item-length">${packet.length} bytes</div>
                    <div class="packet-item-summary">${packet.summary}</div>
                </div>
            </div>
        `;
    }).join('');

    packetList.innerHTML = html;

    // Add click handlers
    packetList.querySelectorAll('.packet-item').forEach(item => {
        item.addEventListener('click', function() {
            const packetId = parseInt(this.getAttribute('data-packet-id'));
            selectPacket(packetId);
        });
    });
}

// Select and inspect a packet
function selectPacket(packetId) {
    selectedPacketId = packetId;

    // Try to find packet in cache first (persistent), then in current packets array
    let packet = packetCache.get(packetId);
    if (!packet) {
        packet = packets.find(p => p.id === packetId);
    }

    if (!packet) {
        console.warn(`Packet ${packetId} not found in cache or current packets`);
        return;
    }

    // Update selected packet index for keyboard navigation
    selectedPacketIndex = packets.findIndex(p => p.id === packetId);

    // Update selected state in list
    document.querySelectorAll('.packet-item').forEach(item => {
        item.classList.remove('selected');
    });

    const selectedElement = document.querySelector(`[data-packet-id="${packetId}"]`);
    if (selectedElement) {
        selectedElement.classList.add('selected');

        // Scroll into view if needed
        selectedElement.scrollIntoView({
            behavior: 'smooth',
            block: 'nearest'
        });
    }

    // Show packet inspector in left sidebar
    showPacketInspector(packet);
}

// Show packet inspector
function showPacketInspector(packet) {
    const packetInspectorContent = document.getElementById('packetInspectorContent');

    // Generate hex dump and ASCII view
    const hexDump = generateHexDump(packet);
    const asciiView = generateAsciiView(packet);

    const currentView = window.currentPacketView || 'hex';

    const html = `
        <div class="packet-detail-section">
            <h4>Frame ${packet.id}</h4>
            <div class="packet-detail-field">
                <div class="packet-detail-label">Timestamp:</div>
                <div class="packet-detail-value">${new Date(packet.timestamp).toLocaleString()}</div>
            </div>
            <div class="packet-detail-field">
                <div class="packet-detail-label">Length:</div>
                <div class="packet-detail-value">${packet.length} bytes</div>
            </div>
        </div>

        <div class="packet-detail-section">
            <h4>Network Layer</h4>
            <div class="packet-detail-field">
                <div class="packet-detail-label">Source IP:</div>
                <div class="packet-detail-value">${packet.src}</div>
            </div>
            ${packet.srcPort ? `
            <div class="packet-detail-field">
                <div class="packet-detail-label">Source Port:</div>
                <div class="packet-detail-value">${packet.srcPort}</div>
            </div>
            ` : ''}
            <div class="packet-detail-field">
                <div class="packet-detail-label">Destination IP:</div>
                <div class="packet-detail-value">${packet.dst}</div>
            </div>
            ${packet.dstPort ? `
            <div class="packet-detail-field">
                <div class="packet-detail-label">Destination Port:</div>
                <div class="packet-detail-value">${packet.dstPort}</div>
            </div>
            ` : ''}
            <div class="packet-detail-field">
                <div class="packet-detail-label">Protocol:</div>
                <div class="packet-detail-value">${packet.protocol}</div>
            </div>
        </div>

        <div class="packet-detail-section">
            <h4>Packet Information</h4>
            <div class="packet-detail-field">
                <div class="packet-detail-label">Packet ID:</div>
                <div class="packet-detail-value">${packet.id}</div>
            </div>
        </div>

        <div class="packet-detail-section">
            <h4>Packet Data</h4>
            <div class="packet-view ${currentView === 'hex' ? 'active' : ''}" id="hexView">
                <div class="packet-hex-dump">${hexDump}</div>
            </div>
            <div class="packet-view ${currentView === 'ascii' ? 'active' : ''}" id="asciiView">
                <div class="packet-ascii-view">${asciiView}</div>
            </div>
        </div>

        <div class="packet-detail-section">
            <h4>Summary</h4>
            <div class="packet-detail-field">
                <div class="packet-detail-value">${packet.summary}</div>
            </div>
        </div>
    `;

    packetInspectorContent.innerHTML = html;
}

// Generate hex dump
function generateHexDump(packet) {
    if (!packet.payload) {
        return 'No payload data available';
    }

    // Decode base64 payload
    const payloadBytes = base64ToBytes(packet.payload);
    const lines = [];
    const bytesPerLine = 16;
    const totalBytes = payloadBytes.length;
    const displayBytes = Math.min(totalBytes, 512); // Show first 512 bytes

    for (let offset = 0; offset < displayBytes; offset += bytesPerLine) {
        const hexOffset = offset.toString(16).padStart(4, '0');
        const bytes = [];
        const ascii = [];

        for (let i = 0; i < bytesPerLine && offset + i < displayBytes; i++) {
            const byte = payloadBytes[offset + i];
            bytes.push(byte.toString(16).padStart(2, '0'));
            ascii.push(byte >= 32 && byte <= 126 ? String.fromCharCode(byte) : '.');
        }

        // Pad hex bytes to ensure consistent alignment (16 bytes = 47 chars with spaces)
        const hexBytes = bytes.join(' ').padEnd(47, ' ');
        const asciiStr = ascii.join('');

        lines.push(
            `<div class="hex-line">` +
            `<span class="hex-offset">${hexOffset}</span>  ` +
            `<span class="hex-bytes">${hexBytes}</span>  ` +
            `<span class="hex-ascii">${asciiStr}</span>` +
            `</div>`
        );
    }

    if (displayBytes < totalBytes) {
        lines.push(`<div class="hex-line"><span class="hex-offset">...</span> (${totalBytes - displayBytes} more bytes)</div>`);
    }

    return lines.join('\n');
}

// Helper function to decode base64 to byte array
function base64ToBytes(base64) {
    const binaryString = atob(base64);
    const bytes = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
        bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes;
}

// Generate ASCII view
function generateAsciiView(packet) {
    if (!packet.payload) {
        return 'No payload data available';
    }

    // Decode base64 payload
    const payloadBytes = base64ToBytes(packet.payload);
    let ascii = '';

    // Add packet header info
    ascii += `Packet #${packet.id} - ${packet.protocol} Protocol\n`;
    ascii += `${packet.src} → ${packet.dst}\n`;
    ascii += `Length: ${packet.length} bytes\n`;
    ascii += `Timestamp: ${new Date(packet.timestamp).toLocaleString()}\n`;
    ascii += `${'='.repeat(60)}\n\n`;

    // Convert payload bytes to ASCII (show first 2048 bytes)
    const displayBytes = Math.min(payloadBytes.length, 2048);
    let payloadAscii = '';

    for (let i = 0; i < displayBytes; i++) {
        const byte = payloadBytes[i];
        // Show printable ASCII or a dot for non-printable
        if (byte >= 32 && byte <= 126) {
            payloadAscii += String.fromCharCode(byte);
        } else if (byte === 10) { // newline
            payloadAscii += '\n';
        } else if (byte === 13) { // carriage return
            payloadAscii += '\r';
        } else if (byte === 9) { // tab
            payloadAscii += '\t';
        } else {
            payloadAscii += '.';
        }
    }

    ascii += 'Payload (ASCII):\n';
    ascii += '─'.repeat(60) + '\n';
    ascii += payloadAscii;

    if (displayBytes < payloadBytes.length) {
        ascii += `\n\n... (${payloadBytes.length - displayBytes} more bytes)`;
    }

    return ascii;
}

// Handle protocol filter changes
function handleFilterChange(event) {
    const protocol = event.target.value;
    if (event.target.checked) {
        protocolFilters.delete(protocol);
    } else {
        protocolFilters.add(protocol);
    }
    updateEdgeVisibility();
}

// Update edge visibility based on filters
function updateEdgeVisibility() {
    const allEdges = edges.get();
    allEdges.forEach(edge => {
        const isHidden = protocolFilters.has(edge.protocol.Name);
        edges.update({
            id: edge.id,
            hidden: isHidden
        });
    });
}

// Connect to WebSocket
function connectWebSocket() {
    // Don't connect if in replay mode
    if (replayMode.active) {
        return;
    }

    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/ws`;

    // Set initial connecting status
    updateConnectionStatus('Connecting...', false);

    ws = new WebSocket(wsUrl);

    ws.onopen = function() {
        console.log('WebSocket connected');
        updateConnectionStatus('Connected', true);
    };

    ws.onmessage = function(event) {
        console.log('WebSocket message received, length:', event.data.length);
        try {
            const data = JSON.parse(event.data);
            throttledUpdateGraph(data);
        } catch (e) {
            console.error('Error processing WebSocket message:', e);
        }
    };

    ws.onerror = function(error) {
        console.error('WebSocket error:', error);
        updateConnectionStatus('Error', false);
    };

    ws.onclose = function() {
        updateConnectionStatus('Disconnected', false);
        // Only attempt to reconnect if not in replay mode
        if (!replayMode.active) {
            setTimeout(connectWebSocket, 3000);
        }
    };
}

// Throttled update to prevent overwhelming the visualization
function throttledUpdateGraph(data) {
    // Dynamic throttle based on node count - keeps things responsive
    const nodeCount = data.nodes ? data.nodes.length : 0;
    if (nodeCount > 50) {
        UPDATE_THROTTLE_MS = 200;  // 50+ nodes: update every 200ms
    } else if (nodeCount > 25) {
        UPDATE_THROTTLE_MS = 150;  // 25-50 nodes: update every 150ms
    } else {
        UPDATE_THROTTLE_MS = 100;  // <25 nodes: update every 100ms (fluid)
    }

    pendingUpdate = data;

    if (updateScheduled) {
        return; // Update already scheduled
    }

    const now = Date.now();
    const timeSinceLastUpdate = now - lastUpdateTime;

    if (timeSinceLastUpdate >= UPDATE_THROTTLE_MS) {
        // Enough time has passed, update immediately
        lastUpdateTime = now;
        updateGraph(data);
        pendingUpdate = null;
    } else {
        // Schedule update for later
        updateScheduled = true;
        setTimeout(() => {
            lastUpdateTime = Date.now();
            updateGraph(pendingUpdate);
            pendingUpdate = null;
            updateScheduled = false;
        }, UPDATE_THROTTLE_MS - timeSinceLastUpdate);
    }
}

// Get node color based on traffic level
function getNodeColorByTraffic(packetCount, lowThreshold, mediumThreshold) {
    const isLightTheme = document.body.classList.contains('light-theme');

    if (packetCount === 0) {
        // Static nodes - grey
        return {
            background: isLightTheme ? '#95a5a6' : '#7f8c8d',
            border: isLightTheme ? '#7f8c8d' : '#5d6d7e',
            highlight: {
                background: isLightTheme ? '#7f8c8d' : '#95a5a6',
                border: isLightTheme ? '#5d6d7e' : '#b2bec3'
            }
        };
    } else if (packetCount < lowThreshold) {
        // Low flow - yellow
        return {
            background: isLightTheme ? '#f1c40f' : '#f39c12',
            border: isLightTheme ? '#f39c12' : '#e67e22',
            highlight: {
                background: isLightTheme ? '#f39c12' : '#f1c40f',
                border: isLightTheme ? '#e67e22' : '#f39c12'
            }
        };
    } else if (packetCount < mediumThreshold) {
        // Medium flow - orange
        return {
            background: isLightTheme ? '#e67e22' : '#d35400',
            border: isLightTheme ? '#d35400' : '#ca6f1e',
            highlight: {
                background: isLightTheme ? '#d35400' : '#e67e22',
                border: isLightTheme ? '#ca6f1e' : '#dc7633'
            }
        };
    } else {
        // High flow - red
        return {
            background: isLightTheme ? '#e74c3c' : '#c0392b',
            border: isLightTheme ? '#c0392b' : '#a93226',
            highlight: {
                background: isLightTheme ? '#c0392b' : '#e74c3c',
                border: isLightTheme ? '#a93226' : '#cb4335'
            }
        };
    }
}

// Update graph with new data
// Helper to determine color tier for delta comparison
function getColorTier(packetCount, lowThreshold, mediumThreshold) {
    if (packetCount === 0) return 0;
    if (packetCount < lowThreshold) return 1;
    if (packetCount < mediumThreshold) return 2;
    return 3;
}

function updateGraph(data) {
    console.log('updateGraph called with', data.nodes?.length, 'nodes and', data.edges?.length, 'edges');

    // Safety check for missing data
    if (!data || !data.nodes || !data.edges) {
        console.error('Invalid data received:', data);
        return;
    }

    // Performance monitoring
    const totalNodes = data.nodes.length;
    const totalEdges = data.edges.length;
    const isLimited = totalNodes > MAX_NODES || totalEdges > MAX_EDGES;

    if (isLimited) {
        console.log(`Performance mode: Limiting display to top ${MAX_NODES} nodes and ${MAX_EDGES} edges (total: ${totalNodes} nodes, ${totalEdges} edges)`);
    }

    // Sort nodes by packet count (most active first) and limit to MAX_NODES
    const sortedNodes = data.nodes
        .sort((a, b) => b.packetCount - a.packetCount)
        .slice(0, MAX_NODES);

    // Calculate thresholds for traffic levels
    const maxPacketCount = Math.max(...sortedNodes.map(n => n.packetCount), 1);
    const lowThreshold = maxPacketCount * 0.2;
    const mediumThreshold = maxPacketCount * 0.5;

    // Get current node IDs for comparison
    const currentNodeIds = new Set(nodes.getIds());
    const newNodeIds = new Set(sortedNodes.map(n => n.id));

    // DELTA UPDATE: Only update nodes that actually changed
    const nodeUpdates = [];
    const newNodeCount = sortedNodes.filter(n => !currentNodeIds.has(n.id)).length;

    for (const node of sortedNodes) {
        const colorTier = getColorTier(node.packetCount, lowThreshold, mediumThreshold);
        const cached = nodeStateCache.get(node.id);
        const isNew = !currentNodeIds.has(node.id);

        // Only update if: new node, packet count changed significantly, or color tier changed
        const needsUpdate = isNew ||
            !cached ||
            cached.colorTier !== colorTier ||
            Math.abs(cached.packetCount - node.packetCount) > cached.packetCount * 0.1; // 10% change threshold

        if (needsUpdate) {
            const color = getNodeColorByTraffic(node.packetCount, lowThreshold, mediumThreshold);
            // Value for scaling: sqrt gives better visual spread than log for node sizes
            const value = Math.sqrt(node.packetCount + 1) * 3;
            const nodeData = {
                id: node.id,
                label: formatNodeLabel(node),
                title: formatNodeTooltip(node),
                value: value,
                color: color,
                ips: node.ips || [node.id],
                hostname: node.label,
                packetCount: node.packetCount,
                byteCount: node.byteCount
            };

            // For new nodes, find initial position near connected neighbor to prevent explosion
            if (isNew && network) {
                const connectedEdge = data.edges.find(e => e.from === node.id || e.to === node.id);
                if (connectedEdge) {
                    const neighborId = connectedEdge.from === node.id ? connectedEdge.to : connectedEdge.from;
                    // Only get position if neighbor exists in the network
                    if (nodes.get(neighborId)) {
                        try {
                            const neighborPos = network.getPosition(neighborId);
                            if (neighborPos && neighborPos.x !== undefined) {
                                // Position near neighbor with small random offset
                                const angle = Math.random() * Math.PI * 2;
                                const distance = 100 + Math.random() * 100;
                                nodeData.x = neighborPos.x + Math.cos(angle) * distance;
                                nodeData.y = neighborPos.y + Math.sin(angle) * distance;
                            }
                        } catch (e) {
                            // Neighbor position not available, will use default positioning
                        }
                    }
                } else {
                    // No connected neighbor - position in a spread-out ring around center
                    const angle = Math.random() * Math.PI * 2;
                    const distance = 200 + Math.random() * 300;
                    nodeData.x = Math.cos(angle) * distance;
                    nodeData.y = Math.sin(angle) * distance;
                }
            }

            nodeUpdates.push(nodeData);
        }

        // Update cache
        nodeStateCache.set(node.id, { packetCount: node.packetCount, byteCount: node.byteCount, colorTier });
    }

    // Remove nodes that no longer exist
    const nodesToRemove = [...currentNodeIds].filter(id => !newNodeIds.has(id));
    if (nodesToRemove.length > 0) {
        nodes.remove(nodesToRemove);
        nodesToRemove.forEach(id => nodeStateCache.delete(id));
    }

    // Only call update if there are actual changes
    if (nodeUpdates.length > 0) {
        nodes.update(nodeUpdates);

        // When many new nodes arrive at once (like during nmap scan), temporarily increase damping
        // to prevent explosive spreading, then restore normal physics after settling
        if (newNodeCount >= 5 && network) {
            const currentLayout = localStorage.getItem('clusterLayout') || 'force';
            if (currentLayout === 'force') {
                // Apply high damping immediately
                network.setOptions({
                    physics: {
                        barnesHut: {
                            damping: 0.5,  // High damping for smooth settling
                            springConstant: 0.02  // Stiffer springs to hold together
                        }
                    }
                });
                // Clear any existing timeout and reset the timer
                // This debounces the restore so it only happens after activity stops
                if (physicsDampingTimeout) {
                    clearTimeout(physicsDampingTimeout);
                }
                physicsDampingTimeout = setTimeout(() => {
                    if (network) {
                        const tier = getPerformanceTier(nodes.getIds().length);
                        const physicsSettings = getPhysicsSettings(tier);
                        network.setOptions({
                            physics: {
                                barnesHut: physicsSettings.barnesHut
                            }
                        });
                    }
                    physicsDampingTimeout = null;
                }, 2000);
            }
        }
    }


    // Filter edges to only those between visible nodes, then sort by packet count and limit
    const visibleNodeIds = newNodeIds;
    const filteredEdges = data.edges
        .filter(edge => visibleNodeIds.has(edge.from) && visibleNodeIds.has(edge.to))
        .sort((a, b) => b.packetCount - a.packetCount)
        .slice(0, MAX_EDGES);

    // Get current edge IDs for comparison
    const currentEdgeIds = new Set(edges.getIds());
    const newEdgeIds = new Set(filteredEdges.map(e => e.id));

    // DELTA UPDATE: Only update edges that actually changed
    const edgeUpdates = [];
    for (const edge of filteredEdges) {
        const cached = edgeStateCache.get(edge.id);
        const isNew = !currentEdgeIds.has(edge.id);

        // Only update if: new edge or packet count changed significantly
        const needsUpdate = isNew ||
            !cached ||
            Math.abs(cached.packetCount - edge.packetCount) > cached.packetCount * 0.1;

        if (needsUpdate) {
            edgeUpdates.push({
                id: edge.id,
                from: edge.from,
                to: edge.to,
                label: formatEdgeLabel(edge),
                title: formatEdgeTooltip(edge),
                color: { color: edge.protocol.Color },
                width: Math.log(edge.packetCount + 1) * 0.5 + 1,
                protocol: edge.protocol,
                hidden: protocolFilters.has(edge.protocol.Name),
                packetCount: edge.packetCount,
                byteCount: edge.byteCount
            });
        }

        // Update cache
        edgeStateCache.set(edge.id, { packetCount: edge.packetCount, byteCount: edge.byteCount });
    }

    // Remove edges that no longer exist
    const edgesToRemove = [...currentEdgeIds].filter(id => !newEdgeIds.has(id));
    if (edgesToRemove.length > 0) {
        edges.remove(edgesToRemove);
        edgesToRemove.forEach(id => edgeStateCache.delete(id));
    }

    // Only call update if there are actual changes
    if (edgeUpdates.length > 0) {
        edges.update(edgeUpdates);
    }

    // Update packets list and cache
    if (data.packets && data.packets.length > 0) {
        packets = data.packets;

        // Add new packets to persistent cache
        data.packets.forEach(packet => {
            if (!packetCache.has(packet.id)) {
                packetCache.set(packet.id, packet);
            }
        });

        // Maintain cache size limit (keep most recent packets)
        if (packetCache.size > MAX_CACHED_PACKETS) {
            const sortedIds = Array.from(packetCache.keys()).sort((a, b) => a - b);
            const toDelete = sortedIds.slice(0, packetCache.size - MAX_CACHED_PACKETS);
            toDelete.forEach(id => packetCache.delete(id));
        }

        // Debounced packet panel refresh (max once per 500ms)
        const now = Date.now();
        const packetPanel = document.getElementById('packetPanel');
        if (packetPanel && packetPanel.classList.contains('show') && (now - lastPacketPanelRefresh) > 500) {
            lastPacketPanelRefresh = now;
            loadPackets();
        }
    }

    // Calculate total collected packets from all nodes
    const totalPackets = data.nodes.reduce((sum, node) => sum + (node.packetCount || 0), 0);

    // Update statistics
    updateStatistics(data.nodes.length, data.edges.length, totalPackets);

    // Update game mode nodes if active and there were changes
    if (gameMode.active && (nodeUpdates.length > 0 || edgeUpdates.length > 0 || nodesToRemove.length > 0 || edgesToRemove.length > 0)) {
        refreshGameNodes();
    }
}

// Format node label
function formatNodeLabel(node) {
    return node.label !== node.id ? node.label : node.id;
}

// Format node tooltip
function formatNodeTooltip(node) {
    let tooltip = '';

    // Display hostname if different from ID
    if (node.label && node.label !== node.id) {
        tooltip += `Hostname: ${node.label}\n`;
    }

    // Display all IPs
    if (node.ips && node.ips.length > 0) {
        if (node.ips.length === 1) {
            tooltip += `IP: ${node.ips[0]}\n`;
        } else {
            tooltip += `IPs:\n`;
            node.ips.forEach(ip => {
                tooltip += `  ${ip}\n`;
            });
        }
    } else {
        // Fallback to ID if no IPs array
        tooltip += `IP: ${node.id}\n`;
    }

    tooltip += `Packets: ${node.packetCount}\nBytes: ${formatBytes(node.byteCount)}`;
    return tooltip;
}

// Format edge label
function formatEdgeLabel(edge) {
    return `${edge.protocol.Name} (${edge.packetCount})`;
}

// Format edge tooltip (bidirectional)
function formatEdgeTooltip(edge) {
    let tooltip = `${edge.from} ↔ ${edge.to}\nProtocol: ${edge.protocol.Name}\n`;
    tooltip += `Total: ${edge.packetCount} pkts, ${formatBytes(edge.byteCount)}\n`;
    // Show directional breakdown if available
    if (edge.forwardPackets !== undefined || edge.reversePackets !== undefined) {
        const fwdPkts = edge.forwardPackets || 0;
        const revPkts = edge.reversePackets || 0;
        const fwdBytes = edge.forwardBytes || 0;
        const revBytes = edge.reverseBytes || 0;
        tooltip += `→ ${fwdPkts} pkts (${formatBytes(fwdBytes)})\n`;
        tooltip += `← ${revPkts} pkts (${formatBytes(revBytes)})`;
    }
    return tooltip;
}

// Format bytes for display
function formatBytes(bytes) {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(2) + ' KB';
    if (bytes < 1024 * 1024 * 1024) return (bytes / (1024 * 1024)).toFixed(2) + ' MB';
    return (bytes / (1024 * 1024 * 1024)).toFixed(2) + ' GB';
}

// Show node details
function showNodeDetails(nodeId) {
    const node = nodes.get(nodeId);
    const connectedEdges = edges.get({
        filter: edge => edge.from === nodeId || edge.to === nodeId
    });

    const detailsPanel = document.getElementById('detailsPanel');
    const modalBackdrop = document.getElementById('modalBackdrop');
    const detailsContent = document.getElementById('detailsContent');

    detailsPanel.classList.add('active');
    modalBackdrop.classList.add('active');

    // Format IP addresses
    let ipAddressHTML = '';
    if (node.ips && node.ips.length > 0) {
        if (node.ips.length === 1) {
            ipAddressHTML = `<strong>IP Address:</strong> ${node.ips[0]}`;
        } else {
            // Multiple IPs (IPv4 + IPv6)
            const ipv4 = node.ips.filter(ip => ip.includes('.'));
            const ipv6 = node.ips.filter(ip => ip.includes(':'));

            if (ipv4.length > 0) {
                ipAddressHTML += `<strong>IPv4:</strong> ${ipv4.join(', ')}<br>`;
            }
            if (ipv6.length > 0) {
                ipAddressHTML += `<strong>IPv6:</strong> ${ipv6.join(', ')}`;
            }
            if (ipv4.length === 0 && ipv6.length === 0) {
                ipAddressHTML = `<strong>IP Addresses:</strong> ${node.ips.join(', ')}`;
            }
        }
    } else {
        ipAddressHTML = `<strong>IP Address:</strong> ${nodeId}`;
    }

    // Format hostname (only show if different from node ID)
    const hostnameHTML = (node.hostname && node.hostname !== nodeId)
        ? `<div class="detail-item"><strong>Hostname:</strong> ${node.hostname}</div>`
        : '';

    detailsContent.innerHTML = `
        <h4>Node Details</h4>
        ${hostnameHTML}
        <div class="detail-item">
            ${ipAddressHTML}
        </div>
        <div class="detail-item">
            <strong>Total Packets:</strong> ${node.packetCount || 0}
        </div>
        <div class="detail-item">
            <strong>Total Bytes:</strong> ${formatBytes(node.byteCount || 0)}
        </div>
        <div class="detail-item">
            <strong>Active Connections:</strong> ${connectedEdges.length}
        </div>
        <h5>Connections:</h5>
        <div class="connections-list">
            ${connectedEdges.map(edge => `
                <div class="connection-item">
                    <span class="color-box" style="background-color: ${edge.color.color}"></span>
                    ${edge.from === nodeId ? '→ ' + edge.to : '← ' + edge.from}
                    (${edge.protocol.Name})
                </div>
            `).join('')}
        </div>
    `;
}

// Show edge details
function showEdgeDetails(edgeId) {
    const edge = edges.get(edgeId);
    const detailsPanel = document.getElementById('detailsPanel');
    const modalBackdrop = document.getElementById('modalBackdrop');
    const detailsContent = document.getElementById('detailsContent');

    detailsPanel.classList.add('active');
    modalBackdrop.classList.add('active');

    detailsContent.innerHTML = `
        <h4>Connection Details</h4>
        <div class="detail-item">
            <strong>From:</strong> ${edge.from}
        </div>
        <div class="detail-item">
            <strong>To:</strong> ${edge.to}
        </div>
        <div class="detail-item">
            <strong>Protocol:</strong>
            <span class="color-box" style="background-color: ${edge.color.color}"></span>
            ${edge.protocol.Name}
        </div>
        <div class="detail-item">
            <strong>Packets:</strong> ${edge.packetCount}
        </div>
        <div class="detail-item">
            <strong>Bytes:</strong> ${formatBytes(edge.byteCount)}
        </div>
    `;
}

// Hide details panel
function hideDetails() {
    const detailsPanel = document.getElementById('detailsPanel');
    const modalBackdrop = document.getElementById('modalBackdrop');
    detailsPanel.classList.remove('active');
    modalBackdrop.classList.remove('active');
    document.getElementById('detailsContent').innerHTML = '<p class="placeholder">Click on a node or edge to view details</p>';
}

// Update statistics
function updateStatistics(nodeCount, edgeCount, totalPackets = 0) {
    document.getElementById('nodeCount').textContent = nodeCount;
    document.getElementById('edgeCount').textContent = edgeCount;

    // Update total packets if element exists
    const totalPacketsElement = document.getElementById('totalPackets');
    if (totalPacketsElement) {
        totalPacketsElement.textContent = totalPackets.toLocaleString();
    }
}

// Update connection status
function updateConnectionStatus(status, connected) {
    const statusElement = document.getElementById('connectionStatus');
    const statsIcon = document.querySelector('#statsToggle .nav-icon');

    statusElement.textContent = status;
    statusElement.className = 'stat-value ' + (connected ? 'connected' : 'disconnected');

    // Update stats icon color based on connection status
    if (statsIcon) {
        // Remove all status classes
        statsIcon.classList.remove('status-connecting', 'status-connected', 'status-disconnected');

        // Add appropriate status class
        if (status === 'Connecting...' || status === 'Connecting') {
            statsIcon.classList.add('status-connecting');
        } else if (connected) {
            statsIcon.classList.add('status-connected');
        } else {
            statsIcon.classList.add('status-disconnected');
        }
    }
}

// Setup theme toggle
function setupTheme() {
    const themeButtons = document.querySelectorAll('[data-theme]');

    themeButtons.forEach(button => {
        button.addEventListener('click', function() {
            const theme = this.getAttribute('data-theme');

            // Remove active class from all theme buttons
            themeButtons.forEach(btn => btn.classList.remove('active'));

            // Add active class to clicked button
            this.classList.add('active');

            // Apply theme
            if (theme === 'light') {
                document.body.classList.add('light-theme');
            } else {
                document.body.classList.remove('light-theme');
            }

            // Update network with new theme-aware options
            if (network) {
                network.setOptions(getNetworkOptions());
            }
        });
    });
}

// Setup cluster layout toggle
function setupClusterLayout() {
    const clusterButtons = document.querySelectorAll('[data-cluster]');

    // Load saved cluster layout from localStorage (default to 'force')
    const savedLayout = localStorage.getItem('clusterLayout') || 'force';

    // Set initial active state based on saved preference
    clusterButtons.forEach(button => {
        const layout = button.getAttribute('data-cluster');
        if (layout === savedLayout) {
            button.classList.add('active');
        } else {
            button.classList.remove('active');
        }
    });

    // Apply the saved layout (will be applied once network is ready)
    currentClusterLayout = savedLayout;

    clusterButtons.forEach(button => {
        button.addEventListener('click', function() {
            const layout = this.getAttribute('data-cluster');

            // Remove active class from all cluster buttons
            clusterButtons.forEach(btn => btn.classList.remove('active'));

            // Add active class to clicked button
            this.classList.add('active');

            // Save to localStorage
            localStorage.setItem('clusterLayout', layout);

            // Apply layout
            applyClusterLayout(layout);
        });
    });
}

// Apply cluster layout to the network
function applyClusterLayout(layout) {
    if (!network) return;

    // Save current layout mode
    currentClusterLayout = layout;

    const options = getNetworkOptions();

    switch (layout) {
        case 'circular':
            // Disable physics and use circular layout
            options.physics.enabled = false;
            options.physics.stabilization = false;
            options.layout = {
                improvedLayout: true,
                hierarchical: false
            };

            // Apply options first to disable physics
            network.setOptions(options);

            // Stop any ongoing simulation
            network.stopSimulation();

            // Position nodes in a circle
            const nodeIds = nodes.getIds();
            const angleStep = (2 * Math.PI) / nodeIds.length;
            const radius = 300;

            nodeIds.forEach((id, index) => {
                const angle = index * angleStep;
                const x = radius * Math.cos(angle);
                const y = radius * Math.sin(angle);
                nodes.update({ id: id, x: x, y: y, fixed: { x: true, y: true } });
            });

            // Early return since we already called setOptions
            return;

        case 'hierarchical':
            // Hierarchical layout based on packet counts and communication patterns
            const hierNodeIds = nodes.getIds();
            const hierTier = getPerformanceTier(hierNodeIds.length);

            // Calculate incoming and outgoing traffic for each node
            const incomingTraffic = new Map();  // node -> total incoming packets
            const outgoingTraffic = new Map();  // node -> total outgoing packets
            const connections = new Map();       // node -> Set of nodes it talks to

            // Initialize maps
            hierNodeIds.forEach(id => {
                incomingTraffic.set(id, 0);
                outgoingTraffic.set(id, 0);
                connections.set(id, new Set());
            });

            // Analyze edges to build traffic patterns
            edges.get().forEach(edge => {
                if (edge.hidden) return;
                const packets = edge.packetCount || 1;

                // Track outgoing from source
                outgoingTraffic.set(edge.from, (outgoingTraffic.get(edge.from) || 0) + packets);

                // Track incoming to destination
                incomingTraffic.set(edge.to, (incomingTraffic.get(edge.to) || 0) + packets);

                // Track connections
                if (connections.has(edge.from)) {
                    connections.get(edge.from).add(edge.to);
                }
            });

            // Calculate hierarchy level for each node
            // Level is based on: ratio of incoming to outgoing traffic
            // High incoming (servers) = level 0 (top)
            // High outgoing (clients) = higher level (bottom)
            // Also consider total traffic volume for importance

            const nodeLevels = new Map();
            const nodeScores = [];

            hierNodeIds.forEach(id => {
                const incoming = incomingTraffic.get(id) || 0;
                const outgoing = outgoingTraffic.get(id) || 0;
                const total = incoming + outgoing;
                const connectionCount = connections.get(id)?.size || 0;

                // Calculate a score: higher = more "server-like" (receives more than sends)
                // Score combines traffic ratio with total volume
                let score = 0;
                if (total > 0) {
                    // Ratio component: incoming / total (0 to 1, higher = more incoming)
                    const ratio = incoming / total;
                    // Volume component: log scale of total traffic
                    const volume = Math.log(total + 1);
                    // Connection component: more connections = more central
                    const connectivity = Math.log(connectionCount + 1);

                    // Combined score (weighted)
                    score = (ratio * 50) + (volume * 30) + (connectivity * 20);
                }

                nodeScores.push({ id, score, incoming, outgoing, total, connectionCount });
            });

            // Sort by score descending (highest score = top of hierarchy)
            nodeScores.sort((a, b) => b.score - a.score);

            // Assign levels based on score percentiles
            // Top nodes get level 0, bottom nodes get higher levels
            const numLevels = Math.min(Math.ceil(hierNodeIds.length / 5), 10); // Max 10 levels
            const nodesPerLevel = Math.ceil(hierNodeIds.length / numLevels);

            nodeScores.forEach((node, index) => {
                const level = Math.floor(index / nodesPerLevel);
                nodeLevels.set(node.id, level);
            });

            // Batch update nodes with their hierarchy levels
            const hierUpdates = hierNodeIds.map(id => ({
                id: id,
                level: nodeLevels.get(id) || 0,
                fixed: { x: false, y: false }
            }));
            nodes.update(hierUpdates);

            // Configure hierarchical layout
            options.physics.enabled = hierTier !== 'low'; // Use physics for fine-tuning except on small graphs
            options.physics.hierarchicalRepulsion = {
                centralGravity: 0.0,
                springLength: 150,
                springConstant: 0.01,
                nodeDistance: 120,
                damping: 0.09
            };
            options.physics.solver = 'hierarchicalRepulsion';
            options.physics.stabilization = {
                enabled: true,
                iterations: hierTier === 'low' ? 100 : 50,
                updateInterval: 50
            };
            options.layout = {
                improvedLayout: hierTier === 'low',
                hierarchical: {
                    enabled: true,
                    direction: 'UD',  // Up-Down: servers at top
                    sortMethod: 'directed',
                    levelSeparation: 120,
                    nodeSpacing: hierTier === 'maximum' ? 100 : 150,
                    treeSpacing: hierTier === 'maximum' ? 150 : 200,
                    shakeTowards: 'roots'  // Shake undefined nodes towards the roots (top)
                }
            };

            // Apply options
            network.setOptions(options);

            // Stop any ongoing simulation after layout is computed
            if (hierTier === 'low') {
                network.stopSimulation();
            } else {
                // Let physics settle briefly then stop
                setTimeout(() => {
                    if (network) network.stopSimulation();
                }, 2000);
            }

            // Early return since we already called setOptions
            return;

        case 'gravity':
            // Clustered Host: Position nodes based on traffic patterns (no physics)
            const gravityNodeIds = nodes.getIds();

            // Disable physics for static layout
            options.physics.enabled = false;
            options.physics.stabilization = false;
            options.layout = {
                improvedLayout: false,
                hierarchical: false
            };

            // Apply options first to disable physics
            network.setOptions(options);
            network.stopSimulation();

            // Calculate packet counts for each node
            const nodePacketCounts = new Map();

            // Get all edges and calculate incoming packet counts
            edges.get().forEach(edge => {
                if (!edge.hidden) {
                    const toNode = edge.to;
                    const packetCount = edge.packetCount || 0;
                    nodePacketCounts.set(toNode, (nodePacketCounts.get(toNode) || 0) + packetCount);
                }
            });

            // Sort nodes by packet count (highest first)
            const maxPackets = Math.max(...Array.from(nodePacketCounts.values()), 1);
            const sortedNodes = gravityNodeIds.map(id => ({
                id,
                packets: nodePacketCounts.get(id) || 0
            })).sort((a, b) => b.packets - a.packets);

            // Position nodes in concentric circles based on traffic
            // High-traffic nodes in center, low-traffic on outer rings
            const centerX = 0;
            const centerY = 0;
            const minRadius = 50;
            const radiusStep = 80;

            // Group nodes into rings based on packet count percentiles
            const numRings = Math.min(Math.ceil(sortedNodes.length / 8), 10);
            const nodesPerRing = Math.ceil(sortedNodes.length / numRings);

            const nodeUpdates = sortedNodes.map((node, index) => {
                const ring = Math.floor(index / nodesPerRing);
                const positionInRing = index % nodesPerRing;
                const nodesInThisRing = Math.min(nodesPerRing, sortedNodes.length - ring * nodesPerRing);

                const radius = minRadius + (ring * radiusStep);
                const angle = (2 * Math.PI * positionInRing) / nodesInThisRing;

                const x = centerX + radius * Math.cos(angle);
                const y = centerY + radius * Math.sin(angle);

                return {
                    id: node.id,
                    x: x,
                    y: y,
                    fixed: { x: true, y: true },
                    value: Math.log(node.packets + 1) * 5
                };
            });

            nodes.update(nodeUpdates);

            // Fit view to show all nodes
            setTimeout(() => {
                if (network) network.fit({ animation: { duration: 500 } });
            }, 100);

            return;

        case 'subnet':
            // Clustered Subnet: Group nodes by IP subnet (no physics)
            const subnetNodeIds = nodes.getIds();

            // Disable physics for static layout
            options.physics.enabled = false;
            options.physics.stabilization = false;
            options.layout = {
                improvedLayout: false,
                hierarchical: false
            };

            // Apply options first to disable physics
            network.setOptions(options);
            network.stopSimulation();

            // Group nodes by subnet
            const subnetGroups = new Map();

            subnetNodeIds.forEach(id => {
                const node = nodes.get(id);
                const label = node.label || id || '';

                // Try to extract subnet from IP address (assumes /24 subnet)
                // Check both label and id for IP patterns
                let subnet = 'unknown';
                const ipMatch = label.match(/(\d{1,3}\.\d{1,3}\.\d{1,3})\.\d{1,3}/) ||
                               (id && id.match(/(\d{1,3}\.\d{1,3}\.\d{1,3})\.\d{1,3}/));
                if (ipMatch) {
                    subnet = ipMatch[1];
                }

                if (!subnetGroups.has(subnet)) {
                    subnetGroups.set(subnet, []);
                }
                subnetGroups.get(subnet).push(id);
            });

            // Position each subnet group in a different area
            const subnetCount = subnetGroups.size;
            const subnetsArray = Array.from(subnetGroups.entries());

            // Adjust cluster radius based on number of subnets
            const clusterRadius = Math.max(300, subnetCount * 60);

            // Batch all node updates for better performance
            const subnetUpdates = [];
            subnetsArray.forEach(([subnet, nodeIdsInSubnet], index) => {
                const angle = (2 * Math.PI * index) / subnetCount;
                const clusterCenterX = clusterRadius * Math.cos(angle);
                const clusterCenterY = clusterRadius * Math.sin(angle);

                // Adjust subnet radius based on number of nodes in subnet
                const subnetRadius = Math.max(50, Math.min(150, nodeIdsInSubnet.length * 15));

                nodeIdsInSubnet.forEach((id, nodeIndex) => {
                    const nodeAngle = (2 * Math.PI * nodeIndex) / nodeIdsInSubnet.length;
                    const x = clusterCenterX + (subnetRadius * Math.cos(nodeAngle));
                    const y = clusterCenterY + (subnetRadius * Math.sin(nodeAngle));

                    subnetUpdates.push({
                        id: id,
                        x: x,
                        y: y,
                        fixed: { x: true, y: true }
                    });
                });
            });
            nodes.update(subnetUpdates);

            // Fit view to show all nodes
            setTimeout(() => {
                if (network) network.fit({ animation: { duration: 500 } });
            }, 100);

            return;

        case 'force':
        default:
            // Enable physics for force-directed layout
            options.physics.enabled = true;
            options.layout = {
                improvedLayout: true,
                hierarchical: false
            };

            // Unfix all nodes to allow physics to work
            const allNodeIds = nodes.getIds();
            allNodeIds.forEach(id => {
                nodes.update({ id: id, fixed: { x: false, y: false } });
            });
            break;
    }

    network.setOptions(options);
}

// Chimpy Mode Implementation
let chimpyMode = {
    active: false,
    currentEdgeIndex: 0,
    currentProgress: 0,
    speed: 0.01, // Progress per frame (0-1)
    animationFrame: null,
    currentEdge: null,
    edgePath: []
};

// Setup Chimpy Mode
function setupChimpyMode() {
    const chimpyToggle = document.getElementById('chimpyToggle');

    if (chimpyToggle) {
        chimpyToggle.addEventListener('click', function() {
            toggleChimpyMode();
        });
    }
}

// Toggle Chimpy Mode on/off
function toggleChimpyMode() {
    const chimpyToggle = document.getElementById('chimpyToggle');
    const chimpyContainer = document.getElementById('chimpyContainer');

    chimpyMode.active = !chimpyMode.active;

    if (chimpyMode.active) {
        // Activate Chimpy Mode
        chimpyToggle.classList.add('chimpy-active');
        chimpyContainer.style.display = 'block';

        // Build edge path for Chimpy to follow
        buildChimpyPath();

        // Start animation
        startChimpyAnimation();
    } else {
        // Deactivate Chimpy Mode
        chimpyToggle.classList.remove('chimpy-active');
        chimpyContainer.style.display = 'none';

        // Stop animation
        stopChimpyAnimation();

        // Reset camera zoom
        if (network) {
            network.moveTo({
                scale: 1.0,
                animation: {
                    duration: 500,
                    easingFunction: 'easeInOutQuad'
                }
            });
        }
    }
}

// Build a path of edges for Chimpy to ride
function buildChimpyPath() {
    if (!network) {
        chimpyMode.edgePath = [];
        return;
    }

    // Get all visible edges
    const allEdges = edges.get().filter(e => !e.hidden);

    if (allEdges.length === 0) {
        chimpyMode.edgePath = [];
        console.warn('Chimpy: No visible edges found');
        return;
    }

    // Validate that edges have valid nodes with positions
    const validEdges = allEdges.filter(edge => {
        const fromNode = nodes.get(edge.from);
        const toNode = nodes.get(edge.to);

        if (!fromNode || !toNode) {
            return false;
        }

        // Check if we can get positions for these nodes
        try {
            const positions = network.getPositions([edge.from, edge.to]);
            return positions[edge.from] && positions[edge.to];
        } catch (e) {
            return false;
        }
    });

    if (validEdges.length === 0) {
        chimpyMode.edgePath = [];
        console.warn('Chimpy: No valid edges with positions found');
        return;
    }

    console.log(`Chimpy: Found ${validEdges.length} valid edges to ride`);

    // Sort edges by packet count (most active first) to make it interesting
    const sortedEdges = validEdges.sort((a, b) => b.packetCount - a.packetCount);

    // Take top edges and shuffle for variety
    const topEdges = sortedEdges.slice(0, Math.min(20, sortedEdges.length));
    chimpyMode.edgePath = shuffleArray([...topEdges]);
    chimpyMode.currentEdgeIndex = 0;
    chimpyMode.currentProgress = 0;
}

// Shuffle array helper
function shuffleArray(array) {
    for (let i = array.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [array[i], array[j]] = [array[j], array[i]];
    }
    return array;
}

// Start Chimpy animation
function startChimpyAnimation() {
    if (chimpyMode.edgePath.length === 0) {
        console.warn('No edges available for Chimpy to ride');
        return;
    }

    function animate() {
        if (!chimpyMode.active) return;

        updateChimpyPosition();
        chimpyMode.animationFrame = requestAnimationFrame(animate);
    }

    animate();
}

// Stop Chimpy animation
function stopChimpyAnimation() {
    if (chimpyMode.animationFrame) {
        cancelAnimationFrame(chimpyMode.animationFrame);
        chimpyMode.animationFrame = null;
    }
}

// Update Chimpy's position along the edge
function updateChimpyPosition() {
    if (!network || chimpyMode.edgePath.length === 0) return;

    // Get current edge
    const edge = chimpyMode.edgePath[chimpyMode.currentEdgeIndex];
    if (!edge) {
        moveToNextEdge();
        return;
    }

    chimpyMode.currentEdge = edge;

    // Validate nodes exist
    const fromNode = nodes.get(edge.from);
    const toNode = nodes.get(edge.to);

    if (!fromNode || !toNode) {
        console.warn(`Chimpy: Nodes not found for edge ${edge.id}, skipping`);
        moveToNextEdge();
        return;
    }

    // Get positions in canvas coordinates
    let positions;
    try {
        positions = network.getPositions([edge.from, edge.to]);
    } catch (e) {
        console.error('Chimpy: Error getting positions', e);
        moveToNextEdge();
        return;
    }

    const fromPos = positions[edge.from];
    const toPos = positions[edge.to];

    if (!fromPos || !toPos) {
        console.warn(`Chimpy: Invalid positions for edge ${edge.id}`);
        moveToNextEdge();
        return;
    }

    // Interpolate position along the edge (linear interpolation)
    const progress = chimpyMode.currentProgress;
    const canvasX = fromPos.x + (toPos.x - fromPos.x) * progress;
    const canvasY = fromPos.y + (toPos.y - fromPos.y) * progress;

    // Convert canvas coordinates to DOM coordinates
    let domPosition;
    try {
        domPosition = network.canvasToDOM({ x: canvasX, y: canvasY });
    } catch (e) {
        console.error('Chimpy: Error converting coordinates', e);
        moveToNextEdge();
        return;
    }

    // Get the network container offset to position Chimpy correctly
    const networkContainer = document.getElementById('network');
    const containerRect = networkContainer.getBoundingClientRect();

    // Calculate absolute position on screen
    const screenX = containerRect.left + domPosition.x;
    const screenY = containerRect.top + domPosition.y;

    // Update Chimpy character position
    const chimpyCharacter = document.getElementById('chimpyCharacter');
    if (chimpyCharacter) {
        chimpyCharacter.style.left = screenX + 'px';
        chimpyCharacter.style.top = screenY + 'px';
    }

    // Update packet window position (offset to the right and down)
    const chimpyPacketWindow = document.getElementById('chimpyPacketWindow');
    if (chimpyPacketWindow) {
        chimpyPacketWindow.style.left = (screenX + 60) + 'px';
        chimpyPacketWindow.style.top = (screenY - 20) + 'px';
    }

    // Update packet info in the window
    updateChimpyPacketInfo(edge);

    // Follow Chimpy with camera (medium zoom)
    network.moveTo({
        position: { x: canvasX, y: canvasY },
        scale: 1.5, // Medium zoom
        animation: false // Smooth following without animation delay
    });

    // Increment progress
    chimpyMode.currentProgress += chimpyMode.speed;

    // Move to next edge when current edge is complete
    if (chimpyMode.currentProgress >= 1.0) {
        moveToNextEdge();
    }
}

// Move to the next edge in the path
function moveToNextEdge() {
    chimpyMode.currentEdgeIndex = (chimpyMode.currentEdgeIndex + 1) % chimpyMode.edgePath.length;
    chimpyMode.currentProgress = 0;

    // Rebuild path occasionally to get new edges
    if (chimpyMode.currentEdgeIndex === 0) {
        buildChimpyPath();
    }
}

// Update packet information in Chimpy's window
function updateChimpyPacketInfo(edge) {
    const chimpyPacketContent = document.getElementById('chimpyPacketContent');
    const chimpyHexDump = document.getElementById('chimpyHexDump');

    if (!edge) return;

    // Get the actual nodes to access their IP addresses
    const fromNode = nodes.get(edge.from);
    const toNode = nodes.get(edge.to);

    if (!fromNode || !toNode) {
        document.querySelector('.chimpy-packet-info').innerHTML = `
<strong>Riding:</strong> ${edge.from} → ${edge.to}
<strong>Protocol:</strong> ${edge.protocol.Name}
<strong>Packets:</strong> ${edge.packetCount}

Loading node data...
        `;
        chimpyHexDump.innerHTML = '';
        return;
    }

    // Get all IPs for both nodes (handles both IPv4 and IPv6, plus hostname consolidation)
    const fromIPs = fromNode.ips || [edge.from];
    const toIPs = toNode.ips || [edge.to];

    // Find packets that match this edge by checking if packet src/dst match any IPs
    const edgePackets = packets.filter(p => {
        const srcMatch = fromIPs.includes(p.src);
        const dstMatch = toIPs.includes(p.dst);
        const reverseSrcMatch = toIPs.includes(p.src);
        const reverseDstMatch = fromIPs.includes(p.dst);

        return (srcMatch && dstMatch) || (reverseSrcMatch && reverseDstMatch);
    });

    if (edgePackets.length > 0) {
        // Pick the most recent packet from this edge
        const packet = edgePackets[edgePackets.length - 1];

        // Update info
        const infoHTML = `
<strong>Riding:</strong> ${edge.from} → ${edge.to}
<strong>Protocol:</strong> ${edge.protocol.Name}
<strong>Packets:</strong> ${edge.packetCount}
<strong>Bytes:</strong> ${formatBytes(edge.byteCount)}

<strong>Current Packet #${packet.id}:</strong>
${packet.src}:${packet.srcPort || '?'} → ${packet.dst}:${packet.dstPort || '?'}
Length: ${packet.length} bytes
        `;

        document.querySelector('.chimpy-packet-info').innerHTML = infoHTML;

        // Generate mini hex dump (first 8 lines only)
        if (packet.payload) {
            const payloadBytes = base64ToBytes(packet.payload);
            const lines = [];
            const bytesPerLine = 16;
            const displayBytes = Math.min(payloadBytes.length, 128); // Show first 128 bytes

            for (let offset = 0; offset < displayBytes; offset += bytesPerLine) {
                const hexOffset = offset.toString(16).padStart(4, '0');
                const bytes = [];
                const ascii = [];

                for (let i = 0; i < bytesPerLine && offset + i < displayBytes; i++) {
                    const byte = payloadBytes[offset + i];
                    bytes.push(byte.toString(16).padStart(2, '0'));
                    ascii.push(byte >= 32 && byte <= 126 ? String.fromCharCode(byte) : '.');
                }

                const hexBytes = bytes.join(' ').padEnd(47, ' ');
                const asciiStr = ascii.join('');

                lines.push(
                    `<span class="hex-offset">${hexOffset}</span>  ` +
                    `<span class="hex-bytes">${hexBytes}</span>  ` +
                    `<span class="hex-ascii">${asciiStr}</span>`
                );
            }

            if (displayBytes < payloadBytes.length) {
                lines.push(`... (${payloadBytes.length - displayBytes} more bytes)`);
            }

            chimpyHexDump.innerHTML = lines.join('\n');
        } else {
            chimpyHexDump.innerHTML = 'No payload data available';
        }
    } else {
        // No packets found for this edge in current packet buffer
        const totalPacketsInBuffer = packets.length;
        document.querySelector('.chimpy-packet-info').innerHTML = `
<strong>Riding:</strong> ${edge.from} → ${edge.to}
<strong>Protocol:</strong> ${edge.protocol.Name}
<strong>Total Packets:</strong> ${edge.packetCount}
<strong>Bytes:</strong> ${formatBytes(edge.byteCount)}

<strong>IPs:</strong>
From: ${fromIPs.join(', ')}
To: ${toIPs.join(', ')}

Searching ${totalPacketsInBuffer} packets...
No matching packets in buffer yet.
        `;
        chimpyHexDump.innerHTML = 'Packet payloads will appear here once captured';
    }
}

// ========== Replay Mode Functions ==========

// Setup replay mode functionality
function setupReplayMode() {
    const replayToggle = document.getElementById('replayToggle');
    const replaySubmenu = document.getElementById('replaySubmenu');
    const returnToLiveButton = document.getElementById('returnToLiveButton');
    const downloadPcapButton = document.getElementById('downloadPcapButton');
    const timelineSlider = document.getElementById('timelineSlider');

    // Load pcap file list
    loadPcapFileList();

    // Reload list every 30 seconds when not in replay mode
    setInterval(() => {
        if (!replayMode.active) {
            loadPcapFileList();
        }
    }, 30000);

    // Return to live mode
    returnToLiveButton.addEventListener('click', () => {
        exitReplayMode();
    });

    // Download current pcap
    downloadPcapButton.addEventListener('click', () => {
        downloadCurrentPcap();
    });

    // Timeline slider
    timelineSlider.addEventListener('input', (e) => {
        const offsetSeconds = (e.target.value / 100) * replayMode.durationSeconds;
        replayMode.currentOffset = offsetSeconds;
        updateTimelineDisplay();
        loadReplayDataAtOffset(offsetSeconds);
    });
}

// Load list of available pcap files
async function loadPcapFileList() {
    try {
        const response = await fetch('/api/pcaps');
        const pcapFiles = await response.json();

        const fileList = document.getElementById('replayFileList');

        if (pcapFiles.length === 0) {
            fileList.innerHTML = '<div class="no-files">No pcap files available</div>';
            return;
        }

        // Show only 3 most recent
        const recentFiles = pcapFiles.slice(0, 3);

        fileList.innerHTML = recentFiles.map(file => `
            <div class="replay-file-item" data-filename="${file.path}">
                <div class="replay-file-name">${file.filename}</div>
                <div class="replay-file-meta">
                    <span>${file.packetCount} packets</span>
                    <span>${formatDuration(file.durationSec)}</span>
                </div>
            </div>
        `).join('');

        // Add click handlers
        fileList.querySelectorAll('.replay-file-item').forEach(item => {
            item.addEventListener('click', () => {
                const filename = item.getAttribute('data-filename');
                console.log('Pcap file clicked:', filename);
                enterReplayMode(filename);
            });
        });

        console.log('Loaded', recentFiles.length, 'pcap files with click handlers');

    } catch (error) {
        console.error('Failed to load pcap files:', error);
        document.getElementById('replayFileList').innerHTML =
            '<div class="error">Failed to load files</div>';
    }
}

// Enter replay mode with selected pcap file
async function enterReplayMode(filename) {
    try {
        console.log('Entering replay mode with file:', filename);

        // Disconnect WebSocket
        if (ws) {
            ws.close();
            ws = null;
        }

        // Load pcap metadata
        const response = await fetch(`/api/pcaps`);
        const pcapFiles = await response.json();
        const fileInfo = pcapFiles.find(f => f.path === filename);

        if (!fileInfo) {
            console.error('File not found:', filename);
            return;
        }

        console.log('File info:', fileInfo);

        // Update replay state
        replayMode.active = true;
        replayMode.currentFile = filename;
        replayMode.startTime = new Date(fileInfo.startTime);
        replayMode.endTime = new Date(fileInfo.endTime);
        replayMode.durationSeconds = fileInfo.durationSec;
        replayMode.currentOffset = 0;

        console.log('Replay state updated:', replayMode);

        // Clear current graph
        nodes.clear();
        edges.clear();
        packets = [];

        // Update UI
        const indicator = document.getElementById('replayModeIndicator');
        const returnButton = document.getElementById('returnToLiveButton');
        const timeline = document.getElementById('timelineContainer');
        const mainContent = document.querySelector('.main-content');

        console.log('UI elements:', { indicator, returnButton, timeline, mainContent });

        if (indicator) indicator.style.display = 'flex';
        if (returnButton) returnButton.style.display = 'block';
        if (timeline) {
            timeline.style.display = 'block';
            timeline.style.visibility = 'visible';
            timeline.style.opacity = '1';
            console.log('Timeline display set to block');
            console.log('Timeline computed style:', window.getComputedStyle(timeline).display, window.getComputedStyle(timeline).visibility, window.getComputedStyle(timeline).zIndex);
        }
        if (mainContent) mainContent.classList.add('timeline-visible');

        // Highlight selected file
        document.querySelectorAll('.replay-file-item').forEach(item => {
            item.classList.remove('active');
        });
        document.querySelector(`[data-filename="${filename}"]`).classList.add('active');

        // Update timeline
        const slider = document.getElementById('timelineSlider');
        slider.value = 0;
        updateTimelineDisplay();

        // Update connection status
        updateConnectionStatus('Replay Mode', false);

        // Load initial data (at time 0)
        await loadReplayDataAtOffset(0);

    } catch (error) {
        console.error('Failed to enter replay mode:', error);
        exitReplayMode();
    }
}

// Exit replay mode and return to live capture
function exitReplayMode() {
    // Reset replay state
    replayMode.active = false;
    replayMode.currentFile = null;

    // Clear graph
    nodes.clear();
    edges.clear();
    packets = [];

    // Update UI
    document.getElementById('replayModeIndicator').style.display = 'none';
    document.getElementById('returnToLiveButton').style.display = 'none';
    document.getElementById('timelineContainer').style.display = 'none';
    document.querySelector('.main-content').classList.remove('timeline-visible');

    // Remove active state from files
    document.querySelectorAll('.replay-file-item').forEach(item => {
        item.classList.remove('active');
    });

    // Reconnect WebSocket
    connectWebSocket();

    // Reload pcap list
    loadPcapFileList();
}

// Load replay data at specific time offset
async function loadReplayDataAtOffset(offsetSeconds) {
    if (!replayMode.active || !replayMode.currentFile) {
        return;
    }

    try {
        const response = await fetch(
            `/api/replay?filename=${encodeURIComponent(replayMode.currentFile)}&offset=${offsetSeconds}`
        );

        if (!response.ok) {
            throw new Error('Failed to load replay data');
        }

        const data = await response.json();

        // Update graph with replay data
        updateGraph(data);

    } catch (error) {
        console.error('Failed to load replay data:', error);
    }
}

// Update timeline display
function updateTimelineDisplay() {
    const currentTime = document.getElementById('timelineCurrentTime');
    const totalTime = document.getElementById('timelineTotalTime');
    const startLabel = document.getElementById('timelineStartLabel');
    const endLabel = document.getElementById('timelineEndLabel');

    if (replayMode.active) {
        currentTime.textContent = formatTime(replayMode.currentOffset);
        totalTime.textContent = formatTime(replayMode.durationSeconds);

        if (replayMode.startTime && replayMode.endTime) {
            startLabel.textContent = replayMode.startTime.toLocaleTimeString();
            endLabel.textContent = replayMode.endTime.toLocaleTimeString();
        }
    }
}

// Download current pcap file
function downloadCurrentPcap() {
    window.location.href = '/api/download';
}

// Format seconds as MM:SS
function formatTime(seconds) {
    const mins = Math.floor(seconds / 60);
    const secs = Math.floor(seconds % 60);
    return `${mins.toString().padStart(2, '0')}:${secs.toString().padStart(2, '0')}`;
}

// Format duration for display
function formatDuration(seconds) {
    if (seconds < 60) {
        return `${Math.floor(seconds)}s`;
    } else if (seconds < 3600) {
        const mins = Math.floor(seconds / 60);
        return `${mins}m`;
    } else {
        const hours = Math.floor(seconds / 3600);
        const mins = Math.floor((seconds % 3600) / 60);
        return `${hours}h ${mins}m`;
    }
}

// ==================== Streams Functionality ====================

// Streams state
let currentStreamData = null;
let currentStreamTab = 'decoded';

// Generate stream ID from packet data (matches backend logic)
function generateStreamId(srcIP, srcPort, dstIP, dstPort, protocol) {
    // Determine stream type based on protocol
    let streamType = 'TCP';
    if (protocol === 'UDP' || protocol === 'DNS') {
        streamType = 'UDP';
    }

    // Normalize direction (lower IP:port first)
    let src = `${srcIP}:${srcPort}`;
    let dst = `${dstIP}:${dstPort}`;

    if (src > dst) {
        [src, dst] = [dst, src];
    }

    return `${streamType}-${src}-${dst}`;
}

// Check if a protocol is stream-capable (TCP or UDP based)
function isStreamProtocol(protocol) {
    const streamProtocols = ['TCP', 'UDP', 'HTTP', 'HTTPS', 'DNS', 'SSH', 'FTP', 'SMTP', 'MySQL', 'PostgreSQL', 'Telnet', 'Redis', 'Slurm'];
    return streamProtocols.includes(protocol);
}

// Setup streams functionality
function setupStreams() {
    const protocolFilter = document.getElementById('streamProtocolFilter');
    const refreshButton = document.getElementById('refreshStreamsButton');
    const detailClose = document.getElementById('streamDetailClose');

    // Restore saved protocol filter from localStorage
    if (protocolFilter) {
        const savedProtocol = localStorage.getItem('streamProtocolFilter') || '';
        protocolFilter.value = savedProtocol;
    }

    // Protocol filter change - save to localStorage
    if (protocolFilter) {
        protocolFilter.addEventListener('change', () => {
            localStorage.setItem('streamProtocolFilter', protocolFilter.value);
            loadStreams(protocolFilter.value);
        });
    }

    // Refresh button
    if (refreshButton) {
        refreshButton.addEventListener('click', () => {
            const filter = document.getElementById('streamProtocolFilter');
            loadStreams(filter?.value || '');
        });
    }

    // Stream detail close button
    if (detailClose) {
        detailClose.addEventListener('click', closeStreamDetail);
    }

    // Setup stream detail tabs
    document.querySelectorAll('.stream-tab[data-stream-tab]').forEach(tab => {
        tab.addEventListener('click', () => {
            const tabName = tab.dataset.streamTab;
            switchStreamTab(tabName);
        });
    });
}

// Load streams from API
async function loadStreams(protocol = '') {
    const streamsList = document.getElementById('streamsList');
    const streamCount = document.getElementById('streamCount');

    if (!streamsList) return;

    streamsList.innerHTML = '<div class="loading">Loading streams...</div>';

    try {
        let url = '/api/streams';
        if (protocol) {
            url += `?protocol=${encodeURIComponent(protocol)}`;
        }

        const response = await fetch(url);
        if (!response.ok) {
            throw new Error('Failed to load streams');
        }

        const streams = await response.json();

        if (streamCount) {
            streamCount.textContent = streams.length;
        }

        if (streams.length === 0) {
            streamsList.innerHTML = '<div class="streams-empty">No streams captured yet</div>';
            return;
        }

        streamsList.innerHTML = streams.map(stream => renderStreamItem(stream)).join('');

        // Add click handlers
        streamsList.querySelectorAll('.stream-item').forEach(item => {
            item.addEventListener('click', () => {
                const streamId = item.dataset.streamId;
                openStreamDetail(streamId);
            });
        });

    } catch (error) {
        console.error('Failed to load streams:', error);
        streamsList.innerHTML = '<div class="streams-empty">Failed to load streams</div>';
    }
}

// Render a stream item for the list
function renderStreamItem(stream) {
    const protocolClass = stream.protocol.toLowerCase().replace(/\s+/g, '');
    const timeAgo = formatTimeAgo(new Date(stream.lastSeen));

    return `
        <div class="stream-item" data-stream-id="${escapeHtml(stream.id)}">
            <div class="stream-item-header">
                <span class="stream-protocol ${protocolClass}">${escapeHtml(stream.protocol)}</span>
                <span class="stream-type">${escapeHtml(stream.type)}</span>
            </div>
            <div class="stream-endpoints">
                ${escapeHtml(stream.srcIp)}:${stream.srcPort} → ${escapeHtml(stream.dstIp)}:${stream.dstPort}
            </div>
            <div class="stream-summary">${escapeHtml(stream.summary || 'No summary')}</div>
            <div class="stream-meta">
                <span>${stream.packetCount} packets</span>
                <span>${formatBytes(stream.byteCount)}</span>
                <span>${timeAgo}</span>
            </div>
        </div>
    `;
}

// Open stream detail panel
async function openStreamDetail(streamId) {
    const panel = document.getElementById('streamDetailPanel');
    const backdrop = document.getElementById('modalBackdrop');

    if (!panel) return;

    try {
        const response = await fetch(`/api/stream?id=${encodeURIComponent(streamId)}`);
        if (!response.ok) {
            throw new Error('Failed to load stream details');
        }

        currentStreamData = await response.json();

        // Update panel header
        document.getElementById('streamDetailTitle').textContent =
            `${currentStreamData.srcIp}:${currentStreamData.srcPort} → ${currentStreamData.dstIp}:${currentStreamData.dstPort}`;

        const badge = document.getElementById('streamProtocolBadge');
        badge.textContent = currentStreamData.protocol;
        badge.className = 'stream-protocol-badge ' + currentStreamData.protocol.toLowerCase();

        // Update metadata
        const metaContainer = document.getElementById('streamDetailMeta');
        metaContainer.innerHTML = `
            <div class="stream-meta-item">
                <span class="stream-meta-label">Type</span>
                <span class="stream-meta-value">${escapeHtml(currentStreamData.type)}</span>
            </div>
            <div class="stream-meta-item">
                <span class="stream-meta-label">Packets</span>
                <span class="stream-meta-value">${currentStreamData.packetCount}</span>
            </div>
            <div class="stream-meta-item">
                <span class="stream-meta-label">Bytes</span>
                <span class="stream-meta-value">${formatBytes(currentStreamData.byteCount)}</span>
            </div>
            <div class="stream-meta-item">
                <span class="stream-meta-label">Started</span>
                <span class="stream-meta-value">${new Date(currentStreamData.startTime).toLocaleString()}</span>
            </div>
            <div class="stream-meta-item">
                <span class="stream-meta-label">Last Seen</span>
                <span class="stream-meta-value">${new Date(currentStreamData.lastSeen).toLocaleString()}</span>
            </div>
        `;

        // Reset to decoded tab
        currentStreamTab = 'decoded';
        document.querySelectorAll('.stream-tab[data-stream-tab]').forEach(tab => {
            tab.classList.toggle('active', tab.dataset.streamTab === 'decoded');
        });

        // Render content
        renderStreamContent();

        // Show panel
        panel.style.display = 'flex';
        backdrop.style.display = 'block';

    } catch (error) {
        console.error('Failed to load stream details:', error);
    }
}

// Close stream detail panel
function closeStreamDetail() {
    const panel = document.getElementById('streamDetailPanel');
    const backdrop = document.getElementById('modalBackdrop');
    const detailsPanel = document.getElementById('detailsPanel');

    if (panel) {
        panel.style.display = 'none';
    }
    // Only hide backdrop if details panel is also closed
    if (backdrop && (!detailsPanel || !detailsPanel.classList.contains('open'))) {
        backdrop.style.display = 'none';
    }
    currentStreamData = null;
}

// Switch stream detail tab
function switchStreamTab(tabName) {
    currentStreamTab = tabName;

    document.querySelectorAll('.stream-tab[data-stream-tab]').forEach(tab => {
        tab.classList.toggle('active', tab.dataset.streamTab === tabName);
    });

    renderStreamContent();
}

// Render stream content based on current tab
function renderStreamContent() {
    if (!currentStreamData) return;

    const content = document.getElementById('streamContentPre');
    if (!content) return;

    switch (currentStreamTab) {
        case 'decoded':
            content.textContent = currentStreamData.decodedContent || 'No decoded content available';
            break;

        case 'raw':
            // Show hex dump of request and response
            let rawContent = '';
            if (currentStreamData.requestPayload) {
                rawContent += '=== REQUEST DATA ===\n';
                rawContent += formatBase64AsHex(currentStreamData.requestPayload);
            }
            if (currentStreamData.responsePayload) {
                rawContent += '\n=== RESPONSE DATA ===\n';
                rawContent += formatBase64AsHex(currentStreamData.responsePayload);
            }
            content.textContent = rawContent || 'No raw data available';
            break;

        case 'packets':
            // Render packets list
            if (currentStreamData.packets && currentStreamData.packets.length > 0) {
                const packetsHtml = currentStreamData.packets.map((pkt, idx) => {
                    const direction = pkt.direction === 'request' ? 'Request' : 'Response';
                    const time = new Date(pkt.timestamp).toLocaleTimeString();
                    const dataPreview = pkt.payload ?
                        truncateBase64(pkt.payload, 100) : '(empty)';

                    return `[${idx + 1}] ${direction} - ${time} - ${pkt.length} bytes\n${dataPreview}\n`;
                }).join('\n');
                content.textContent = packetsHtml;
            } else {
                content.textContent = 'No packets recorded';
            }
            break;
    }
}

// Format base64 data as hex dump
function formatBase64AsHex(base64Data) {
    try {
        const binary = atob(base64Data);
        let result = '';
        const lineWidth = 16;

        for (let i = 0; i < binary.length && i < 4096; i += lineWidth) {
            // Offset
            result += i.toString(16).padStart(8, '0') + '  ';

            // Hex bytes
            let hexPart = '';
            let asciiPart = '';
            for (let j = 0; j < lineWidth; j++) {
                if (i + j < binary.length) {
                    const byte = binary.charCodeAt(i + j);
                    hexPart += byte.toString(16).padStart(2, '0') + ' ';
                    asciiPart += (byte >= 32 && byte < 127) ? binary[i + j] : '.';
                } else {
                    hexPart += '   ';
                }
                if (j === 7) hexPart += ' ';
            }

            result += hexPart + ' |' + asciiPart + '|\n';
        }

        if (binary.length > 4096) {
            result += `\n... (${binary.length - 4096} more bytes truncated)`;
        }

        return result;
    } catch (e) {
        return '(Unable to decode data)';
    }
}

// Truncate base64 and show as ASCII
function truncateBase64(base64Data, maxChars) {
    try {
        const binary = atob(base64Data);
        let result = '';
        for (let i = 0; i < binary.length && i < maxChars; i++) {
            const byte = binary.charCodeAt(i);
            result += (byte >= 32 && byte < 127) ? binary[i] : '.';
        }
        if (binary.length > maxChars) {
            result += '...';
        }
        return result;
    } catch (e) {
        return '(Unable to decode)';
    }
}

// Format time ago
function formatTimeAgo(date) {
    const now = new Date();
    const diffMs = now - date;
    const diffSec = Math.floor(diffMs / 1000);

    if (diffSec < 60) return `${diffSec}s ago`;
    if (diffSec < 3600) return `${Math.floor(diffSec / 60)}m ago`;
    if (diffSec < 86400) return `${Math.floor(diffSec / 3600)}h ago`;
    return `${Math.floor(diffSec / 86400)}d ago`;
}

// Format bytes
function formatBytes(bytes) {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
    if (bytes < 1024 * 1024 * 1024) return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
    return (bytes / (1024 * 1024 * 1024)).toFixed(1) + ' GB';
}

// Escape HTML to prevent XSS
function escapeHtml(text) {
    if (text === null || text === undefined) return '';
    const div = document.createElement('div');
    div.textContent = String(text);
    return div.innerHTML;
}

// ==================== Game Mode Implementation ====================

// Game mode state
const gameMode = {
    active: false,
    scene: null,
    camera: null,
    renderer: null,
    raycaster: null,
    mouse: new THREE.Vector2(),
    nodeMeshes: [],
    nodeDataMap: new Map(), // mesh.uuid -> node data
    nodeIdToMesh: new Map(), // node.id -> mesh (for incremental updates)
    stars: null,
    nebulae: [],
    ambientDust: null,
    asteroids: [],
    animationId: null,
    moveForward: false,
    moveBackward: false,
    moveLeft: false,
    moveRight: false,
    moveUp: false,
    moveDown: false,
    velocity: new THREE.Vector3(),
    currentSpeed: 0,
    euler: new THREE.Euler(0, 0, 0, 'YXZ'),
    PI_2: Math.PI / 2,
    lockedTarget: null,
    laserCooldown: false,
    speedLinesActive: false,
    autoLockPosition: null,
    boosting: false,
    spaceElevators: [],
    elevatorParticles: [],
    warpDriveActive: false,
    warpSelectedIndex: 0,
    warpResults: [],
    isWarping: false
};

// Setup game mode
function setupGameMode() {
    const gameModeToggle = document.getElementById('gameModeToggle');

    if (gameModeToggle) {
        gameModeToggle.addEventListener('click', function(e) {
            e.stopPropagation();
            toggleGameMode();
        });
    }
}

// Toggle game mode on/off
function toggleGameMode() {
    const container = document.getElementById('gameModeContainer');
    const toggle = document.getElementById('gameModeToggle');

    if (gameMode.active) {
        // Deactivate game mode
        gameMode.active = false;
        container.style.display = 'none';
        toggle.classList.remove('game-active');

        // Stop animation loop
        if (gameMode.animationId) {
            cancelAnimationFrame(gameMode.animationId);
            gameMode.animationId = null;
        }

        // Cleanup space elevators first (before scene disposal)
        gameMode.spaceElevators.forEach(elevator => {
            if (elevator.line) {
                gameMode.scene.remove(elevator.line);
                if (elevator.line.geometry) elevator.line.geometry.dispose();
                if (elevator.line.material) elevator.line.material.dispose();
            }
            if (elevator.glow) {
                gameMode.scene.remove(elevator.glow);
                if (elevator.glow.geometry) elevator.glow.geometry.dispose();
                if (elevator.glow.material) elevator.glow.material.dispose();
            }
            if (elevator.particles) {
                gameMode.scene.remove(elevator.particles);
                if (elevator.particles.geometry) elevator.particles.geometry.dispose();
                if (elevator.particles.material) elevator.particles.material.dispose();
            }
        });
        gameMode.spaceElevators = [];

        // Cleanup node meshes
        gameMode.nodeMeshes.forEach(mesh => {
            if (mesh.children) {
                mesh.children.forEach(child => {
                    if (child.geometry) child.geometry.dispose();
                    if (child.material) child.material.dispose();
                });
            }
            if (mesh.geometry) mesh.geometry.dispose();
            if (mesh.material) mesh.material.dispose();
            gameMode.scene.remove(mesh);
        });
        gameMode.nodeMeshes = [];
        gameMode.nodeDataMap.clear();
        gameMode.nodeIdToMesh.clear();

        // Cleanup nebulae
        gameMode.nebulae.forEach(nebula => {
            if (nebula.geometry) nebula.geometry.dispose();
            if (nebula.material) nebula.material.dispose();
            gameMode.scene.remove(nebula);
        });
        gameMode.nebulae = [];

        // Cleanup stars
        if (gameMode.stars) {
            if (gameMode.stars.geometry) gameMode.stars.geometry.dispose();
            if (gameMode.stars.material) gameMode.stars.material.dispose();
            gameMode.scene.remove(gameMode.stars);
            gameMode.stars = null;
        }

        // Cleanup ambient dust
        if (gameMode.ambientDust) {
            if (gameMode.ambientDust.geometry) gameMode.ambientDust.geometry.dispose();
            if (gameMode.ambientDust.material) gameMode.ambientDust.material.dispose();
            gameMode.scene.remove(gameMode.ambientDust);
            gameMode.ambientDust = null;
        }

        // Cleanup sun flares
        if (gameMode.sunFlares) {
            if (gameMode.sunFlares.geometry) gameMode.sunFlares.geometry.dispose();
            if (gameMode.sunFlares.material) gameMode.sunFlares.material.dispose();
            gameMode.scene.remove(gameMode.sunFlares);
            gameMode.sunFlares = null;
        }

        // Cleanup shooting star
        if (gameMode.shootingStar) {
            if (gameMode.shootingStar.mesh) {
                if (gameMode.shootingStar.mesh.geometry) gameMode.shootingStar.mesh.geometry.dispose();
                if (gameMode.shootingStar.mesh.material) gameMode.shootingStar.mesh.material.dispose();
                gameMode.scene.remove(gameMode.shootingStar.mesh);
            }
            gameMode.shootingStar = null;
        }

        // Clear all remaining scene children
        while (gameMode.scene && gameMode.scene.children.length > 0) {
            const child = gameMode.scene.children[0];
            if (child.geometry) child.geometry.dispose();
            if (child.material) {
                if (Array.isArray(child.material)) {
                    child.material.forEach(m => m.dispose());
                } else {
                    child.material.dispose();
                }
            }
            gameMode.scene.remove(child);
        }

        // Cleanup Three.js renderer
        if (gameMode.renderer) {
            gameMode.renderer.dispose();
            gameMode.renderer = null;
        }

        // Clear scene and camera references
        gameMode.scene = null;
        gameMode.camera = null;
        gameMode.raycaster = null;
        gameMode.starTwinkleData = null;
        gameMode.asteroids = [];
        gameMode.elevatorParticles = [];
        gameMode.warpResults = [];
        gameMode.warpSelectedIndex = 0;

        // Reset movement state
        gameMode.moveForward = false;
        gameMode.moveBackward = false;
        gameMode.moveLeft = false;
        gameMode.moveRight = false;
        gameMode.moveUp = false;
        gameMode.moveDown = false;
        gameMode.boosting = false;
        gameMode.currentSpeed = 0;
        gameMode.velocity = new THREE.Vector3();
        gameMode.euler = new THREE.Euler(0, 0, 0, 'YXZ');
        gameMode.lockedTarget = null;
        gameMode.laserCooldown = false;
        gameMode.autoLockPosition = null;

        // Close warp drive if open
        if (gameMode.warpDriveActive) {
            closeWarpDrive();
        }
        gameMode.isWarping = false;

        // Hide HUD elements
        const cockpitHud = document.getElementById('cockpitHud');
        const targetingReticle = document.getElementById('targetingReticle');
        const crosshairEl = document.getElementById('crosshair');
        if (cockpitHud) cockpitHud.style.display = 'none';
        if (targetingReticle) targetingReticle.style.display = 'none';
        if (crosshairEl) crosshairEl.style.display = 'none';

        // Remove resize listener
        window.removeEventListener('resize', handleGameResize);

        // Unlock pointer
        document.exitPointerLock();

        // Remove event listeners
        document.removeEventListener('keydown', handleGameKeyDown);
        document.removeEventListener('keyup', handleGameKeyUp);
        document.removeEventListener('mousemove', handleGameMouseMove);
        document.removeEventListener('click', handleGameClick);

    } else {
        // Activate game mode
        gameMode.active = true;
        container.style.display = 'block';
        toggle.classList.add('game-active');

        // Cancel any lingering animation frame from previous session
        if (gameMode.animationId) {
            cancelAnimationFrame(gameMode.animationId);
            gameMode.animationId = null;
        }

        // Reset movement and camera state for fresh start
        gameMode.euler = new THREE.Euler(0, 0, 0, 'YXZ');
        gameMode.velocity = new THREE.Vector3();
        gameMode.currentSpeed = 0;
        gameMode.moveForward = false;
        gameMode.moveBackward = false;
        gameMode.moveLeft = false;
        gameMode.moveRight = false;
        gameMode.moveUp = false;
        gameMode.moveDown = false;
        gameMode.boosting = false;
        gameMode.lockedTarget = null;

        // Initialize Three.js scene
        initGameScene();

        // Add event listeners
        document.addEventListener('keydown', handleGameKeyDown);
        document.addEventListener('keyup', handleGameKeyUp);
        document.addEventListener('mousemove', handleGameMouseMove);
        document.addEventListener('click', handleGameClick);

        // Request pointer lock
        const canvas = document.getElementById('gameCanvas');
        canvas.requestPointerLock();

        // Start animation loop
        animateGameScene();
    }
}

function createCyberpunkCockpit() {
    // Minimal 3D cockpit - most HUD elements are CSS overlays
    const cockpit = new THREE.Group();

    const glowMaterial = new THREE.MeshBasicMaterial({
        color: 0x00ffcc,
        transparent: true,
        opacity: 0.6
    });

    // Just subtle 3D frame hints at the very edges
    const frameGeom = new THREE.BoxGeometry(0.05, 8, 0.05);

    // Far corner accents only
    const leftFrame = new THREE.Mesh(frameGeom, glowMaterial);
    leftFrame.position.set(-12, 0, -15);
    cockpit.add(leftFrame);

    const rightFrame = new THREE.Mesh(frameGeom, glowMaterial);
    rightFrame.position.set(12, 0, -15);
    cockpit.add(rightFrame);

    return cockpit;
}

// Initialize the Three.js scene
function initGameScene() {
    const oldCanvas = document.getElementById('gameCanvas');
    const width = window.innerWidth;
    const height = window.innerHeight;

    // Replace canvas to ensure clean WebGL context
    const newCanvas = document.createElement('canvas');
    newCanvas.id = 'gameCanvas';
    newCanvas.width = width;
    newCanvas.height = height;
    oldCanvas.parentNode.replaceChild(newCanvas, oldCanvas);
    const canvas = newCanvas;

    // Create scene
    gameMode.scene = new THREE.Scene();
    gameMode.scene.background = new THREE.Color(0x000208);
    gameMode.scene.fog = new THREE.FogExp2(0x000510, 0.000003); // Reduced fog for better visibility

    // Create camera
    gameMode.camera = new THREE.PerspectiveCamera(75, width / height, 10, 600000);
    gameMode.camera.position.set(0, 5000, 35000);
    const cockpit = createCyberpunkCockpit();
    gameMode.camera.add(cockpit);
    gameMode.scene.add(gameMode.camera);

    // Create renderer with fresh canvas
    gameMode.renderer = new THREE.WebGLRenderer({
        canvas: canvas,
        antialias: true,
        alpha: false,
        powerPreference: 'high-performance'
    });
    gameMode.renderer.setSize(width, height);
    gameMode.renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));

    document.getElementById('cockpitHud').style.display = 'block';
    document.getElementById('targetingReticle').style.display = 'block';
    document.getElementById('crosshair').style.display = 'block';
    document.querySelector('.cockpit-frame').style.display = 'none';
    document.getElementById('cockpitStats').style.display = 'none';


    // Create raycaster for targeting
    gameMode.raycaster = new THREE.Raycaster();
    gameMode.raycaster.far = 20000;

    // Create space atmosphere layers (back to front)
    createGalacticPlane();      // Milky Way band
    createNebulae();            // Colorful nebulae
    createCosmicDust();         // Dark dust lanes
    createStarfield();          // Multi-layer stars
    createDistantGalaxies();    // Spiral galaxies

    // Create sun (central light source)
    createSun();

    // Create asteroid belt
    createAsteroidBelt();

    // Create ambient dust near camera
    createAmbientDust();

    // Add ambient light
    const ambientLight = new THREE.AmbientLight(0x334466, 0.6);
    gameMode.scene.add(ambientLight);

    // Add directional light for better planet shading
    const dirLight = new THREE.DirectionalLight(0xffffff, 0.5);
    dirLight.position.set(100, 100, 100);
    gameMode.scene.add(dirLight);

    // Create nodes as planets
    createNodeSpheres();

    // Create space elevators between connected planets
    createSpaceElevators();

    // Initialize speed lines
    initSpeedLines();

    // Update HUD stats
    updateGameHUD();

    // Handle window resize
    window.addEventListener('resize', handleGameResize);
}

// Create nebulae for space atmosphere - vast and immersive
function createNebulae() {
    const nebulaColors = [
        { r: 0.6, g: 0.1, b: 0.8 },  // Deep Purple
        { r: 0.1, g: 0.5, b: 0.8 },  // Cosmic Blue
        { r: 0.8, g: 0.2, b: 0.5 },  // Magenta/Pink
        { r: 0.1, g: 0.7, b: 0.6 },  // Teal/Cyan
        { r: 0.7, g: 0.5, b: 0.1 },  // Gold/Orange
        { r: 0.4, g: 0.1, b: 0.6 },  // Violet
        { r: 0.1, g: 0.3, b: 0.5 },  // Deep Blue
        { r: 0.6, g: 0.1, b: 0.4 },  // Crimson
        { r: 0.2, g: 0.8, b: 0.3 },  // Emerald
        { r: 0.9, g: 0.4, b: 0.1 },  // Flame Orange
    ];

    // Create massive nebula clouds spanning the scene
    for (let n = 0; n < 10; n++) {
        const particleCount = 2000;
        const positions = new Float32Array(particleCount * 3);
        const colors = new Float32Array(particleCount * 3);

        // Spread nebulae across vast distances
        const nebulaX = (Math.random() - 0.5) * 180000;
        const nebulaY = (Math.random() - 0.5) * 80000;
        const nebulaZ = (Math.random() - 0.5) * 180000;
        const nebulaSize = 15000 + Math.random() * 30000;

        const baseColor = nebulaColors[Math.floor(Math.random() * nebulaColors.length)];
        const secondaryColor = nebulaColors[Math.floor(Math.random() * nebulaColors.length)];
        const tertiaryColor = nebulaColors[Math.floor(Math.random() * nebulaColors.length)];

        for (let i = 0; i < particleCount; i++) {
            // Gaussian-like distribution with wispy tendrils
            const r = nebulaSize * Math.pow(Math.random(), 0.35);
            const theta = Math.random() * Math.PI * 2;
            const phi = Math.acos(2 * Math.random() - 1);

            // Multiple tendril layers for organic look
            const tendril1 = Math.sin(theta * 4 + phi * 2) * 0.4 + 1;
            const tendril2 = Math.cos(theta * 2 - phi * 3) * 0.3 + 1;
            const tendrilFactor = (tendril1 + tendril2) / 2;

            positions[i * 3] = nebulaX + r * Math.sin(phi) * Math.cos(theta) * tendrilFactor;
            positions[i * 3 + 1] = nebulaY + r * Math.sin(phi) * Math.sin(theta) * 0.5;
            positions[i * 3 + 2] = nebulaZ + r * Math.cos(phi) * tendrilFactor;

            // Rich color gradients blending three colors
            const distFromCenter = r / nebulaSize;
            const colorBlend = Math.random();
            const colorVar = 0.3;

            let finalColor;
            if (colorBlend < 0.4) {
                finalColor = baseColor;
            } else if (colorBlend < 0.7) {
                finalColor = secondaryColor;
            } else {
                finalColor = tertiaryColor;
            }

            const brightness = 1 - distFromCenter * 0.4;
            colors[i * 3] = finalColor.r * brightness + (Math.random() - 0.5) * colorVar;
            colors[i * 3 + 1] = finalColor.g * brightness + (Math.random() - 0.5) * colorVar;
            colors[i * 3 + 2] = finalColor.b * brightness + (Math.random() - 0.5) * colorVar;
        }

        const geometry = new THREE.BufferGeometry();
        geometry.setAttribute('position', new THREE.BufferAttribute(positions, 3));
        geometry.setAttribute('color', new THREE.BufferAttribute(colors, 3));

        const nebulaOpacity = 0.02 + Math.random() * 0.03; // Reduced for less mist
        const material = new THREE.PointsMaterial({
            size: 40 + Math.random() * 60,
            vertexColors: true,
            transparent: true,
            opacity: nebulaOpacity,
            sizeAttenuation: true,
            blending: THREE.AdditiveBlending
        });

        const nebula = new THREE.Points(geometry, material);
        nebula.userData.baseOpacity = nebulaOpacity;
        gameMode.scene.add(nebula);
        gameMode.nebulae.push(nebula);
    }

    // Add bright emission nebulae (star-forming regions)
    for (let n = 0; n < 5; n++) {
        const particleCount = 1000;
        const positions = new Float32Array(particleCount * 3);
        const colors = new Float32Array(particleCount * 3);

        const nebulaX = (Math.random() - 0.5) * 150000;
        const nebulaY = (Math.random() - 0.5) * 60000;
        const nebulaZ = (Math.random() - 0.5) * 150000;
        const coreSize = 8000 + Math.random() * 15000;

        // Emission nebula colors (ionized gas)
        const emissionColors = [
            { r: 1.0, g: 0.3, b: 0.4 },  // H-alpha red
            { r: 0.3, g: 0.9, b: 1.0 },  // OIII cyan
            { r: 0.5, g: 0.7, b: 1.0 },  // Blue reflection
            { r: 1.0, g: 0.6, b: 0.8 },  // Pink hydrogen
            { r: 0.4, g: 1.0, b: 0.5 },  // Green oxygen
        ];
        const baseColor = emissionColors[Math.floor(Math.random() * emissionColors.length)];

        for (let i = 0; i < particleCount; i++) {
            const r = coreSize * Math.pow(Math.random(), 0.6);
            const theta = Math.random() * Math.PI * 2;
            const phi = Math.acos(2 * Math.random() - 1);

            // Add pillar-like structures
            const pillarEffect = Math.pow(Math.abs(Math.sin(theta * 3)), 2) * 0.5 + 0.5;

            positions[i * 3] = nebulaX + r * Math.sin(phi) * Math.cos(theta);
            positions[i * 3 + 1] = nebulaY + r * Math.sin(phi) * Math.sin(theta) * pillarEffect;
            positions[i * 3 + 2] = nebulaZ + r * Math.cos(phi);

            const brightness = 1 - (r / coreSize) * 0.4;
            colors[i * 3] = baseColor.r * brightness;
            colors[i * 3 + 1] = baseColor.g * brightness;
            colors[i * 3 + 2] = baseColor.b * brightness;
        }

        const geometry = new THREE.BufferGeometry();
        geometry.setAttribute('position', new THREE.BufferAttribute(positions, 3));
        geometry.setAttribute('color', new THREE.BufferAttribute(colors, 3));

        const material = new THREE.PointsMaterial({
            size: 25,
            vertexColors: true,
            transparent: true,
            opacity: 0.06,
            sizeAttenuation: true,
            blending: THREE.AdditiveBlending
        });

        const emissionNebula = new THREE.Points(geometry, material);
        emissionNebula.userData.baseOpacity = 0.06;
        gameMode.scene.add(emissionNebula);
        gameMode.nebulae.push(emissionNebula);
    }

    // Add dark nebulae (dust clouds that obscure background)
    for (let n = 0; n < 4; n++) {
        const particleCount = 800;
        const positions = new Float32Array(particleCount * 3);
        const colors = new Float32Array(particleCount * 3);

        const nebulaX = (Math.random() - 0.5) * 120000;
        const nebulaY = (Math.random() - 0.5) * 50000;
        const nebulaZ = (Math.random() - 0.5) * 120000;
        const cloudSize = 10000 + Math.random() * 20000;

        for (let i = 0; i < particleCount; i++) {
            const r = cloudSize * Math.pow(Math.random(), 0.5);
            const theta = Math.random() * Math.PI * 2;
            const phi = Math.acos(2 * Math.random() - 1);

            positions[i * 3] = nebulaX + r * Math.sin(phi) * Math.cos(theta);
            positions[i * 3 + 1] = nebulaY + r * Math.sin(phi) * Math.sin(theta) * 0.4;
            positions[i * 3 + 2] = nebulaZ + r * Math.cos(phi);

            // Dark brownish-red colors
            const darkness = 0.15 + Math.random() * 0.1;
            colors[i * 3] = darkness * 1.2;
            colors[i * 3 + 1] = darkness * 0.8;
            colors[i * 3 + 2] = darkness * 0.6;
        }

        const geometry = new THREE.BufferGeometry();
        geometry.setAttribute('position', new THREE.BufferAttribute(positions, 3));
        geometry.setAttribute('color', new THREE.BufferAttribute(colors, 3));

        const material = new THREE.PointsMaterial({
            size: 80,
            vertexColors: true,
            transparent: true,
            opacity: 0.08,
            sizeAttenuation: true,
            blending: THREE.NormalBlending
        });

        const darkNebula = new THREE.Points(geometry, material);
        darkNebula.userData.baseOpacity = 0.08;
        gameMode.scene.add(darkNebula);
        gameMode.nebulae.push(darkNebula);
    }
}

// Create distant galaxies
function createDistantGalaxies() {
    for (let g = 0; g < 5; g++) {
        const galaxyParticles = 500;
        const positions = new Float32Array(galaxyParticles * 3);
        const colors = new Float32Array(galaxyParticles * 3);

        const galaxyX = (Math.random() - 0.5) * 80000;
        const galaxyY = (Math.random() - 0.5) * 40000;
        const galaxyZ = -30000 - Math.random() * 30000;

        for (let i = 0; i < galaxyParticles; i++) {
            // Spiral galaxy shape
            const arm = Math.floor(Math.random() * 2);
            const distance = Math.random() * 2000;
            const angle = (distance / 300) + arm * Math.PI + (Math.random() - 0.5) * 0.5;

            positions[i * 3] = galaxyX + Math.cos(angle) * distance;
            positions[i * 3 + 1] = galaxyY + (Math.random() - 0.5) * 150;
            positions[i * 3 + 2] = galaxyZ + Math.sin(angle) * distance;

            // Galaxy colors (warm center, blue edges)
            const t = distance / 300;
            colors[i * 3] = 1 - t * 0.3;
            colors[i * 3 + 1] = 0.8 - t * 0.2;
            colors[i * 3 + 2] = 0.6 + t * 0.4;
        }

        const geometry = new THREE.BufferGeometry();
        geometry.setAttribute('position', new THREE.BufferAttribute(positions, 3));
        geometry.setAttribute('color', new THREE.BufferAttribute(colors, 3));

        const material = new THREE.PointsMaterial({
            size: 3,
            vertexColors: true,
            transparent: true,
            opacity: 0.6,
            sizeAttenuation: true,
            blending: THREE.AdditiveBlending
        });

        const galaxy = new THREE.Points(geometry, material);
        gameMode.scene.add(galaxy);
    }
}

// Create realistic starfield background with multiple layers
function createStarfield() {
    // Layer 0: Ultra-distant faint stars (creates depth)
    const ultraDistantCount = 20000;
    const ultraDistantPositions = new Float32Array(ultraDistantCount * 3);
    const ultraDistantColors = new Float32Array(ultraDistantCount * 3);

    for (let i = 0; i < ultraDistantCount; i++) {
        const radius = 90000 + Math.random() * 50000;
        const theta = Math.random() * Math.PI * 2;
        const phi = Math.acos(2 * Math.random() - 1);

        ultraDistantPositions[i * 3] = radius * Math.sin(phi) * Math.cos(theta);
        ultraDistantPositions[i * 3 + 1] = radius * Math.sin(phi) * Math.sin(theta);
        ultraDistantPositions[i * 3 + 2] = radius * Math.cos(phi);

        const brightness = 0.2 + Math.random() * 0.3;
        ultraDistantColors[i * 3] = brightness;
        ultraDistantColors[i * 3 + 1] = brightness;
        ultraDistantColors[i * 3 + 2] = brightness * 1.1;
    }

    const ultraDistantGeometry = new THREE.BufferGeometry();
    ultraDistantGeometry.setAttribute('position', new THREE.BufferAttribute(ultraDistantPositions, 3));
    ultraDistantGeometry.setAttribute('color', new THREE.BufferAttribute(ultraDistantColors, 3));

    const ultraDistantMaterial = new THREE.PointsMaterial({
        size: 1.5,
        vertexColors: true,
        transparent: true,
        opacity: 0.5,
        sizeAttenuation: true
    });

    const ultraDistantStars = new THREE.Points(ultraDistantGeometry, ultraDistantMaterial);
    gameMode.scene.add(ultraDistantStars);

    // Layer 1: Distant dim stars (most numerous)
    const distantStarCount = 15000;
    const distantPositions = new Float32Array(distantStarCount * 3);
    const distantColors = new Float32Array(distantStarCount * 3);

    for (let i = 0; i < distantStarCount; i++) {
        const radius = 50000 + Math.random() * 70000;
        const theta = Math.random() * Math.PI * 2;
        const phi = Math.acos(2 * Math.random() - 1);

        distantPositions[i * 3] = radius * Math.sin(phi) * Math.cos(theta);
        distantPositions[i * 3 + 1] = radius * Math.sin(phi) * Math.sin(theta);
        distantPositions[i * 3 + 2] = radius * Math.cos(phi);

        // Realistic stellar classification colors
        const colorChoice = Math.random();
        const brightness = 0.5 + Math.random() * 0.5;
        if (colorChoice < 0.03) {
            // O-type: Blue (rare, very hot)
            distantColors[i * 3] = 0.6 * brightness;
            distantColors[i * 3 + 1] = 0.7 * brightness;
            distantColors[i * 3 + 2] = 1.0 * brightness;
        } else if (colorChoice < 0.13) {
            // B-type: Blue-white
            distantColors[i * 3] = 0.75 * brightness;
            distantColors[i * 3 + 1] = 0.85 * brightness;
            distantColors[i * 3 + 2] = 1.0 * brightness;
        } else if (colorChoice < 0.20) {
            // A-type: White
            distantColors[i * 3] = 0.95 * brightness;
            distantColors[i * 3 + 1] = 0.95 * brightness;
            distantColors[i * 3 + 2] = 1.0 * brightness;
        } else if (colorChoice < 0.27) {
            // F-type: Yellow-white
            distantColors[i * 3] = 1.0 * brightness;
            distantColors[i * 3 + 1] = 0.95 * brightness;
            distantColors[i * 3 + 2] = 0.85 * brightness;
        } else if (colorChoice < 0.40) {
            // G-type: Yellow (sun-like)
            distantColors[i * 3] = 1.0 * brightness;
            distantColors[i * 3 + 1] = 0.92 * brightness;
            distantColors[i * 3 + 2] = 0.7 * brightness;
        } else if (colorChoice < 0.60) {
            // K-type: Orange
            distantColors[i * 3] = 1.0 * brightness;
            distantColors[i * 3 + 1] = 0.75 * brightness;
            distantColors[i * 3 + 2] = 0.5 * brightness;
        } else {
            // M-type: Red (most common)
            distantColors[i * 3] = 1.0 * brightness;
            distantColors[i * 3 + 1] = 0.6 * brightness;
            distantColors[i * 3 + 2] = 0.45 * brightness;
        }
    }

    const distantGeometry = new THREE.BufferGeometry();
    distantGeometry.setAttribute('position', new THREE.BufferAttribute(distantPositions, 3));
    distantGeometry.setAttribute('color', new THREE.BufferAttribute(distantColors, 3));

    const distantMaterial = new THREE.PointsMaterial({
        size: 3,
        vertexColors: true,
        transparent: true,
        opacity: 0.8,
        sizeAttenuation: true
    });

    const distantStars = new THREE.Points(distantGeometry, distantMaterial);
    gameMode.scene.add(distantStars);

    // Layer 2: Mid-range stars
    const midStarCount = 8000;
    const midPositions = new Float32Array(midStarCount * 3);
    const midColors = new Float32Array(midStarCount * 3);

    for (let i = 0; i < midStarCount; i++) {
        const radius = 25000 + Math.random() * 35000;
        const theta = Math.random() * Math.PI * 2;
        const phi = Math.acos(2 * Math.random() - 1);

        midPositions[i * 3] = radius * Math.sin(phi) * Math.cos(theta);
        midPositions[i * 3 + 1] = radius * Math.sin(phi) * Math.sin(theta);
        midPositions[i * 3 + 2] = radius * Math.cos(phi);

        // Slightly brighter colors
        const colorChoice = Math.random();
        if (colorChoice < 0.5) {
            midColors[i * 3] = 1; midColors[i * 3 + 1] = 1; midColors[i * 3 + 2] = 1;
        } else if (colorChoice < 0.7) {
            midColors[i * 3] = 1; midColors[i * 3 + 1] = 0.95; midColors[i * 3 + 2] = 0.8;
        } else if (colorChoice < 0.85) {
            midColors[i * 3] = 0.8; midColors[i * 3 + 1] = 0.9; midColors[i * 3 + 2] = 1;
        } else {
            midColors[i * 3] = 1; midColors[i * 3 + 1] = 0.7; midColors[i * 3 + 2] = 0.5;
        }
    }

    const midGeometry = new THREE.BufferGeometry();
    midGeometry.setAttribute('position', new THREE.BufferAttribute(midPositions, 3));
    midGeometry.setAttribute('color', new THREE.BufferAttribute(midColors, 3));

    const midMaterial = new THREE.PointsMaterial({
        size: 5,
        vertexColors: true,
        transparent: true,
        opacity: 0.9,
        sizeAttenuation: true
    });

    gameMode.stars = new THREE.Points(midGeometry, midMaterial);
    gameMode.scene.add(gameMode.stars);

    // Layer 3: Bright foreground stars
    const brightStarCount = 1500;
    const brightPositions = new Float32Array(brightStarCount * 3);
    const brightColors = new Float32Array(brightStarCount * 3);

    for (let i = 0; i < brightStarCount; i++) {
        const radius = 12000 + Math.random() * 20000;
        const theta = Math.random() * Math.PI * 2;
        const phi = Math.acos(2 * Math.random() - 1);

        brightPositions[i * 3] = radius * Math.sin(phi) * Math.cos(theta);
        brightPositions[i * 3 + 1] = radius * Math.sin(phi) * Math.sin(theta);
        brightPositions[i * 3 + 2] = radius * Math.cos(phi);

        // Bright star colors
        const colorChoice = Math.random();
        if (colorChoice < 0.4) {
            brightColors[i * 3] = 1; brightColors[i * 3 + 1] = 1; brightColors[i * 3 + 2] = 1;
        } else if (colorChoice < 0.6) {
            brightColors[i * 3] = 0.85; brightColors[i * 3 + 1] = 0.92; brightColors[i * 3 + 2] = 1;
        } else if (colorChoice < 0.8) {
            brightColors[i * 3] = 1; brightColors[i * 3 + 1] = 0.98; brightColors[i * 3 + 2] = 0.85;
        } else {
            brightColors[i * 3] = 1; brightColors[i * 3 + 1] = 0.8; brightColors[i * 3 + 2] = 0.6;
        }
    }

    const brightGeometry = new THREE.BufferGeometry();
    brightGeometry.setAttribute('position', new THREE.BufferAttribute(brightPositions, 3));
    brightGeometry.setAttribute('color', new THREE.BufferAttribute(brightColors, 3));

    const brightMaterial = new THREE.PointsMaterial({
        size: 10,
        vertexColors: true,
        transparent: true,
        opacity: 1,
        sizeAttenuation: true,
        blending: THREE.AdditiveBlending
    });

    const brightStars = new THREE.Points(brightGeometry, brightMaterial);
    gameMode.scene.add(brightStars);
    gameMode.brightStars = brightStars;

    // Layer 4: Very bright "named" stars (like Sirius, Vega) with glow
    const superBrightCount = 150;
    const superBrightPositions = new Float32Array(superBrightCount * 3);
    const superBrightColors = new Float32Array(superBrightCount * 3);

    for (let i = 0; i < superBrightCount; i++) {
        const radius = 15000 + Math.random() * 35000;
        const theta = Math.random() * Math.PI * 2;
        const phi = Math.acos(2 * Math.random() - 1);

        superBrightPositions[i * 3] = radius * Math.sin(phi) * Math.cos(theta);
        superBrightPositions[i * 3 + 1] = radius * Math.sin(phi) * Math.sin(theta);
        superBrightPositions[i * 3 + 2] = radius * Math.cos(phi);

        // Give super bright stars slight color variation
        const colorVar = Math.random();
        if (colorVar < 0.4) {
            superBrightColors[i * 3] = 1;
            superBrightColors[i * 3 + 1] = 1;
            superBrightColors[i * 3 + 2] = 1;
        } else if (colorVar < 0.6) {
            superBrightColors[i * 3] = 0.9;
            superBrightColors[i * 3 + 1] = 0.95;
            superBrightColors[i * 3 + 2] = 1;
        } else if (colorVar < 0.8) {
            superBrightColors[i * 3] = 1;
            superBrightColors[i * 3 + 1] = 0.95;
            superBrightColors[i * 3 + 2] = 0.85;
        } else {
            superBrightColors[i * 3] = 1;
            superBrightColors[i * 3 + 1] = 0.85;
            superBrightColors[i * 3 + 2] = 0.7;
        }
    }

    const superBrightGeometry = new THREE.BufferGeometry();
    superBrightGeometry.setAttribute('position', new THREE.BufferAttribute(superBrightPositions, 3));
    superBrightGeometry.setAttribute('color', new THREE.BufferAttribute(superBrightColors, 3));

    const superBrightMaterial = new THREE.PointsMaterial({
        size: 20,
        vertexColors: true,
        transparent: true,
        opacity: 1,
        sizeAttenuation: true,
        blending: THREE.AdditiveBlending
    });

    const superBrightStars = new THREE.Points(superBrightGeometry, superBrightMaterial);
    gameMode.scene.add(superBrightStars);
    gameMode.superBrightStars = superBrightStars;

    // Store original sizes for twinkling animation
    gameMode.starTwinkleData = {
        brightStars: {
            material: brightMaterial,
            baseSize: 10,
            positions: brightPositions,
            phases: new Float32Array(brightStarCount).map(() => Math.random() * Math.PI * 2)
        },
        superBright: {
            material: superBrightMaterial,
            baseSize: 20,
            positions: superBrightPositions,
            phases: new Float32Array(superBrightCount).map(() => Math.random() * Math.PI * 2)
        }
    };
}

// Create the galactic plane (Milky Way band)
function createGalacticPlane() {
    const particleCount = 12000;
    const positions = new Float32Array(particleCount * 3);
    const colors = new Float32Array(particleCount * 3);

    for (let i = 0; i < particleCount; i++) {
        // Create a band across the sky
        const distance = 40000 + Math.random() * 60000;
        const angle = Math.random() * Math.PI * 2;

        // Flatten into a disk/band shape
        const bandWidth = 8000 + Math.random() * 12000;
        const heightVariation = (Math.random() - 0.5) * bandWidth * 0.3;

        positions[i * 3] = Math.cos(angle) * distance;
        positions[i * 3 + 1] = heightVariation;
        positions[i * 3 + 2] = Math.sin(angle) * distance;

        // Milky way colors - mostly dim white/cream with some variation
        const brightness = 0.3 + Math.random() * 0.5;
        const colorVar = Math.random();
        if (colorVar < 0.7) {
            // Cream/white
            colors[i * 3] = brightness;
            colors[i * 3 + 1] = brightness * 0.95;
            colors[i * 3 + 2] = brightness * 0.85;
        } else if (colorVar < 0.85) {
            // Slight blue tint (young stars)
            colors[i * 3] = brightness * 0.85;
            colors[i * 3 + 1] = brightness * 0.9;
            colors[i * 3 + 2] = brightness;
        } else {
            // Slight red/orange (old stars)
            colors[i * 3] = brightness;
            colors[i * 3 + 1] = brightness * 0.7;
            colors[i * 3 + 2] = brightness * 0.5;
        }
    }

    const geometry = new THREE.BufferGeometry();
    geometry.setAttribute('position', new THREE.BufferAttribute(positions, 3));
    geometry.setAttribute('color', new THREE.BufferAttribute(colors, 3));

    const material = new THREE.PointsMaterial({
        size: 8,
        vertexColors: true,
        transparent: true,
        opacity: 0.25,
        sizeAttenuation: true,
        blending: THREE.AdditiveBlending
    });

    const galacticPlane = new THREE.Points(geometry, material);
    galacticPlane.rotation.x = Math.PI * 0.15; // Tilt the band
    galacticPlane.rotation.z = Math.PI * 0.1;
    gameMode.scene.add(galacticPlane);

    // Add denser core region
    const coreCount = 5000;
    const corePositions = new Float32Array(coreCount * 3);
    const coreColors = new Float32Array(coreCount * 3);

    for (let i = 0; i < coreCount; i++) {
        const distance = 50000 + Math.random() * 30000;
        const angle = (Math.random() - 0.5) * 0.8; // Concentrated in one direction
        const spread = (Math.random() - 0.5) * 15000;

        corePositions[i * 3] = Math.cos(angle) * distance + spread * 0.3;
        corePositions[i * 3 + 1] = (Math.random() - 0.5) * 5000;
        corePositions[i * 3 + 2] = Math.sin(angle) * distance + spread;

        const brightness = 0.4 + Math.random() * 0.4;
        coreColors[i * 3] = brightness;
        coreColors[i * 3 + 1] = brightness * 0.9;
        coreColors[i * 3 + 2] = brightness * 0.75;
    }

    const coreGeometry = new THREE.BufferGeometry();
    coreGeometry.setAttribute('position', new THREE.BufferAttribute(corePositions, 3));
    coreGeometry.setAttribute('color', new THREE.BufferAttribute(coreColors, 3));

    const coreMaterial = new THREE.PointsMaterial({
        size: 10,
        vertexColors: true,
        transparent: true,
        opacity: 0.35,
        sizeAttenuation: true,
        blending: THREE.AdditiveBlending
    });

    const galacticCore = new THREE.Points(coreGeometry, coreMaterial);
    galacticCore.rotation.x = Math.PI * 0.15;
    galacticCore.rotation.z = Math.PI * 0.1;
    gameMode.scene.add(galacticCore);
}

// Create cosmic dust clouds and floating debris
function createCosmicDust() {
    // Vast dust lanes spanning the scene
    for (let d = 0; d < 6; d++) {
        const dustCount = 1500;
        const positions = new Float32Array(dustCount * 3);
        const colors = new Float32Array(dustCount * 3);

        const centerX = (Math.random() - 0.5) * 160000;
        const centerY = (Math.random() - 0.5) * 40000;
        const centerZ = (Math.random() - 0.5) * 160000;
        const cloudSize = 15000 + Math.random() * 25000;

        for (let i = 0; i < dustCount; i++) {
            const r = cloudSize * Math.pow(Math.random(), 0.6);
            const theta = Math.random() * Math.PI * 2;
            const phi = Math.acos(2 * Math.random() - 1);

            // Create streaky, filament-like structures
            const streakFactor = Math.sin(theta * 5) * 0.5 + 1;

            positions[i * 3] = centerX + r * Math.sin(phi) * Math.cos(theta) * streakFactor;
            positions[i * 3 + 1] = centerY + r * Math.sin(phi) * Math.sin(theta) * 0.25;
            positions[i * 3 + 2] = centerZ + r * Math.cos(phi) * streakFactor;

            // Varied dust colors - some darker, some with slight tint
            const dustType = Math.random();
            if (dustType < 0.6) {
                // Dark brown dust
                const darkness = 0.08 + Math.random() * 0.12;
                colors[i * 3] = darkness * 1.1;
                colors[i * 3 + 1] = darkness * 0.9;
                colors[i * 3 + 2] = darkness * 0.7;
            } else if (dustType < 0.8) {
                // Reddish dust
                const darkness = 0.1 + Math.random() * 0.1;
                colors[i * 3] = darkness * 1.5;
                colors[i * 3 + 1] = darkness * 0.6;
                colors[i * 3 + 2] = darkness * 0.4;
            } else {
                // Slight blue reflection dust
                const darkness = 0.05 + Math.random() * 0.08;
                colors[i * 3] = darkness * 0.8;
                colors[i * 3 + 1] = darkness * 0.9;
                colors[i * 3 + 2] = darkness * 1.2;
            }
        }

        const geometry = new THREE.BufferGeometry();
        geometry.setAttribute('position', new THREE.BufferAttribute(positions, 3));
        geometry.setAttribute('color', new THREE.BufferAttribute(colors, 3));

        const material = new THREE.PointsMaterial({
            size: 100 + Math.random() * 50,
            vertexColors: true,
            transparent: true,
            opacity: 0.12 + Math.random() * 0.08,
            sizeAttenuation: true
        });

        const dustCloud = new THREE.Points(geometry, material);
        gameMode.scene.add(dustCloud);
    }

    // Add floating ice/debris particles throughout the system
    const debrisCount = 5000;
    const debrisPositions = new Float32Array(debrisCount * 3);
    const debrisColors = new Float32Array(debrisCount * 3);

    for (let i = 0; i < debrisCount; i++) {
        const radius = 3000 + Math.random() * 100000;
        const theta = Math.random() * Math.PI * 2;
        const phi = Math.acos(2 * Math.random() - 1);

        debrisPositions[i * 3] = radius * Math.sin(phi) * Math.cos(theta);
        debrisPositions[i * 3 + 1] = (Math.random() - 0.5) * 20000;
        debrisPositions[i * 3 + 2] = radius * Math.cos(phi);

        // Icy/metallic debris colors
        const type = Math.random();
        if (type < 0.5) {
            // Ice
            debrisColors[i * 3] = 0.7 + Math.random() * 0.3;
            debrisColors[i * 3 + 1] = 0.8 + Math.random() * 0.2;
            debrisColors[i * 3 + 2] = 0.9 + Math.random() * 0.1;
        } else {
            // Rock/metal
            const gray = 0.3 + Math.random() * 0.3;
            debrisColors[i * 3] = gray;
            debrisColors[i * 3 + 1] = gray * 0.9;
            debrisColors[i * 3 + 2] = gray * 0.8;
        }
    }

    const debrisGeometry = new THREE.BufferGeometry();
    debrisGeometry.setAttribute('position', new THREE.BufferAttribute(debrisPositions, 3));
    debrisGeometry.setAttribute('color', new THREE.BufferAttribute(debrisColors, 3));

    const debrisMaterial = new THREE.PointsMaterial({
        size: 8,
        vertexColors: true,
        transparent: true,
        opacity: 0.6,
        sizeAttenuation: true,
        blending: THREE.AdditiveBlending
    });

    const debris = new THREE.Points(debrisGeometry, debrisMaterial);
    gameMode.scene.add(debris);
    gameMode.floatingDebris = debris;
}

// Create asteroid belt - scaled for massive solar system with huge sun
function createAsteroidBelt() {
    const asteroidCount = 3000;

    // Main belt between inner and outer planets - much larger
    const beltRadius = 60000;  // Further out to match new orbital spacing
    const beltWidth = 15000;

    for (let i = 0; i < asteroidCount; i++) {
        const angle = Math.random() * Math.PI * 2;
        const radius = beltRadius + (Math.random() - 0.5) * beltWidth;
        const height = (Math.random() - 0.5) * 2000;

        // Larger asteroids for the scaled scene
        const size = 10 + Math.random() * 60;
        const geometry = new THREE.IcosahedronGeometry(size, 0);

        // Randomize vertices for irregular shape
        const positions = geometry.attributes.position;
        for (let v = 0; v < positions.count; v++) {
            positions.setX(v, positions.getX(v) * (0.6 + Math.random() * 0.8));
            positions.setY(v, positions.getY(v) * (0.6 + Math.random() * 0.8));
            positions.setZ(v, positions.getZ(v) * (0.6 + Math.random() * 0.8));
        }
        geometry.computeVertexNormals();

        // More varied asteroid colors
        const asteroidType = Math.random();
        let color, emissive;
        if (asteroidType < 0.4) {
            // C-type (carbonaceous) - dark
            color = 0x333333 + Math.floor(Math.random() * 0x111111);
            emissive = 0x080808;
        } else if (asteroidType < 0.7) {
            // S-type (siliceous) - lighter, reddish
            color = 0x665544 + Math.floor(Math.random() * 0x222211);
            emissive = 0x110808;
        } else {
            // M-type (metallic) - grayish with shine
            color = 0x888888 + Math.floor(Math.random() * 0x222222);
            emissive = 0x111111;
        }

        const material = new THREE.MeshPhongMaterial({
            color: color,
            emissive: emissive,
            emissiveIntensity: 0.15,
            flatShading: true,
            shininess: asteroidType > 0.7 ? 30 : 5
        });

        const asteroid = new THREE.Mesh(geometry, material);
        asteroid.position.set(
            Math.cos(angle) * radius,
            height,
            Math.sin(angle) * radius
        );
        asteroid.rotation.set(
            Math.random() * Math.PI,
            Math.random() * Math.PI,
            Math.random() * Math.PI
        );

        // Store orbit data for animation
        asteroid.userData.orbitAngle = angle;
        asteroid.userData.orbitRadius = radius;
        asteroid.userData.orbitSpeed = 0.00005 + Math.random() * 0.0001;
        asteroid.userData.rotationSpeed = {
            x: (Math.random() - 0.5) * 0.01,
            y: (Math.random() - 0.5) * 0.01,
            z: (Math.random() - 0.5) * 0.01
        };
        asteroid.userData.isAsteroid = true;

        gameMode.scene.add(asteroid);
    }
}

// Create ambient space dust particles near camera
function createAmbientDust() {
    const dustCount = 1000;
    const positions = new Float32Array(dustCount * 3);
    const colors = new Float32Array(dustCount * 3);

    for (let i = 0; i < dustCount; i++) {
        // Distribute around camera starting position
        positions[i * 3] = (Math.random() - 0.5) * 5000;
        positions[i * 3 + 1] = (Math.random() - 0.5) * 3000 + 500;
        positions[i * 3 + 2] = (Math.random() - 0.5) * 5000 + 2000;

        const brightness = 0.3 + Math.random() * 0.4;
        colors[i * 3] = brightness;
        colors[i * 3 + 1] = brightness;
        colors[i * 3 + 2] = brightness;
    }

    const geometry = new THREE.BufferGeometry();
    geometry.setAttribute('position', new THREE.BufferAttribute(positions, 3));
    geometry.setAttribute('color', new THREE.BufferAttribute(colors, 3));

    const material = new THREE.PointsMaterial({
        size: 1.5,
        vertexColors: true,
        transparent: true,
        opacity: 0.3,
        sizeAttenuation: true
    });

    gameMode.ambientDust = new THREE.Points(geometry, material);
    gameMode.scene.add(gameMode.ambientDust);
}

// Create a shooting star effect
function createShootingStar() {
    if (gameMode.shootingStar) return;

    // Random starting position in the sky
    const camPos = gameMode.camera.position;
    const startDistance = 8000 + Math.random() * 15000;
    const startTheta = Math.random() * Math.PI * 2;
    const startPhi = Math.PI * 0.1 + Math.random() * Math.PI * 0.4; // Upper hemisphere

    const startPos = new THREE.Vector3(
        camPos.x + startDistance * Math.sin(startPhi) * Math.cos(startTheta),
        camPos.y + startDistance * Math.cos(startPhi),
        camPos.z + startDistance * Math.sin(startPhi) * Math.sin(startTheta)
    );

    // Direction of travel (downward and across)
    const direction = new THREE.Vector3(
        (Math.random() - 0.5) * 2,
        -0.8 - Math.random() * 0.4,
        (Math.random() - 0.5) * 2
    ).normalize();

    // Create the shooting star trail
    const trailLength = 20;
    const positions = new Float32Array(trailLength * 3);
    const colors = new Float32Array(trailLength * 3);

    for (let i = 0; i < trailLength; i++) {
        const t = i / trailLength;
        positions[i * 3] = startPos.x - direction.x * i * 50;
        positions[i * 3 + 1] = startPos.y - direction.y * i * 50;
        positions[i * 3 + 2] = startPos.z - direction.z * i * 50;

        // Fade from white to blue
        const brightness = 1 - t * 0.8;
        colors[i * 3] = brightness;
        colors[i * 3 + 1] = brightness;
        colors[i * 3 + 2] = brightness * 1.2;
    }

    const geometry = new THREE.BufferGeometry();
    geometry.setAttribute('position', new THREE.BufferAttribute(positions, 3));
    geometry.setAttribute('color', new THREE.BufferAttribute(colors, 3));

    const material = new THREE.PointsMaterial({
        size: 15,
        vertexColors: true,
        transparent: true,
        opacity: 1,
        sizeAttenuation: true,
        blending: THREE.AdditiveBlending
    });

    const shootingStar = new THREE.Points(geometry, material);
    gameMode.scene.add(shootingStar);

    gameMode.shootingStar = {
        mesh: shootingStar,
        direction: direction,
        speed: 150 + Math.random() * 100,
        life: 0,
        maxLife: 80 + Math.random() * 40
    };
}

// Update shooting star position
function updateShootingStar() {
    if (!gameMode.shootingStar) return;

    const star = gameMode.shootingStar;
    star.life++;

    // Move the shooting star
    const positions = star.mesh.geometry.attributes.position.array;
    for (let i = 0; i < positions.length / 3; i++) {
        positions[i * 3] += star.direction.x * star.speed;
        positions[i * 3 + 1] += star.direction.y * star.speed;
        positions[i * 3 + 2] += star.direction.z * star.speed;
    }
    star.mesh.geometry.attributes.position.needsUpdate = true;

    // Fade out near end of life
    const fadeStart = star.maxLife * 0.6;
    if (star.life > fadeStart) {
        const fadeProgress = (star.life - fadeStart) / (star.maxLife - fadeStart);
        star.mesh.material.opacity = 1 - fadeProgress;
    }

    // Remove when dead
    if (star.life >= star.maxLife) {
        gameMode.scene.remove(star.mesh);
        star.mesh.geometry.dispose();
        star.mesh.material.dispose();
        gameMode.shootingStar = null;
    }
}

// Initialize speed lines for motion effect
function initSpeedLines() {
    const speedLinesContainer = document.getElementById('speedLines');
    speedLinesContainer.innerHTML = '';

    // Create 30 speed lines
    for (let i = 0; i < 30; i++) {
        const line = document.createElement('div');
        line.className = 'speed-line';
        line.style.left = Math.random() * 100 + '%';
        line.style.top = Math.random() * 100 + '%';
        line.style.animationDelay = Math.random() * 0.3 + 's';
        speedLinesContainer.appendChild(line);
    }
}

// Create central sun
function createSun() {
    // Sun geometry - MASSIVE central star (10x bigger)
    const sunGeometry = new THREE.SphereGeometry(8000, 64, 64);
    const sunMaterial = new THREE.MeshBasicMaterial({
        color: 0xffaa00,
        transparent: true,
        opacity: 0.95
    });
    const sun = new THREE.Mesh(sunGeometry, sunMaterial);
    sun.position.set(0, 0, 0);
    gameMode.scene.add(sun);

    // Sun corona (outer glow)
    const coronaGeometry = new THREE.SphereGeometry(12000, 64, 64);
    const coronaMaterial = new THREE.MeshBasicMaterial({
        color: 0xff6600,
        transparent: true,
        opacity: 0.25,
        side: THREE.BackSide
    });
    const corona = new THREE.Mesh(coronaGeometry, coronaMaterial);
    corona.position.set(0, 0, 0);
    gameMode.scene.add(corona);

    // Inner glow
    const glowGeometry = new THREE.SphereGeometry(9500, 64, 64);
    const glowMaterial = new THREE.MeshBasicMaterial({
        color: 0xffcc44,
        transparent: true,
        opacity: 0.18,
        side: THREE.BackSide
    });
    const glow = new THREE.Mesh(glowGeometry, glowMaterial);
    glow.position.set(0, 0, 0);
    gameMode.scene.add(glow);

    // Outer halo
    const haloGeometry = new THREE.SphereGeometry(15000, 32, 32);
    const haloMaterial = new THREE.MeshBasicMaterial({
        color: 0xffdd88,
        transparent: true,
        opacity: 0.08,
        side: THREE.BackSide
    });
    const halo = new THREE.Mesh(haloGeometry, haloMaterial);
    halo.position.set(0, 0, 0);
    gameMode.scene.add(halo);

    // Solar flare particles around the sun
    const flareCount = 5000;
    const flarePositions = new Float32Array(flareCount * 3);
    const flareColors = new Float32Array(flareCount * 3);

    for (let i = 0; i < flareCount; i++) {
        const radius = 8000 + Math.random() * 6000;
        const theta = Math.random() * Math.PI * 2;
        const phi = Math.acos(2 * Math.random() - 1);

        flarePositions[i * 3] = radius * Math.sin(phi) * Math.cos(theta);
        flarePositions[i * 3 + 1] = radius * Math.sin(phi) * Math.sin(theta);
        flarePositions[i * 3 + 2] = radius * Math.cos(phi);

        // Yellow-orange-white colors
        const heat = Math.random();
        flareColors[i * 3] = 1;
        flareColors[i * 3 + 1] = 0.5 + heat * 0.5;
        flareColors[i * 3 + 2] = heat * 0.5;
    }

    const flareGeometry = new THREE.BufferGeometry();
    flareGeometry.setAttribute('position', new THREE.BufferAttribute(flarePositions, 3));
    flareGeometry.setAttribute('color', new THREE.BufferAttribute(flareColors, 3));

    const flareMaterial = new THREE.PointsMaterial({
        size: 80,
        vertexColors: true,
        transparent: true,
        opacity: 0.6,
        blending: THREE.AdditiveBlending
    });

    const flares = new THREE.Points(flareGeometry, flareMaterial);
    gameMode.scene.add(flares);
    gameMode.sunFlares = flares;

    // Point light from sun - intense light flooding the vast system
    const sunLight = new THREE.PointLight(0xffdd66, 10, 300000);
    sunLight.position.set(0, 0, 0);
    gameMode.scene.add(sunLight);

    // Secondary warm light for fill
    const sunLight2 = new THREE.PointLight(0xffaa33, 5, 200000);
    sunLight2.position.set(0, 0, 0);
    gameMode.scene.add(sunLight2);

    // Add hemisphere light for overall illumination
    const hemiLight = new THREE.HemisphereLight(0xffffcc, 0x222244, 1.5);
    gameMode.scene.add(hemiLight);
}

// Planet type configurations for variety
const PLANET_TYPES = [
    { name: 'terrestrial', colors: [0x4488aa, 0x448866, 0x886644], hasAtmosphere: true, atmosphereColor: 0x88ccff },
    { name: 'gas_giant', colors: [0xddaa66, 0xcc8844, 0xbb9955], hasAtmosphere: true, atmosphereColor: 0xffddaa, hasRings: true },
    { name: 'ice_giant', colors: [0x66aacc, 0x5599bb, 0x4488aa], hasAtmosphere: true, atmosphereColor: 0xaaddff },
    { name: 'desert', colors: [0xcc9966, 0xbb8855, 0xaa7744], hasAtmosphere: true, atmosphereColor: 0xffccaa },
    { name: 'volcanic', colors: [0x884422, 0x662211, 0x993322], hasAtmosphere: true, atmosphereColor: 0xff6644 },
    { name: 'ocean', colors: [0x2266aa, 0x3377bb, 0x1155aa], hasAtmosphere: true, atmosphereColor: 0x66aaff },
    { name: 'barren', colors: [0x666666, 0x555555, 0x777777], hasAtmosphere: false },
    { name: 'toxic', colors: [0x668844, 0x557733, 0x779955], hasAtmosphere: true, atmosphereColor: 0xaaff66 },
];

// Create spherical nodes from network data as realistic planets
function createNodeSpheres() {
    // Get current nodes from vis.js BEFORE clearing existing ones
    const allNodes = nodes.get();
    if (allNodes.length === 0) return;  // Don't clear if no new nodes to display

    // Clear existing nodes
    gameMode.nodeMeshes.forEach(mesh => {
        // Remove all children (atmosphere, rings, moons)
        while (mesh.children.length > 0) {
            const child = mesh.children[0];
            mesh.remove(child);
            if (child.geometry) child.geometry.dispose();
            if (child.material) child.material.dispose();
        }
        gameMode.scene.remove(mesh);
        // Only dispose geometry/material if they exist (Groups don't have them)
        if (mesh.geometry) mesh.geometry.dispose();
        if (mesh.material) mesh.material.dispose();
    });
    gameMode.nodeMeshes = [];
    gameMode.nodeDataMap.clear();
    gameMode.nodeIdToMesh.clear();

    // Position nodes in orbital rings around the sun
    const nodeCount = allNodes.length;
    const rings = Math.ceil(Math.sqrt(nodeCount));

    allNodes.forEach((node, index) => {
        // Determine ring and position within ring
        const ring = Math.floor(index / Math.max(1, Math.ceil(nodeCount / rings)));
        const positionInRing = index % Math.max(1, Math.ceil(nodeCount / rings));
        const nodesInRing = Math.ceil(nodeCount / rings);

        // Calculate orbital position - vast solar system with huge sun
        const orbitRadius = 25000 + ring * 25000;  // Start further out, more spacing
        const angle = (positionInRing / nodesInRing) * Math.PI * 2 + ring * 0.5;
        const verticalOffset = (seededRandom(node.id, 'voff') - 0.5) * 8000;
        const orbitTilt = (seededRandom(node.id, 'tilt') - 0.5) * 0.4; // Slight orbital plane tilt

        // Size based on packet count - MASSIVE planets (10x original)
        const packetCount = extractPacketCount(node.title) || 1;
        const baseSize = 1500;  // Minimum planet size
        const maxSize = 6000;   // Maximum planet size
        const size = Math.min(maxSize, baseSize + Math.log10(packetCount + 1) * 1200);

        // Select planet type based on hash of node ID for consistency
        const planetTypeIndex = hashCode(node.id) % PLANET_TYPES.length;
        const planetType = PLANET_TYPES[Math.abs(planetTypeIndex)];

        // Create planet group
        const planetGroup = new THREE.Group();

        // Main planet body with high detail
        const geometry = new THREE.SphereGeometry(size, 64, 64);
        const baseColor = planetType.colors[Math.abs(hashCode(node.id + 'color')) % planetType.colors.length];

        // Create procedural surface variation
        const material = new THREE.MeshPhongMaterial({
            color: baseColor,
            emissive: baseColor,
            emissiveIntensity: 0.12,
            shininess: 40,
            transparent: false
        });

        const planet = new THREE.Mesh(geometry, material);
        planet.rotation.x = seededRandom(node.id, 'rotx') * 0.5;
        planet.rotation.z = seededRandom(node.id, 'rotz') * 0.3;
        planetGroup.add(planet);

        // Add surface features layer (continents/storms/terrain)
        const featureGeometry = new THREE.SphereGeometry(size * 1.002, 64, 64);
        const featureColor = new THREE.Color(baseColor).offsetHSL(0.05, 0.1, 0.15);
        const featureMaterial = new THREE.MeshPhongMaterial({
            color: featureColor,
            emissive: featureColor,
            emissiveIntensity: 0.08,
            transparent: true,
            opacity: 0.6,
            blending: THREE.AdditiveBlending
        });
        const features = new THREE.Mesh(featureGeometry, featureMaterial);
        features.rotation.y = seededRandom(node.id, 'feat') * Math.PI;
        planetGroup.add(features);

        // Add cloud layer for atmospheric planets
        if (planetType.hasAtmosphere && seededRandom(node.id, 'cloud') > 0.3) {
            const cloudGeometry = new THREE.SphereGeometry(size * 1.02, 48, 48);
            const cloudMaterial = new THREE.MeshPhongMaterial({
                color: 0xffffff,
                emissive: 0x222222,
                transparent: true,
                opacity: 0.25,
                blending: THREE.NormalBlending
            });
            const clouds = new THREE.Mesh(cloudGeometry, cloudMaterial);
            clouds.userData.rotationSpeed = 0.0002 + seededRandom(node.id, 'cloudspd') * 0.0003;
            planetGroup.add(clouds);
        }

        // Add polar ice caps for terrestrial planets
        if (planetType.name === 'terrestrial' || planetType.name === 'ocean') {
            const capSize = size * 0.25;
            const northCapGeometry = new THREE.SphereGeometry(capSize, 32, 16, 0, Math.PI * 2, 0, Math.PI * 0.3);
            const capMaterial = new THREE.MeshPhongMaterial({
                color: 0xeeffff,
                emissive: 0x446688,
                emissiveIntensity: 0.2,
                transparent: true,
                opacity: 0.8
            });
            const northCap = new THREE.Mesh(northCapGeometry, capMaterial);
            northCap.position.y = size * 0.92;
            planetGroup.add(northCap);

            const southCap = new THREE.Mesh(northCapGeometry, capMaterial);
            southCap.position.y = -size * 0.92;
            southCap.rotation.x = Math.PI;
            planetGroup.add(southCap);
        }

        // Add storm bands for gas giants
        if (planetType.name === 'gas_giant') {
            for (let b = 0; b < 5; b++) {
                const bandGeometry = new THREE.TorusGeometry(size * (0.7 + b * 0.12), size * 0.02, 8, 64);
                const bandColor = new THREE.Color(baseColor).offsetHSL(b * 0.02, -0.1, b % 2 === 0 ? 0.1 : -0.1);
                const bandMaterial = new THREE.MeshBasicMaterial({
                    color: bandColor,
                    transparent: true,
                    opacity: 0.4
                });
                const band = new THREE.Mesh(bandGeometry, bandMaterial);
                band.rotation.x = Math.PI / 2;
                band.position.y = size * (0.6 - b * 0.25);
                planetGroup.add(band);
            }

            // Great storm spot
            if (seededRandom(node.id, 'storm') > 0.5) {
                const stormGeometry = new THREE.SphereGeometry(size * 0.15, 32, 32);
                const stormMaterial = new THREE.MeshBasicMaterial({
                    color: 0xff6644,
                    transparent: true,
                    opacity: 0.7
                });
                const storm = new THREE.Mesh(stormGeometry, stormMaterial);
                storm.position.set(size * 0.8, size * 0.2, size * 0.4);
                planetGroup.add(storm);
            }
        }

        // Add volcanic activity for volcanic planets
        if (planetType.name === 'volcanic') {
            for (let v = 0; v < 8; v++) {
                const volcanoGlow = new THREE.PointLight(0xff4400, 0.5, size * 0.8);
                const theta = seededRandom(node.id, 'vtheta' + v) * Math.PI * 2;
                const phi = seededRandom(node.id, 'vphi' + v) * Math.PI;
                volcanoGlow.position.set(
                    size * Math.sin(phi) * Math.cos(theta),
                    size * Math.cos(phi),
                    size * Math.sin(phi) * Math.sin(theta)
                );
                planetGroup.add(volcanoGlow);
            }
        }

        // Add atmosphere glow
        if (planetType.hasAtmosphere) {
            const atmosphereGeometry = new THREE.SphereGeometry(size * 1.15, 32, 32);
            const atmosphereMaterial = new THREE.MeshBasicMaterial({
                color: planetType.atmosphereColor,
                transparent: true,
                opacity: 0.15,
                side: THREE.BackSide
            });
            const atmosphere = new THREE.Mesh(atmosphereGeometry, atmosphereMaterial);
            planetGroup.add(atmosphere);

            // Inner glow
            const innerGlowGeometry = new THREE.SphereGeometry(size * 1.05, 32, 32);
            const innerGlowMaterial = new THREE.MeshBasicMaterial({
                color: planetType.atmosphereColor,
                transparent: true,
                opacity: 0.08,
                side: THREE.FrontSide
            });
            const innerGlow = new THREE.Mesh(innerGlowGeometry, innerGlowMaterial);
            planetGroup.add(innerGlow);
        }

        // Add rings to some planets (gas giants or random chance)
        const hasRings = planetType.hasRings || (size > 1500 && seededRandom(node.id, 'rings') > 0.5);
        if (hasRings) {
            const ringInnerRadius = size * 1.4;
            const ringOuterRadius = size * 2.2;
            const ringGeometry = new THREE.RingGeometry(ringInnerRadius, ringOuterRadius, 64);
            const ringMaterial = new THREE.MeshBasicMaterial({
                color: 0xccbb99,
                transparent: true,
                opacity: 0.4,
                side: THREE.DoubleSide
            });
            const rings = new THREE.Mesh(ringGeometry, ringMaterial);
            rings.rotation.x = Math.PI / 2 + (seededRandom(node.id, 'ringtilt') - 0.5) * 0.3;
            planetGroup.add(rings);
        }

        // Add moons to larger planets
        if (size > 200 && seededRandom(node.id, 'hasmoon') > 0.4) {
            const moonCount = Math.floor(seededRandom(node.id, 'moonct') * 4) + 1;
            for (let m = 0; m < moonCount; m++) {
                const moonSize = size * (0.08 + seededRandom(node.id, 'moonsz' + m) * 0.12);
                const moonDistance = size * (1.4 + m * 0.5 + seededRandom(node.id, 'moondst' + m) * 0.3);
                const moonGeometry = new THREE.SphereGeometry(moonSize, 24, 24);
                const moonMaterial = new THREE.MeshPhongMaterial({
                    color: 0x999999,
                    emissive: 0x333333,
                    emissiveIntensity: 0.15
                });
                const moon = new THREE.Mesh(moonGeometry, moonMaterial);
                moon.userData.moonOrbitRadius = moonDistance;
                moon.userData.moonOrbitSpeed = 0.008 + seededRandom(node.id, 'moonspd' + m) * 0.012;
                // Spread moons evenly around planet, plus small random offset
                const baseAngle = (m / moonCount) * Math.PI * 2;
                const randomOffset = (seededRandom(node.id, 'moonang' + m) - 0.5) * 0.5;
                moon.userData.moonOrbitAngle = baseAngle + randomOffset;
                // Position moon using its orbit angle
                moon.position.set(
                    Math.cos(moon.userData.moonOrbitAngle) * moonDistance,
                    0,
                    Math.sin(moon.userData.moonOrbitAngle) * moonDistance
                );
                planetGroup.add(moon);
            }
        }

        // Position the planet group
        planetGroup.position.set(
            Math.cos(angle) * orbitRadius,
            verticalOffset + Math.sin(angle * 2) * orbitTilt * orbitRadius,
            Math.sin(angle) * orbitRadius
        );

        // Store node data
        gameMode.nodeDataMap.set(planetGroup.uuid, {
            id: node.id,
            label: node.label,
            title: node.title,
            packetCount: packetCount,
            orbitRadius: orbitRadius,
            orbitAngle: angle,
            orbitTilt: orbitTilt,
            orbitSpeed: 0.0003 + seededRandom(node.id, 'orbspd') * 0.0008,
            rotationSpeed: 0.005 + seededRandom(node.id, 'rotspd') * 0.01,
            planetType: planetType.name,
            size: size
        });

        gameMode.scene.add(planetGroup);
        gameMode.nodeMeshes.push(planetGroup);
        gameMode.nodeIdToMesh.set(node.id, planetGroup);
    });
}

// Simple hash function for consistent planet types
function hashCode(str) {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
        const char = str.charCodeAt(i);
        hash = ((hash << 5) - hash) + char;
        hash = hash & hash;
    }
    return hash;
}

// Seeded random function for deterministic "random" values based on node ID
function seededRandom(nodeId, seed) {
    const hash = hashCode(nodeId + seed);
    // Convert hash to 0-1 range
    return (Math.abs(hash) % 10000) / 10000;
}

// Create space elevators between connected planets
function createSpaceElevators() {
    // Clear existing elevators
    gameMode.spaceElevators.forEach(elevator => {
        if (elevator.line) {
            gameMode.scene.remove(elevator.line);
            elevator.line.geometry.dispose();
            elevator.line.material.dispose();
        }
        if (elevator.glow) {
            gameMode.scene.remove(elevator.glow);
            elevator.glow.geometry.dispose();
            elevator.glow.material.dispose();
        }
        if (elevator.particles) {
            gameMode.scene.remove(elevator.particles);
            elevator.particles.geometry.dispose();
            elevator.particles.material.dispose();
        }
    });
    gameMode.spaceElevators = [];

    // Build a map from node ID to planet mesh
    const nodeIdToMesh = new Map();
    gameMode.nodeMeshes.forEach(mesh => {
        const data = gameMode.nodeDataMap.get(mesh.uuid);
        if (data) {
            nodeIdToMesh.set(data.id, mesh);
        }
    });

    // Get all edges
    const allEdges = edges.get();
    if (!allEdges || allEdges.length === 0) return;

    // Limit elevators to prevent performance issues
    const maxElevators = 50;
    const sortedEdges = allEdges
        .filter(edge => !edge.hidden)
        .sort((a, b) => (b.packetCount || 0) - (a.packetCount || 0))
        .slice(0, maxElevators);

    sortedEdges.forEach(edge => {
        const fromMesh = nodeIdToMesh.get(edge.from);
        const toMesh = nodeIdToMesh.get(edge.to);

        if (!fromMesh || !toMesh) return;

        // Get positions
        const fromPos = fromMesh.position.clone();
        const toPos = toMesh.position.clone();

        // Get planet sizes for offset
        const fromData = gameMode.nodeDataMap.get(fromMesh.uuid);
        const toData = gameMode.nodeDataMap.get(toMesh.uuid);
        const fromSize = fromData ? fromData.size : 1500;
        const toSize = toData ? toData.size : 1500;

        // Calculate direction and offset from planet surfaces
        const direction = new THREE.Vector3().subVectors(toPos, fromPos).normalize();
        const startPos = fromPos.clone().add(direction.clone().multiplyScalar(fromSize * 1.1));
        const endPos = toPos.clone().sub(direction.clone().multiplyScalar(toSize * 1.1));

        // Create the elevator beam
        const points = [];
        const segments = 32;
        for (let i = 0; i <= segments; i++) {
            const t = i / segments;
            // Add slight curve for visual interest
            const midHeight = Math.sin(t * Math.PI) * 500;
            const perpendicular = new THREE.Vector3(-direction.z, 0, direction.x).normalize();
            const point = new THREE.Vector3().lerpVectors(startPos, endPos, t);
            point.add(perpendicular.clone().multiplyScalar(midHeight * 0.3));
            point.y += midHeight;
            points.push(point);
        }

        const curve = new THREE.CatmullRomCurve3(points);
        const curvePoints = curve.getPoints(64);

        // Main beam (tube-like appearance)
        const beamGeometry = new THREE.BufferGeometry().setFromPoints(curvePoints);
        const protocolColor = edge.protocol ? new THREE.Color(edge.protocol.Color) : new THREE.Color(0x00ffcc);
        const beamMaterial = new THREE.LineBasicMaterial({
            color: protocolColor,
            transparent: true,
            opacity: 0.6,
            linewidth: 2
        });
        const beam = new THREE.Line(beamGeometry, beamMaterial);

        // Outer glow effect
        const glowMaterial = new THREE.LineBasicMaterial({
            color: protocolColor,
            transparent: true,
            opacity: 0.15,
            linewidth: 4
        });
        const glow = new THREE.Line(beamGeometry.clone(), glowMaterial);

        // Create particles traveling along the beam
        const particleCount = Math.min(20, Math.max(5, Math.floor((edge.packetCount || 1) / 10)));
        const particleGeometry = new THREE.BufferGeometry();
        const particlePositions = new Float32Array(particleCount * 3);
        const particleSizes = new Float32Array(particleCount);
        const particleProgress = new Float32Array(particleCount);

        for (let i = 0; i < particleCount; i++) {
            particleProgress[i] = Math.random(); // Random starting position along curve
            particleSizes[i] = 80 + Math.random() * 120;

            // Initial position
            const point = curve.getPoint(particleProgress[i]);
            particlePositions[i * 3] = point.x;
            particlePositions[i * 3 + 1] = point.y;
            particlePositions[i * 3 + 2] = point.z;
        }

        particleGeometry.setAttribute('position', new THREE.BufferAttribute(particlePositions, 3));
        particleGeometry.setAttribute('size', new THREE.BufferAttribute(particleSizes, 1));

        const particleMaterial = new THREE.PointsMaterial({
            color: protocolColor,
            size: 100,
            transparent: true,
            opacity: 0.9,
            blending: THREE.AdditiveBlending,
            sizeAttenuation: true
        });

        const particles = new THREE.Points(particleGeometry, particleMaterial);

        // Add to scene
        gameMode.scene.add(beam);
        gameMode.scene.add(glow);
        gameMode.scene.add(particles);

        // Store elevator data for animation
        gameMode.spaceElevators.push({
            line: beam,
            glow: glow,
            particles: particles,
            curve: curve,
            particleProgress: particleProgress,
            particleCount: particleCount,
            speed: 0.002 + (edge.packetCount || 1) * 0.00001, // Speed based on traffic
            fromMesh: fromMesh,
            toMesh: toMesh,
            edge: edge
        });
    });
}

// Animate space elevator particles
function animateSpaceElevators() {
    gameMode.spaceElevators.forEach(elevator => {
        // Update particle positions along the curve
        const positions = elevator.particles.geometry.attributes.position.array;

        for (let i = 0; i < elevator.particleCount; i++) {
            // Move particle along curve
            elevator.particleProgress[i] += elevator.speed;
            if (elevator.particleProgress[i] > 1) {
                elevator.particleProgress[i] = 0;
            }

            // Get new position on curve
            const point = elevator.curve.getPoint(elevator.particleProgress[i]);
            positions[i * 3] = point.x;
            positions[i * 3 + 1] = point.y;
            positions[i * 3 + 2] = point.z;
        }

        elevator.particles.geometry.attributes.position.needsUpdate = true;

        // Update beam endpoints to follow planet positions
        const fromPos = elevator.fromMesh.position.clone();
        const toPos = elevator.toMesh.position.clone();

        const fromData = gameMode.nodeDataMap.get(elevator.fromMesh.uuid);
        const toData = gameMode.nodeDataMap.get(elevator.toMesh.uuid);
        const fromSize = fromData ? fromData.size : 1500;
        const toSize = toData ? toData.size : 1500;

        const direction = new THREE.Vector3().subVectors(toPos, fromPos).normalize();
        const startPos = fromPos.clone().add(direction.clone().multiplyScalar(fromSize * 1.1));
        const endPos = toPos.clone().sub(direction.clone().multiplyScalar(toSize * 1.1));

        // Rebuild curve with new endpoints
        const points = [];
        const segments = 32;
        for (let j = 0; j <= segments; j++) {
            const t = j / segments;
            const midHeight = Math.sin(t * Math.PI) * 500;
            const perpendicular = new THREE.Vector3(-direction.z, 0, direction.x).normalize();
            const point = new THREE.Vector3().lerpVectors(startPos, endPos, t);
            point.add(perpendicular.clone().multiplyScalar(midHeight * 0.3));
            point.y += midHeight;
            points.push(point);
        }

        elevator.curve = new THREE.CatmullRomCurve3(points);
        const curvePoints = elevator.curve.getPoints(64);

        // Update line geometry
        elevator.line.geometry.setFromPoints(curvePoints);
        elevator.glow.geometry.setFromPoints(curvePoints);
    });
}

// ==================== WARP DRIVE SYSTEM ====================

// Open warp drive search overlay
function openWarpDrive() {
    if (gameMode.isWarping) return;

    gameMode.warpDriveActive = true;
    gameMode.warpSelectedIndex = 0;
    gameMode.warpResults = [];

    const overlay = document.getElementById('warpDriveOverlay');
    const input = document.getElementById('warpSearchInput');
    const results = document.getElementById('warpDriveResults');
    const status = document.getElementById('warpDriveStatus');

    if (overlay) {
        overlay.classList.add('active');
        status.textContent = 'READY';
        status.className = 'warp-drive-status';
        results.innerHTML = '<div class="warp-no-results">Type to search for a destination...</div>';
    }

    if (input) {
        input.value = '';
        input.focus();

        // Add input listener
        input.oninput = () => updateWarpSearch(input.value);
    }

    // Exit pointer lock for typing
    document.exitPointerLock();
}

// Close warp drive overlay
function closeWarpDrive() {
    gameMode.warpDriveActive = false;
    gameMode.warpResults = [];

    const overlay = document.getElementById('warpDriveOverlay');
    const input = document.getElementById('warpSearchInput');

    if (overlay) {
        overlay.classList.remove('active');
    }

    if (input) {
        input.oninput = null;
        input.value = '';
    }
}

// Update warp search results
function updateWarpSearch(query) {
    const results = document.getElementById('warpDriveResults');
    if (!results) return;

    if (!query || query.length < 1) {
        results.innerHTML = '<div class="warp-no-results">Type to search for a destination...</div>';
        gameMode.warpResults = [];
        return;
    }

    const queryLower = query.toLowerCase();
    const matches = [];

    // Search through all nodes
    const allNodes = nodes.get();
    allNodes.forEach(node => {
        const nodeMatches = [];

        // Check ID (IP address)
        if (node.id && node.id.toLowerCase().includes(queryLower)) {
            nodeMatches.push({ type: 'IP', value: node.id });
        }

        // Check label (hostname)
        if (node.label && node.label.toLowerCase().includes(queryLower)) {
            nodeMatches.push({ type: 'Hostname', value: node.label });
        }

        // Check MAC addresses
        if (node.macs) {
            node.macs.forEach(mac => {
                if (mac.toLowerCase().includes(queryLower)) {
                    nodeMatches.push({ type: 'MAC', value: mac });
                }
            });
        }

        // Check title for additional data
        if (node.title && node.title.toLowerCase().includes(queryLower)) {
            nodeMatches.push({ type: 'Data', value: 'Packet data match' });
        }

        if (nodeMatches.length > 0) {
            matches.push({
                node: node,
                matches: nodeMatches
            });
        }
    });

    // Also search edges for protocol matches
    const allEdges = edges.get();
    allEdges.forEach(edge => {
        if (edge.protocol && edge.protocol.Name && edge.protocol.Name.toLowerCase().includes(queryLower)) {
            // Find the source node for this edge
            const sourceNode = allNodes.find(n => n.id === edge.from);
            if (sourceNode && !matches.find(m => m.node.id === sourceNode.id)) {
                matches.push({
                    node: sourceNode,
                    matches: [{ type: 'Protocol', value: edge.protocol.Name }]
                });
            }
        }
    });

    // Search through packet payloads
    const allCachedPackets = Array.from(packetCache.values());
    if (allCachedPackets && allCachedPackets.length > 0 && query.length >= 2) {
        const queryBytes = stringToBytes(queryLower);

        allCachedPackets.forEach(packet => {
            if (!packet.payload) return;

            try {
                const payloadBytes = base64ToBytes(packet.payload);

                if (searchInPayload(payloadBytes, queryBytes)) {
                    // Find the source node for this packet
                    const sourceNode = allNodes.find(n => n.id === packet.src ||
                        (n.ips && n.ips.includes(packet.src)));

                    if (sourceNode) {
                        let existingMatch = matches.find(m => m.node.id === sourceNode.id);
                        if (!existingMatch) {
                            existingMatch = {
                                node: sourceNode,
                                matches: []
                            };
                            matches.push(existingMatch);
                        }

                        // Add payload match if not already present
                        if (!existingMatch.matches.find(m => m.type === 'Payload')) {
                            const payloadPreview = getPayloadPreview(payloadBytes, queryBytes);
                            existingMatch.matches.push({
                                type: 'Payload',
                                value: `"${payloadPreview}"`
                            });
                        }
                    }
                }
            } catch (e) {
                // Skip packets with invalid payload data
            }
        });
    }

    gameMode.warpResults = matches.slice(0, 10); // Limit to 10 results
    gameMode.warpSelectedIndex = 0;

    if (matches.length === 0) {
        results.innerHTML = '<div class="warp-no-results">No destinations found for "' + query + '"</div>';
        return;
    }

    // Render results
    results.innerHTML = gameMode.warpResults.map((result, index) => {
        const node = result.node;
        const packetCount = extractPacketCount(node.title) || 0;
        const matchText = result.matches.map(m => `${m.type}: ${m.value}`).join(' | ');

        return `
            <div class="warp-result-item ${index === 0 ? 'selected' : ''}" data-index="${index}">
                <div class="warp-result-hostname">${node.label || node.id}</div>
                <div class="warp-result-details">
                    <span>IP: ${node.id}</span>
                    <span>Packets: ${packetCount.toLocaleString()}</span>
                </div>
                <div class="warp-result-match">${matchText}</div>
            </div>
        `;
    }).join('');

    // Add click handlers
    results.querySelectorAll('.warp-result-item').forEach(item => {
        item.onclick = () => {
            const index = parseInt(item.dataset.index);
            selectWarpDestination(index);
        };
    });
}

// Update selected result highlight
function updateWarpSelection() {
    const results = document.getElementById('warpDriveResults');
    if (!results) return;

    results.querySelectorAll('.warp-result-item').forEach((item, index) => {
        if (index === gameMode.warpSelectedIndex) {
            item.classList.add('selected');
            item.scrollIntoView({ block: 'nearest' });
        } else {
            item.classList.remove('selected');
        }
    });
}

// Select and warp to destination
function selectWarpDestination(index) {
    if (index === undefined) index = gameMode.warpSelectedIndex;
    if (!gameMode.warpResults[index]) return;

    const result = gameMode.warpResults[index];
    const targetNode = result.node;

    // Find the planet mesh for this node
    let targetMesh = null;
    for (const mesh of gameMode.nodeMeshes) {
        const data = gameMode.nodeDataMap.get(mesh.uuid);
        if (data && data.id === targetNode.id) {
            targetMesh = mesh;
            break;
        }
    }

    if (!targetMesh) {
        console.warn('Could not find planet for node:', targetNode.id);
        closeWarpDrive();
        return;
    }

    // Start warp sequence
    initiateWarp(targetMesh, targetNode);
}

// Initiate warp travel to destination
function initiateWarp(targetMesh, targetNode) {
    gameMode.isWarping = true;

    const status = document.getElementById('warpDriveStatus');
    if (status) {
        status.textContent = 'ENGAGING';
        status.className = 'warp-drive-status warping';
    }

    // Close search overlay after brief delay
    setTimeout(() => {
        closeWarpDrive();
    }, 300);

    // Show warp effect
    const effectOverlay = document.getElementById('warpEffectOverlay');
    const streaksContainer = document.getElementById('warpStreaks');
    const destinationLabel = document.getElementById('warpDestination');

    if (effectOverlay) {
        effectOverlay.classList.add('active');

        // Create warp streaks
        if (streaksContainer) {
            streaksContainer.innerHTML = '';
            for (let i = 0; i < 60; i++) {
                const streak = document.createElement('div');
                streak.className = 'warp-streak';
                const angle = (Math.random() * 360);
                const delay = Math.random() * 0.3;
                streak.style.transform = `rotate(${angle}deg)`;
                streak.style.animationDelay = `${delay}s`;
                streak.style.left = `${50 + (Math.random() - 0.5) * 20}%`;
                streak.style.top = `${50 + (Math.random() - 0.5) * 20}%`;
                streaksContainer.appendChild(streak);
            }
        }

        // Show destination name
        if (destinationLabel) {
            destinationLabel.textContent = targetNode.label || targetNode.id;
        }
    }

    // Get target position (slightly in front of planet)
    const targetData = gameMode.nodeDataMap.get(targetMesh.uuid);
    const planetSize = targetData ? targetData.size : 2000;
    const targetPos = targetMesh.position.clone();

    // Calculate viewing position (in front of and slightly above the planet)
    const cameraOffset = planetSize * 3;
    const viewDirection = new THREE.Vector3()
        .subVectors(gameMode.camera.position, targetPos)
        .normalize();

    const finalPosition = targetPos.clone().add(viewDirection.multiplyScalar(cameraOffset));
    finalPosition.y += planetSize * 0.5;

    // Store starting position
    const startPosition = gameMode.camera.position.clone();
    const startTime = Date.now();
    const warpDuration = 2000; // 2 seconds

    // Animate warp travel
    function animateWarp() {
        const elapsed = Date.now() - startTime;
        const progress = Math.min(elapsed / warpDuration, 1);

        // Easing function for smooth acceleration/deceleration
        const easeProgress = progress < 0.5
            ? 4 * progress * progress * progress
            : 1 - Math.pow(-2 * progress + 2, 3) / 2;

        // Update camera position
        gameMode.camera.position.lerpVectors(startPosition, finalPosition, easeProgress);

        // Make camera look at target during warp
        const lookAtProgress = Math.min(progress * 1.5, 1);
        if (lookAtProgress < 1) {
            const currentTarget = new THREE.Vector3().lerpVectors(
                startPosition.clone().add(new THREE.Vector3(0, 0, -1000)),
                targetPos,
                lookAtProgress
            );
            gameMode.camera.lookAt(currentTarget);
        } else {
            gameMode.camera.lookAt(targetPos);
        }

        if (progress < 1) {
            requestAnimationFrame(animateWarp);
        } else {
            // Warp complete
            completeWarp(targetMesh, targetNode);
        }
    }

    animateWarp();
}

// Complete warp sequence
function completeWarp(targetMesh, targetNode) {
    // Flash effect
    const container = document.getElementById('gameModeContainer');
    const flash = document.createElement('div');
    flash.className = 'warp-flash active';
    container.appendChild(flash);

    setTimeout(() => {
        flash.remove();
    }, 600);

    // Hide warp effect
    const effectOverlay = document.getElementById('warpEffectOverlay');
    if (effectOverlay) {
        effectOverlay.classList.remove('active');
        const streaksContainer = document.getElementById('warpStreaks');
        if (streaksContainer) streaksContainer.innerHTML = '';
    }

    // Lock onto the target
    gameMode.lockedTarget = { mesh: targetMesh, data: targetNode };

    // Update targeting UI
    const reticle = document.getElementById('targetingReticle');
    const targetPanel = document.querySelector('.hud-panel-right');
    if (reticle) reticle.classList.add('locked');
    if (targetPanel) targetPanel.classList.add('locked');

    // Show planet info
    const planetInfoScreen = document.getElementById('planetInfoScreen');
    if (planetInfoScreen) {
        planetInfoScreen.classList.add('show');
        const packetCount = extractPacketCount(targetNode.title) || 0;
        planetInfoScreen.innerHTML = `
            <h4>DESTINATION REACHED</h4>
            <div class="info-item"><strong>ID:</strong> ${targetNode.id}</div>
            <div class="info-item"><strong>HOST:</strong> ${targetNode.label || 'Unknown'}</div>
            <div class="info-item"><strong>PACKETS:</strong> ${packetCount.toLocaleString()}</div>
        `;
    }

    gameMode.isWarping = false;

    // Reset camera velocity
    gameMode.currentSpeed = 0;
    gameMode.velocity.set(0, 0, 0);
}

// Handle warp drive keyboard input
function handleWarpKeyDown(e) {
    if (!gameMode.warpDriveActive) return false;

    switch (e.key) {
        case 'Escape':
            closeWarpDrive();
            return true;

        case 'ArrowDown':
            e.preventDefault();
            if (gameMode.warpResults.length > 0) {
                gameMode.warpSelectedIndex = (gameMode.warpSelectedIndex + 1) % gameMode.warpResults.length;
                updateWarpSelection();
            }
            return true;

        case 'ArrowUp':
            e.preventDefault();
            if (gameMode.warpResults.length > 0) {
                gameMode.warpSelectedIndex = (gameMode.warpSelectedIndex - 1 + gameMode.warpResults.length) % gameMode.warpResults.length;
                updateWarpSelection();
            }
            return true;

        case 'Enter':
            e.preventDefault();
            if (gameMode.warpResults.length > 0) {
                selectWarpDestination();
            }
            return true;
    }

    return false;
}

// ==================== END WARP DRIVE SYSTEM ====================

// Get node color based on traffic
function getNodeColor(node) {
    const title = node.title || '';
    const packets = extractPacketCount(title);

    // Color gradient based on traffic intensity
    if (packets > 1000) return 0xff4444; // Red - high traffic
    if (packets > 500) return 0xff8844; // Orange
    if (packets > 100) return 0xffcc44; // Yellow
    if (packets > 10) return 0x44ff88; // Green
    return 0x4488ff; // Blue - low traffic
}

// Animation loop
function animateGameScene() {
    if (!gameMode.active) return;

    gameMode.animationId = requestAnimationFrame(animateGameScene);

    // Handle movement with realistic spacecraft physics
    const maxSpeed = 150;  // Cruising speed for vast distances
    const boostSpeed = 400; // When holding shift
    const acceleration = 0.02;  // Slow, realistic acceleration
    const deceleration = 0.015; // Gradual slowdown (space has no friction but thrusters)
    const direction = new THREE.Vector3();

    // Calculate target speed - slower, more deliberate movement
    let targetForwardSpeed = 0;
    const currentMaxSpeed = gameMode.boosting ? boostSpeed : maxSpeed;
    if (gameMode.moveForward) targetForwardSpeed = -currentMaxSpeed;
    if (gameMode.moveBackward) targetForwardSpeed = currentMaxSpeed * 0.5; // Reverse is slower

    // Very smooth speed interpolation for realistic feel
    if (targetForwardSpeed !== 0) {
        gameMode.currentSpeed += (targetForwardSpeed - gameMode.currentSpeed) * acceleration;
    } else {
        gameMode.currentSpeed *= (1 - deceleration);
        if (Math.abs(gameMode.currentSpeed) < 0.5) gameMode.currentSpeed = 0;
    }

    direction.z = gameMode.currentSpeed;
    // Strafe is slower than forward movement
    if (gameMode.moveLeft) direction.x -= currentMaxSpeed * 0.3;
    if (gameMode.moveRight) direction.x += currentMaxSpeed * 0.3;
    if (gameMode.moveUp) direction.y += currentMaxSpeed * 0.2;
    if (gameMode.moveDown) direction.y -= currentMaxSpeed * 0.2;

    // Apply camera rotation to movement
    direction.applyQuaternion(gameMode.camera.quaternion);
    gameMode.camera.position.add(direction);

    // Update speed effects
    updateSpeedEffects();

    // Animate planets with realistic motion
    gameMode.nodeMeshes.forEach(planetGroup => {
        const data = gameMode.nodeDataMap.get(planetGroup.uuid);
        if (data) {
            // Orbital motion
            data.orbitAngle += data.orbitSpeed;
            planetGroup.position.x = Math.cos(data.orbitAngle) * data.orbitRadius;
            planetGroup.position.z = Math.sin(data.orbitAngle) * data.orbitRadius;
            planetGroup.position.y += Math.sin(data.orbitAngle * 2) * data.orbitTilt * 0.5;

            // Planet self-rotation
            if (planetGroup.children[0]) {
                planetGroup.children[0].rotation.y += data.rotationSpeed;
            }

            // Animate moons
            planetGroup.children.forEach(child => {
                if (child.userData.moonOrbitRadius) {
                    child.userData.moonOrbitAngle += child.userData.moonOrbitSpeed;
                    child.position.x = Math.cos(child.userData.moonOrbitAngle) * child.userData.moonOrbitRadius;
                    child.position.z = Math.sin(child.userData.moonOrbitAngle) * child.userData.moonOrbitRadius;
                }
            });
        }
    });

    // Animate space elevators (node-to-node communication beams)
    animateSpaceElevators();

    // Slowly rotate starfield for parallax effect
    if (gameMode.stars) {
        gameMode.stars.rotation.y += 0.00003;
        gameMode.stars.rotation.x += 0.00001;
    }

    // Animate star twinkling
    if (gameMode.starTwinkleData) {
        const time = Date.now() * 0.001;

        // Twinkle bright stars
        if (gameMode.starTwinkleData.brightStars) {
            const { material, baseSize, phases } = gameMode.starTwinkleData.brightStars;
            const twinkleFactor = 0.3;
            let avgTwinkle = 0;
            for (let i = 0; i < Math.min(phases.length, 100); i++) {
                avgTwinkle += Math.sin(time * (1 + (i % 10) * 0.1) + phases[i]);
            }
            avgTwinkle = avgTwinkle / 100;
            material.size = baseSize * (1 + avgTwinkle * twinkleFactor);
        }

        // Twinkle super bright stars more dramatically
        if (gameMode.starTwinkleData.superBright) {
            const { material, baseSize, phases } = gameMode.starTwinkleData.superBright;
            const twinkleFactor = 0.4;
            let avgTwinkle = 0;
            for (let i = 0; i < Math.min(phases.length, 50); i++) {
                avgTwinkle += Math.sin(time * 0.8 * (1 + (i % 5) * 0.2) + phases[i]);
            }
            avgTwinkle = avgTwinkle / 50;
            material.size = baseSize * (1 + avgTwinkle * twinkleFactor);
            material.opacity = 0.85 + avgTwinkle * 0.15;
        }
    }

    // Occasional shooting stars
    if (Math.random() < 0.002 && !gameMode.shootingStar) {
        createShootingStar();
    }

    // Update shooting star if active
    if (gameMode.shootingStar) {
        updateShootingStar();
    }

    // Animate nebulae with subtle drift
    gameMode.nebulae.forEach((nebula, i) => {
        nebula.rotation.y += 0.00002 * (i % 2 === 0 ? 1 : -1);
        nebula.rotation.z += 0.00001;
        // Subtle pulsing
        nebula.material.opacity = nebula.userData.baseOpacity * (0.9 + 0.1 * Math.sin(Date.now() * 0.0005 + i));
    });

    // Animate sun flares - rotate and pulse
    if (gameMode.sunFlares) {
        gameMode.sunFlares.rotation.y += 0.0003;
        gameMode.sunFlares.rotation.x += 0.0001;
        gameMode.sunFlares.material.opacity = 0.5 + 0.2 * Math.sin(Date.now() * 0.001);
    }

    // Animate asteroids
    gameMode.scene.children.forEach(child => {
        if (child.userData && child.userData.isAsteroid) {
            child.userData.orbitAngle += child.userData.orbitSpeed;
            child.position.x = Math.cos(child.userData.orbitAngle) * child.userData.orbitRadius;
            child.position.z = Math.sin(child.userData.orbitAngle) * child.userData.orbitRadius;

            child.rotation.x += child.userData.rotationSpeed.x;
            child.rotation.y += child.userData.rotationSpeed.y;
            child.rotation.z += child.userData.rotationSpeed.z;
        }
    });

    // Move ambient dust with camera for parallax
    if (gameMode.ambientDust) {
        gameMode.ambientDust.position.x = gameMode.camera.position.x;
        gameMode.ambientDust.position.y = gameMode.camera.position.y;
        gameMode.ambientDust.position.z = gameMode.camera.position.z;
        gameMode.ambientDust.rotation.y += 0.0001;
    }

    // Animate blinky buttons
    for (let i = 0; i < 8; i++) {
        const button = gameMode.camera.getObjectByName("blinky_button_" + i);
        if (button) {
            button.material.emissiveIntensity = 0.4 + Math.abs(Math.sin(Date.now() * 0.003 * (i + 1))) * 0.6;
        }
    }

    // Animate warning lights
    for (let i = 0; i < 4; i++) {
        const warning = gameMode.camera.getObjectByName("warning_light_" + i);
        if (warning) {
            warning.material.opacity = 0.5 + Math.abs(Math.sin(Date.now() * 0.004 + i * 1.5)) * 0.5;
        }
    }

    // Animate holographic display
    const holoDisplay = gameMode.camera.getObjectByName("holo_display");
    if (holoDisplay) {
        holoDisplay.material.opacity = 0.08 + Math.abs(Math.sin(Date.now() * 0.002)) * 0.07;
    }

    // Auto-lock targeting - find nearest planet to screen center
    const reticle = document.getElementById('targetingReticle');
    const targetPanel = document.querySelector('.hud-panel-right');
    const targetIp = document.getElementById('targetIp');
    const targetPackets = document.getElementById('targetPackets');
    const hostnameLabel = document.getElementById('planetHostnameLabel');
    const hostnameText = document.getElementById('hostnameText');
    const hostnameIpText = document.getElementById('hostnameIp');

    const screenCenterX = window.innerWidth / 2;
    const screenCenterY = window.innerHeight / 2;
    const autoLockRadius = 300; // Pixels from center to auto-lock

    let nearestPlanet = null;
    let nearestDistance = Infinity;
    let nearestScreenPos = null;

    // Check all planets and find the nearest one to screen center
    gameMode.nodeMeshes.forEach(group => {
        const nodeData = gameMode.nodeDataMap.get(group.uuid);
        if (!nodeData) return;

        // Project planet position to screen
        const vector = group.position.clone();
        vector.project(gameMode.camera);

        // Check if in front of camera
        if (vector.z > 1) return;

        const screenX = (vector.x * 0.5 + 0.5) * window.innerWidth;
        const screenY = (-(vector.y * 0.5) + 0.5) * window.innerHeight;

        // Calculate distance from screen center
        const dx = screenX - screenCenterX;
        const dy = screenY - screenCenterY;
        const distance = Math.sqrt(dx * dx + dy * dy);

        // Check if within auto-lock radius and closer than current nearest
        if (distance < autoLockRadius && distance < nearestDistance) {
            nearestDistance = distance;
            nearestPlanet = { mesh: group, data: nodeData };
            nearestScreenPos = { x: screenX, y: screenY };
        }
    });

    if (nearestPlanet) {
        // Lock onto nearest planet
        reticle.classList.add('locked');
        if (targetPanel) targetPanel.classList.add('locked');
        gameMode.lockedTarget = nearestPlanet;
        gameMode.autoLockPosition = nearestScreenPos;

        // Move reticle to planet position
        reticle.style.left = nearestScreenPos.x + 'px';
        reticle.style.top = nearestScreenPos.y + 'px';
        reticle.style.transform = 'translate(-50%, -50%)';

        // Update target info in Shodan HUD style
        if (targetIp) targetIp.textContent = nearestPlanet.data.id;
        if (targetPackets) targetPackets.textContent = nearestPlanet.data.packetCount.toLocaleString();

        // Show floating hostname label above the reticle
        if (hostnameLabel) {
            hostnameLabel.classList.add('visible', 'locked');
            hostnameLabel.style.left = nearestScreenPos.x + 'px';
            hostnameLabel.style.top = (nearestScreenPos.y - 50) + 'px';

            // Get hostname (label) and IP
            const hostname = nearestPlanet.data.label || nearestPlanet.data.id;
            const ip = nearestPlanet.data.id;

            if (hostnameText) hostnameText.textContent = hostname;
            if (hostnameIpText) hostnameIpText.textContent = ip !== hostname ? ip : '';
        }
    } else {
        // No target - reset reticle to center
        reticle.classList.remove('locked');
        if (targetPanel) targetPanel.classList.remove('locked');
        if (targetIp) targetIp.textContent = '---';
        if (targetPackets) targetPackets.textContent = '---';
        gameMode.lockedTarget = null;
        gameMode.autoLockPosition = { x: screenCenterX, y: screenCenterY };

        // Reset reticle to center
        reticle.style.left = '50%';
        reticle.style.top = '50%';
        reticle.style.transform = 'translate(-50%, -50%)';

        // Hide hostname label
        if (hostnameLabel) {
            hostnameLabel.classList.remove('visible', 'locked');
        }
    }

    // Render
    gameMode.renderer.render(gameMode.scene, gameMode.camera);
}

// Update speed visual effects
function updateSpeedEffects() {
    const speedLines = document.getElementById('speedLines');
    const warpTunnel = document.getElementById('warpTunnel');
    const speedFill = document.getElementById('speedFill');
    const speedValue = document.getElementById('speedValue');
    const velocityBar = document.querySelector('.hud-velocity-bar');

    const absSpeed = Math.abs(gameMode.currentSpeed);
    const maxDisplaySpeed = gameMode.boosting ? 400 : 150;
    const speedPercent = Math.min((absSpeed / maxDisplaySpeed) * 100, 100);

    // Update speed bar
    if (speedFill) {
        speedFill.style.width = speedPercent + '%';
        // Change color when boosting
        if (gameMode.boosting && absSpeed > 100) {
            speedFill.style.background = 'linear-gradient(90deg, rgba(255, 100, 50, 0.8), rgba(255, 200, 50, 1), rgba(255, 255, 150, 1))';
            speedFill.style.boxShadow = '0 0 15px rgba(255, 150, 50, 0.8), inset 0 0 5px rgba(255, 255, 255, 0.5)';
        } else {
            speedFill.style.background = '';
            speedFill.style.boxShadow = '';
        }
    }
    if (speedValue) speedValue.textContent = Math.round(absSpeed);

    // Determine direction
    const isReverse = gameMode.currentSpeed > 0;
    if (speedFill) speedFill.classList.toggle('reverse', isReverse);
    if (speedLines) speedLines.classList.toggle('reverse', isReverse);
    if (warpTunnel) warpTunnel.classList.toggle('reverse', isReverse);

    // Activate effects based on speed
    if (absSpeed > 50) {
        if (speedLines) speedLines.classList.add('active');
        if (!gameMode.speedLinesActive) {
            gameMode.speedLinesActive = true;
            // Regenerate speed lines with random positions
            if (speedLines) {
                const lines = speedLines.querySelectorAll('.speed-line');
                lines.forEach(line => {
                    line.style.left = Math.random() * 100 + '%';
                    line.style.animationDelay = Math.random() * 0.3 + 's';
                });
            }
        }
    } else {
        if (speedLines) speedLines.classList.remove('active');
        gameMode.speedLinesActive = false;
    }

    // Warp tunnel at high speed or when boosting
    if (absSpeed > 200 || (gameMode.boosting && absSpeed > 100)) {
        if (warpTunnel) warpTunnel.classList.add('active');
    } else {
        if (warpTunnel) warpTunnel.classList.remove('active');
    }
}

// Handle keyboard input for movement
function handleGameKeyDown(e) {
    if (!gameMode.active) return;

    // Handle warp drive input first
    if (gameMode.warpDriveActive) {
        if (handleWarpKeyDown(e)) return;
    }

    // Check for "/" key to open warp drive
    if (e.key === '/' && !gameMode.warpDriveActive && !gameMode.isWarping) {
        e.preventDefault();
        openWarpDrive();
        return;
    }

    switch (e.code) {
        case 'KeyW':
            gameMode.moveForward = true;
            break;
        case 'KeyS':
            gameMode.moveBackward = true;
            break;
        case 'KeyA':
            gameMode.moveLeft = true;
            break;
        case 'KeyD':
            gameMode.moveRight = true;
            break;
        case 'Space':
            gameMode.moveUp = true;
            break;
        case 'ControlLeft':
        case 'ControlRight':
        case 'KeyC':
            gameMode.moveDown = true;
            break;
        case 'ShiftLeft':
        case 'ShiftRight':
            gameMode.boosting = true;
            break;
        case 'Escape':
            // Close warp drive if open, otherwise exit game mode
            if (gameMode.warpDriveActive) {
                closeWarpDrive();
            } else {
                toggleGameMode();
            }
            break;
    }
}

function handleGameKeyUp(e) {
    if (!gameMode.active) return;

    switch (e.code) {
        case 'KeyW':
            gameMode.moveForward = false;
            break;
        case 'KeyS':
            gameMode.moveBackward = false;
            break;
        case 'KeyA':
            gameMode.moveLeft = false;
            break;
        case 'KeyD':
            gameMode.moveRight = false;
            break;
        case 'Space':
            gameMode.moveUp = false;
            break;
        case 'ControlLeft':
        case 'ControlRight':
        case 'KeyC':
            gameMode.moveDown = false;
            break;
        case 'ShiftLeft':
        case 'ShiftRight':
            gameMode.boosting = false;
            break;
    }
}

// Handle mouse movement for camera rotation
function handleGameMouseMove(e) {
    if (!gameMode.active) return;
    if (document.pointerLockElement !== document.getElementById('gameCanvas')) return;

    const movementX = e.movementX || 0;
    const movementY = e.movementY || 0;

    gameMode.euler.setFromQuaternion(gameMode.camera.quaternion);

    gameMode.euler.y -= movementX * 0.002;
    gameMode.euler.x -= movementY * 0.002;

    // Clamp vertical rotation
    gameMode.euler.x = Math.max(-gameMode.PI_2, Math.min(gameMode.PI_2, gameMode.euler.x));

    gameMode.camera.quaternion.setFromEuler(gameMode.euler);
}

// Handle click for shooting laser
function handleGameClick(e) {
    if (!gameMode.active) return;
    if (gameMode.laserCooldown) return;

    // Request pointer lock if not locked
    if (document.pointerLockElement !== document.getElementById('gameCanvas')) {
        document.getElementById('gameCanvas').requestPointerLock();
        return;
    }

    // Fire laser
    fireLaser();
}

// Fire laser effect - moving projectile beams from bottom corners to reticle
function fireLaser() {
    if (gameMode.laserCooldown) return;
    gameMode.laserCooldown = true;

    const container = document.getElementById('gameModeContainer');
    const reticle = document.getElementById('targetingReticle');
    const containerRect = container.getBoundingClientRect();

    // Get reticle position (center of screen or locked target position)
    let targetX = containerRect.width / 2;
    let targetY = containerRect.height / 2;

    if (reticle && gameMode.autoLockPosition) {
        targetX = gameMode.autoLockPosition.x;
        targetY = gameMode.autoLockPosition.y;
    }

    // Bottom corner positions
    const leftStart = { x: 40, y: containerRect.height - 60 };
    const rightStart = { x: containerRect.width - 40, y: containerRect.height - 60 };

    // Create and animate left laser
    const laserLeft = document.createElement('div');
    laserLeft.className = 'laser-beam laser-left';
    container.appendChild(laserLeft);
    animateLaserProjectile(laserLeft, leftStart, { x: targetX, y: targetY }, 200);

    // Create and animate right laser
    const laserRight = document.createElement('div');
    laserRight.className = 'laser-beam laser-right';
    container.appendChild(laserRight);
    animateLaserProjectile(laserRight, rightStart, { x: targetX, y: targetY }, 200);

    // Remove after animation
    setTimeout(() => {
        laserLeft.remove();
        laserRight.remove();
        gameMode.laserCooldown = false;
    }, 250);

    // Check if we hit a target
    if (gameMode.lockedTarget) {
        const { mesh, data } = gameMode.lockedTarget;

        // Create hit effect in 3D scene
        createHitEffect(mesh.position.clone(), data);

        // Flash the planet
        if (mesh.children && mesh.children[0] && mesh.children[0].material) {
            const planet = mesh.children[0];
            const originalEmissive = planet.material.emissiveIntensity;
            planet.material.emissiveIntensity = 1;
            setTimeout(() => {
                planet.material.emissiveIntensity = originalEmissive;
            }, 200);
        }

        // Create packet data explosion
        createPacketExplosion(mesh.position.clone(), data);

        // Show detailed stats
        showNodeScanResult(data);

        // Show planet info screen
        const planetInfoScreen = document.getElementById('planetInfoScreen');
        planetInfoScreen.classList.add('show');
        planetInfoScreen.innerHTML = `
            <h4>PLANET SCAN</h4>
            <div class="info-item"><strong>ID:</strong> ${data.id}</div>
            <div class="info-item"><strong>HOST:</strong> ${data.label || 'Unknown'}</div>
            <div class="info-item"><strong>PACKETS:</strong> ${data.packetCount.toLocaleString()}</div>
            <div class="info-item"><strong>BYTES:</strong> ${extractByteCount(data.title) || 'N/A'}</div>
        `;

        // Fetch and display a random TCP stream
        displayRandomStream(data);
    }
}

// Fetch and display a random TCP stream in tail-like fashion
async function displayRandomStream(nodeData) {
    const terminal = document.getElementById('streamTerminal');
    const title = document.getElementById('streamTerminalTitle');
    const status = document.getElementById('streamTerminalStatus');
    const content = document.getElementById('streamTerminalContent');

    if (!terminal || !content) return;

    // Show terminal
    terminal.style.display = 'block';
    content.innerHTML = '<span class="stream-cursor">_</span>';
    status.textContent = 'CONNECTING...';
    status.className = 'stream-terminal-status connecting';

    try {
        // Fetch available streams
        const streamsResponse = await fetch('/api/streams');
        if (!streamsResponse.ok) throw new Error('Failed to fetch streams');

        const streams = await streamsResponse.json();
        if (!streams || streams.length === 0) {
            content.innerHTML = '<span class="stream-error">NO STREAMS AVAILABLE</span>';
            status.textContent = 'NO DATA';
            return;
        }

        // Pick a random stream
        const randomStream = streams[Math.floor(Math.random() * streams.length)];

        // Update title with stream info
        title.textContent = `// TCP STREAM [${randomStream.src_port || '?'} → ${randomStream.dst_port || '?'}]`;
        status.textContent = 'STREAMING';
        status.className = 'stream-terminal-status active';

        // Fetch the stream content
        const streamResponse = await fetch(`/api/stream?id=${randomStream.id}`);
        if (!streamResponse.ok) throw new Error('Failed to fetch stream content');

        const streamData = await streamResponse.json();
        const streamText = streamData.data || streamData.content || JSON.stringify(streamData, null, 2);

        // Display in tail-like fashion (character by character)
        content.innerHTML = '';
        displayStreamText(content, streamText, 0);

    } catch (error) {
        console.error('Stream fetch error:', error);
        content.innerHTML = `<span class="stream-error">ERROR: ${error.message}</span>`;
        status.textContent = 'ERROR';
        status.className = 'stream-terminal-status error';
    }
}

// Display text character by character like tail
function displayStreamText(container, text, index) {
    if (index >= text.length || index >= 2000) { // Limit to 2000 chars
        // Add blinking cursor at end
        const cursor = document.createElement('span');
        cursor.className = 'stream-cursor';
        cursor.textContent = '_';
        container.appendChild(cursor);

        // Update status
        const status = document.getElementById('streamTerminalStatus');
        if (status) {
            status.textContent = 'COMPLETE';
            status.className = 'stream-terminal-status complete';
        }
        return;
    }

    const char = text[index];

    if (char === '\n') {
        container.appendChild(document.createElement('br'));
    } else if (char === ' ') {
        container.appendChild(document.createTextNode('\u00A0'));
    } else {
        const span = document.createElement('span');
        span.textContent = char;
        span.className = 'stream-char';
        container.appendChild(span);
    }

    // Auto-scroll to bottom
    container.scrollTop = container.scrollHeight;

    // Speed varies: faster for spaces/newlines, slower for other chars
    const delay = (char === ' ' || char === '\n') ? 5 : 15;

    setTimeout(() => {
        displayStreamText(container, text, index + 1);
    }, delay);
}

// Animate laser projectile from start to end position
function animateLaserProjectile(laser, start, end, duration) {
    const startTime = performance.now();

    // Calculate angle from start to end
    const dx = end.x - start.x;
    const dy = end.y - start.y;
    const angle = Math.atan2(dy, dx) * (180 / Math.PI);
    const distance = Math.sqrt(dx * dx + dy * dy);

    // Set initial position and rotation
    laser.style.left = start.x + 'px';
    laser.style.top = start.y + 'px';
    laser.style.transform = `rotate(${angle}deg)`;
    laser.style.transformOrigin = 'center center';

    function animate(currentTime) {
        const elapsed = currentTime - startTime;
        const progress = Math.min(elapsed / duration, 1);

        // Ease out for smooth deceleration
        const easeProgress = 1 - Math.pow(1 - progress, 2);

        // Calculate current position along the path
        const currentX = start.x + dx * easeProgress;
        const currentY = start.y + dy * easeProgress;

        laser.style.left = currentX + 'px';
        laser.style.top = currentY + 'px';

        // Fade out near the end
        if (progress > 0.7) {
            laser.style.opacity = 1 - ((progress - 0.7) / 0.3);
        }

        if (progress < 1) {
            requestAnimationFrame(animate);
        }
    }

    requestAnimationFrame(animate);
}

// Create hit effect at position
function createHitEffect(position, data) {
    // Project 3D position to 2D screen
    const vector = position.clone();
    vector.project(gameMode.camera);

    const x = (vector.x * 0.5 + 0.5) * window.innerWidth;
    const y = (-(vector.y * 0.5) + 0.5) * window.innerHeight;

    // Create hit effect element
    const container = document.getElementById('gameModeContainer');
    const hit = document.createElement('div');
    hit.className = 'hit-effect';
    hit.style.left = x + 'px';
    hit.style.top = y + 'px';
    container.appendChild(hit);

    // Remove after animation
    setTimeout(() => hit.remove(), 300);
}

// Create packet data explosion effect
function createPacketExplosion(position, data) {
    // Project 3D position to 2D screen
    const vector = position.clone();
    vector.project(gameMode.camera);

    const centerX = (vector.x * 0.5 + 0.5) * window.innerWidth;
    const centerY = (-(vector.y * 0.5) + 0.5) * window.innerHeight;

    const container = document.getElementById('gameModeContainer');

    // Create explosion container
    const explosion = document.createElement('div');
    explosion.className = 'packet-explosion';
    explosion.style.left = centerX + 'px';
    explosion.style.top = centerY + 'px';

    // Generate packet data particles
    const particleData = [
        { text: data.id, type: 'ip', delay: 0 },
        { text: data.label || 'Unknown Host', type: 'hostname', delay: 50 },
        { text: `${data.packetCount.toLocaleString()} packets`, type: 'packets', delay: 100 },
        { text: extractByteCount(data.title) || 'N/A bytes', type: 'bytes', delay: 150 },
        { text: data.planetType ? data.planetType.toUpperCase() : 'UNKNOWN', type: 'protocol', delay: 200 },
    ];

    // Add port info if available from title
    const portMatch = data.title?.match(/Port:\s*(\d+)/);
    if (portMatch) {
        particleData.push({ text: `Port ${portMatch[1]}`, type: 'port', delay: 250 });
    }

    // Add additional random packet info
    const extraInfo = [
        'TCP SYN',
        'ACK',
        'PSH',
        'FIN',
        'RST',
        'HTTP/1.1',
        'TLS 1.3',
        'DNS Query',
        'ICMP Echo'
    ];

    // Add 3-5 random extra particles
    const extraCount = 3 + Math.floor(Math.random() * 3);
    for (let i = 0; i < extraCount; i++) {
        particleData.push({
            text: extraInfo[Math.floor(Math.random() * extraInfo.length)],
            type: ['packets', 'bytes', 'protocol', 'port'][Math.floor(Math.random() * 4)],
            delay: 300 + i * 80
        });
    }

    particleData.forEach((item, index) => {
        setTimeout(() => {
            const particle = document.createElement('div');
            particle.className = `packet-particle ${item.type}`;
            particle.textContent = item.text;

            // Random explosion direction
            const angle = (index / particleData.length) * Math.PI * 2 + (Math.random() - 0.5) * 0.5;
            const distance = 60 + Math.random() * 80;
            const tx = Math.cos(angle) * distance;
            const ty = Math.sin(angle) * distance;

            particle.style.setProperty('--tx', tx + 'px');
            particle.style.setProperty('--ty', ty + 'px');

            explosion.appendChild(particle);
        }, item.delay);
    });

    container.appendChild(explosion);

    // Remove explosion container after all animations complete
    setTimeout(() => explosion.remove(), 2500);
}

// Show detailed node scan result
function showNodeScanResult(data) {
    const targetPanel = document.querySelector('.hud-panel-right');

    // Flash the target panel on hit
    if (targetPanel) {
        targetPanel.style.animation = 'none';
        targetPanel.offsetHeight; // Trigger reflow
        targetPanel.style.animation = 'hudHitFlash 0.3s ease-out';
        setTimeout(() => targetPanel.style.animation = '', 300);
    }

    // Could show more detailed packet info here
    console.log('Scanned node:', data);
}

// Update game HUD with current stats
function updateGameHUD() {
    const nodeCount = nodes.length || nodes.getIds().length;
    let totalPackets = 0;

    // Sum packets from all nodes
    nodes.get().forEach(node => {
        totalPackets += extractPacketCount(node.title) || 0;
    });

    document.getElementById('gameNodeCount').textContent = nodeCount;
    document.getElementById('gamePacketCount').textContent = totalPackets.toLocaleString();
}

// Handle window resize for game mode
function handleGameResize() {
    if (!gameMode.active || !gameMode.camera || !gameMode.renderer) return;

    const width = window.innerWidth;
    const height = window.innerHeight;

    gameMode.camera.aspect = width / height;
    gameMode.camera.updateProjectionMatrix();
    gameMode.renderer.setSize(width, height);
}

// Refresh game nodes when network data updates - INCREMENTAL version
function refreshGameNodes() {
    if (!gameMode.active) return;

    const allNodes = nodes.get();
    if (allNodes.length === 0) return;

    const currentNodeIds = new Set(allNodes.map(n => n.id));
    const existingNodeIds = new Set(gameMode.nodeIdToMesh.keys());

    // Find nodes to add and remove
    const nodesToAdd = allNodes.filter(n => !existingNodeIds.has(n.id));
    const nodeIdsToRemove = [...existingNodeIds].filter(id => !currentNodeIds.has(id));

    // Remove deleted nodes
    nodeIdsToRemove.forEach(nodeId => {
        const mesh = gameMode.nodeIdToMesh.get(nodeId);
        if (mesh) {
            // Clean up mesh
            while (mesh.children.length > 0) {
                const child = mesh.children[0];
                mesh.remove(child);
                if (child.geometry) child.geometry.dispose();
                if (child.material) child.material.dispose();
            }
            gameMode.scene.remove(mesh);
            if (mesh.geometry) mesh.geometry.dispose();
            if (mesh.material) mesh.material.dispose();

            // Remove from tracking
            const meshIndex = gameMode.nodeMeshes.indexOf(mesh);
            if (meshIndex > -1) gameMode.nodeMeshes.splice(meshIndex, 1);
            gameMode.nodeDataMap.delete(mesh.uuid);
            gameMode.nodeIdToMesh.delete(nodeId);
        }
    });

    // Add new nodes
    if (nodesToAdd.length > 0) {
        addNewGameNodes(nodesToAdd);
    }

    // Update data for existing nodes (packet counts, titles)
    allNodes.forEach(node => {
        const mesh = gameMode.nodeIdToMesh.get(node.id);
        if (mesh) {
            const data = gameMode.nodeDataMap.get(mesh.uuid);
            if (data) {
                const packetCount = extractPacketCount(node.title) || 1;
                data.packetCount = packetCount;
                data.title = node.title;
                data.label = node.label;
            }
        }
    });

    // Only rebuild elevators if nodes changed
    if (nodesToAdd.length > 0 || nodeIdsToRemove.length > 0) {
        createSpaceElevators();
    }

    updateGameHUD();
}

// Add new nodes to game mode without rebuilding everything
function addNewGameNodes(newNodes) {
    const allNodes = nodes.get();
    const nodeCount = allNodes.length;
    const rings = Math.ceil(Math.sqrt(nodeCount));

    newNodes.forEach(node => {
        // Find this node's index in the full list for positioning
        const index = allNodes.findIndex(n => n.id === node.id);
        if (index === -1) return;

        const ring = Math.floor(index / Math.max(1, Math.ceil(nodeCount / rings)));
        const positionInRing = index % Math.max(1, Math.ceil(nodeCount / rings));
        const nodesInRing = Math.ceil(nodeCount / rings);

        const orbitRadius = 25000 + ring * 25000;
        const angle = (positionInRing / nodesInRing) * Math.PI * 2 + ring * 0.5;
        const verticalOffset = (seededRandom(node.id, 'voff') - 0.5) * 8000;
        const orbitTilt = (seededRandom(node.id, 'tilt') - 0.5) * 0.4;

        const packetCount = extractPacketCount(node.title) || 1;
        const baseSize = 1500;
        const maxSize = 6000;
        const size = Math.min(maxSize, baseSize + Math.log10(packetCount + 1) * 1200);

        const planetTypeIndex = hashCode(node.id) % PLANET_TYPES.length;
        const planetType = PLANET_TYPES[Math.abs(planetTypeIndex)];

        const planetGroup = createPlanetMesh(node.id, size, planetType);

        planetGroup.position.set(
            Math.cos(angle) * orbitRadius,
            verticalOffset + Math.sin(angle * 2) * orbitTilt * orbitRadius,
            Math.sin(angle) * orbitRadius
        );

        gameMode.nodeDataMap.set(planetGroup.uuid, {
            id: node.id,
            label: node.label,
            title: node.title,
            packetCount: packetCount,
            orbitRadius: orbitRadius,
            orbitAngle: angle,
            orbitTilt: orbitTilt,
            orbitSpeed: 0.0003 + seededRandom(node.id, 'orbspd') * 0.0008,
            rotationSpeed: 0.005 + seededRandom(node.id, 'rotspd') * 0.01,
            planetType: planetType.name,
            size: size
        });

        gameMode.scene.add(planetGroup);
        gameMode.nodeMeshes.push(planetGroup);
        gameMode.nodeIdToMesh.set(node.id, planetGroup);
    });
}

// Create a planet mesh for a node (extracted helper)
function createPlanetMesh(nodeId, size, planetType) {
    const planetGroup = new THREE.Group();
    const baseColor = planetType.colors[Math.abs(hashCode(nodeId + 'color')) % planetType.colors.length];

    // Main planet body
    const geometry = new THREE.SphereGeometry(size, 64, 64);
    const material = new THREE.MeshPhongMaterial({
        color: baseColor,
        emissive: baseColor,
        emissiveIntensity: 0.12,
        shininess: 40,
        transparent: false
    });
    const planet = new THREE.Mesh(geometry, material);
    planet.rotation.x = seededRandom(nodeId, 'rotx') * 0.5;
    planet.rotation.z = seededRandom(nodeId, 'rotz') * 0.3;
    planetGroup.add(planet);

    // Surface features
    const featureGeometry = new THREE.SphereGeometry(size * 1.002, 64, 64);
    const featureColor = new THREE.Color(baseColor).offsetHSL(0.05, 0.1, 0.15);
    const featureMaterial = new THREE.MeshPhongMaterial({
        color: featureColor,
        emissive: featureColor,
        emissiveIntensity: 0.08,
        transparent: true,
        opacity: 0.6,
        blending: THREE.AdditiveBlending
    });
    const features = new THREE.Mesh(featureGeometry, featureMaterial);
    features.rotation.y = seededRandom(nodeId, 'feat') * Math.PI;
    planetGroup.add(features);

    // Clouds for atmospheric planets
    if (planetType.hasAtmosphere && seededRandom(nodeId, 'cloud') > 0.3) {
        const cloudGeometry = new THREE.SphereGeometry(size * 1.02, 48, 48);
        const cloudMaterial = new THREE.MeshPhongMaterial({
            color: 0xffffff,
            emissive: 0x222222,
            transparent: true,
            opacity: 0.25,
            blending: THREE.NormalBlending
        });
        const clouds = new THREE.Mesh(cloudGeometry, cloudMaterial);
        clouds.userData.rotationSpeed = 0.0002 + seededRandom(nodeId, 'cloudspd') * 0.0003;
        planetGroup.add(clouds);
    }

    // Atmosphere glow
    if (planetType.hasAtmosphere) {
        const atmosphereGeometry = new THREE.SphereGeometry(size * 1.15, 32, 32);
        const atmosphereMaterial = new THREE.MeshBasicMaterial({
            color: planetType.atmosphereColor,
            transparent: true,
            opacity: 0.15,
            side: THREE.BackSide
        });
        planetGroup.add(new THREE.Mesh(atmosphereGeometry, atmosphereMaterial));
    }

    // Rings
    const hasRings = planetType.hasRings || (size > 1500 && seededRandom(nodeId, 'rings') > 0.5);
    if (hasRings) {
        const ringGeometry = new THREE.RingGeometry(size * 1.4, size * 2.2, 64);
        const ringMaterial = new THREE.MeshBasicMaterial({
            color: 0xccbb99,
            transparent: true,
            opacity: 0.4,
            side: THREE.DoubleSide
        });
        const rings = new THREE.Mesh(ringGeometry, ringMaterial);
        rings.rotation.x = Math.PI / 2 + (seededRandom(nodeId, 'ringtilt') - 0.5) * 0.3;
        planetGroup.add(rings);
    }

    // Moons
    if (size > 200 && seededRandom(nodeId, 'hasmoon') > 0.4) {
        const moonCount = Math.floor(seededRandom(nodeId, 'moonct') * 4) + 1;
        for (let m = 0; m < moonCount; m++) {
            const moonSize = size * (0.08 + seededRandom(nodeId, 'moonsz' + m) * 0.12);
            const moonDistance = size * (1.4 + m * 0.5 + seededRandom(nodeId, 'moondst' + m) * 0.3);
            const moonGeometry = new THREE.SphereGeometry(moonSize, 24, 24);
            const moonMaterial = new THREE.MeshPhongMaterial({
                color: 0x999999,
                emissive: 0x333333,
                emissiveIntensity: 0.15
            });
            const moon = new THREE.Mesh(moonGeometry, moonMaterial);
            moon.userData.moonOrbitRadius = moonDistance;
            moon.userData.moonOrbitSpeed = 0.008 + seededRandom(nodeId, 'moonspd' + m) * 0.012;
            // Spread moons evenly around planet, plus small random offset
            const baseAngle = (m / moonCount) * Math.PI * 2;
            const randomOffset = (seededRandom(nodeId, 'moonang' + m) - 0.5) * 0.5;
            moon.userData.moonOrbitAngle = baseAngle + randomOffset;
            // Position moon using its orbit angle
            moon.position.set(
                Math.cos(moon.userData.moonOrbitAngle) * moonDistance,
                0,
                Math.sin(moon.userData.moonOrbitAngle) * moonDistance
            );
            planetGroup.add(moon);
        }
    }

    return planetGroup;
}

// Start the application when DOM is ready
document.addEventListener('DOMContentLoaded', init);
