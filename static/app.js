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
        updateConnectionStatus('Connected', true);
    };

    ws.onmessage = function(event) {
        const data = JSON.parse(event.data);
        throttledUpdateGraph(data);
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

// Start the application when DOM is ready
document.addEventListener('DOMContentLoaded', init);
