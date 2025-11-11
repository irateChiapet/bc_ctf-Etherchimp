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
