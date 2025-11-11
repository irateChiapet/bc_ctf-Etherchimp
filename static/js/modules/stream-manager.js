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
