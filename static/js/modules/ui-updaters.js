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
