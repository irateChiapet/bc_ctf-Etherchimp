# EtherChimp Quick Reference Guide

## Panel Locations & Element IDs

### Left Sidebar (Fixed 300px Width)

```
#sidebar
├─ #totalPackets         → Total Packets stat value
├─ #uniqueHosts          → Unique Hosts stat value
├─ #activeConnections    → Active Connections stat value
├─ #dataVolume           → Total Volume in MB
├─ #avgPacketSize        → Average Packet Size
├─ #protocolCount        → Protocols Detected count
├─ #alertCount           → Security Alerts badge
├─ #alertsList           → Recent alerts list (scrollable)
└─ #alertsPanel          → Expandable full alerts panel
```

### Bottom-Left Info Panel

```
#infoPanel (position: absolute; bottom: 20px; left: 20px)
├─ #packetsPerSec        → Packets per second metric
├─ #bandwidth            → Bandwidth in Mbps
├─ #activeFlows          → Active flows count
├─ #threats              → Threats found (red text)
└─ #packetDataSection    → Selected packet details (hidden by default)
```

### Bottom-Right Timeline Panel

```
#timelineContainer (position: absolute; bottom: 20px; right: 20px)
├─ #timelineTime         → Current time display
├─ #timelineSlider       → Draggable slider
├─ #timelineProgress     → Progress bar (0-100%)
├─ #timelineStart        → Start time label
└─ #timelineEnd          → End time label
```

---

## Update Functions Quick Lookup

### Main UI Update Functions

| Function | File | Lines | Purpose |
|----------|------|-------|---------|
| `updateStats()` | ui-updaters.js | 1-38 | Updates all stat values from parser.summary |
| `updateAlerts()` | ui-updaters.js | 40-71 | Refreshes alert list with latest alerts |
| `updateUI()` | app.js | 3109+ | Timeline-specific updates |
| `scheduleUIUpdate()` | app.js | 4416-4427 | Batches updates with requestAnimationFrame |

### Update Trigger Points

```
File Upload Mode:
├─ fetch('/upload')
│  ├─ Receives JSON response
│  ├─ parser.summary = response.summary
│  └─ updateStats() called once

Live Capture Mode:
├─ socket.on('packet_batch')
│  ├─ Updates visualizer.nodes
│  ├─ Updates visualizer.edges
│  ├─ Updates parser.packets
│  └─ scheduleUIUpdate() called
│
└─ Every 2 seconds (batch interval)
```

---

## Metric Calculations

### From Backend (Preferred in Live Mode)

```javascript
parser.summary = {
  totalPackets: response.summary.totalPackets,
  uniqueHosts: response.summary.uniqueHosts,
  activeConnections: response.summary.activeConnections,
  dataVolumeMB: response.summary.dataVolumeMB,
  avgPacketSize: response.summary.avgPacketSize,
  protocolCount: response.summary.protocolCount,
  packetsPerSec: response.summary.packetsPerSec,
  bandwidthMbps: response.summary.bandwidthMbps,
  threatsFound: response.summary.threatsFound
}
```

### Calculations Used

```javascript
// Bandwidth (Mbps)
bandwidthMbps = (totalBytes * 8 / durationSeconds) / 1,000,000

// Packets per second
packetsPerSec = totalPackets / durationSeconds

// Average packet size
avgPacketSize = totalBytes / totalPackets

// Data volume
dataVolumeMB = totalBytes / 1,048,576
```

---

## Socket.IO Events

### Listen (Frontend receives)

```javascript
socket.on('packet_batch', (data) => {
  // Frequency: Every 2 seconds
  // data.packets - array of up to 100 packets
  // data.nodes - pre-aggregated host nodes
  // data.edges - pre-aggregated connections
  // data.statistics - summary stats
  // data.dnsCache - resolved hostnames
})

socket.on('capture_started', (data) => {
  // Frequency: Once on capture start
  // data.interface - interface name
})

socket.on('capture_stopped', () => {
  // Frequency: Once on capture stop
})

socket.on('interface_ready', (data) => {
  // Frequency: Once on connection if interface configured
  // Auto-starts capture
})

socket.on('capture_error', (data) => {
  // Frequency: On error
  // data.error - error message
})
```

### Emit (Frontend sends)

```javascript
socket.emit('start_capture', {})  // Start live capture
socket.emit('stop_capture', {})   // Stop live capture
socket.emit('save_and_restart_capture', {})  // Save & restart
```

---

## CSS Classes for Styling

### Panel Styling

```css
/* Info Panel */
.info-panel { position: absolute; bottom: 20px; left: 20px; }
.info-title { font-size: 14px; font-weight: 700; }
.info-grid { display: grid; grid-template-columns: 1fr 1fr; }
.info-item { text-align: center; }
.info-label { font-size: 11px; color: #666; }
.info-value { font-size: 18px; font-weight: 700; color: #0099ff; }

/* Timeline Panel */
.timeline-container { position: absolute; bottom: 20px; right: 20px; }
.timeline-container.active { display: block; }
.timeline-slider { width: 100%; height: 6px; background: #e0e0e0; }
.timeline-progress { background: linear-gradient(90deg, #0099ff 0%, #00d4ff 100%); }
.timeline-handle { width: 16px; height: 16px; cursor: grab; }

/* Sidebar Stats */
.stat-card { padding: 16px; border-radius: 8px; margin-bottom: 12px; }
.stat-value { font-size: 28px; font-weight: 700; color: #0099ff; }
.stat-label { font-size: 11px; text-transform: uppercase; color: #666; }
```

### Dark Mode Support

```css
body.dark-mode {
  background: #000;
  color: #fff;
}

body.dark-mode #sidebar {
  background: linear-gradient(180deg, #0a0a0a 0%, #1a1a1a 100%);
}

body.dark-mode .info-panel {
  background: rgba(0,0,0,0.9);
  border: 1px solid #333;
}

body.dark-mode .timeline-container {
  background: rgba(0,0,0,0.9);
  border: 1px solid #333;
}
```

---

## Backend Endpoints Summary

### HTTP Endpoints

```
GET  /                 → Serves run.html
GET  /autoload         → Returns autoload config
POST /upload           → Process PCAP file

Response format for /upload:
{
  summary: {
    totalPackets: int,
    uniqueHosts: int,
    activeConnections: int,
    dataVolumeMB: float,
    avgPacketSize: int,
    protocolCount: int,
    packetsPerSec: int,
    bandwidthMbps: float,
    threatsFound: int
  },
  hosts: [{ ip, hostname, mac, packetsSent, packetsReceived, ... }],
  connections: [{ source, destination, protocol, packets, bytes, ... }],
  packets: [{ timestamp, source, destination, protocol, length, ... }],
  alerts: [{ type, severity, source, destination, details, ... }]
}
```

### WebSocket (SocketIO) Endpoints

**From Server:**
- `packet_batch` - Every 2 seconds (live mode)
- `capture_started` - On capture start
- `capture_stopped` - On capture stop
- `capture_restarted` - On save and restart
- `interface_ready` - On connection (if interface configured)
- `pcap_saved` - When PCAP file saved
- `capture_error` - On error

**To Server:**
- `start_capture` - Request capture start
- `stop_capture` - Request capture stop
- `save_and_restart_capture` - Save current and start new
- `connect` - Auto-sent by Socket.IO

---

## Global Variables

```javascript
// Parser instance
const parser = new PCAPParser();
parser.summary = {};
parser.packets = [];
parser.hosts = new Map();
parser.connections = new Map();
parser.protocols = new Map();
parser.alerts = [];

// Visualizer instance
const visualizer = new NetworkVisualizer(canvas);
visualizer.nodes = new Map();
visualizer.edges = [];
visualizer.allPackets = [];

// Socket connection
const socket = io();

// Mode tracking
let liveMode = false;

// Update scheduling
let updateScheduled = false;
```

---

## Common Data Structures

### Packet Object

```javascript
{
  timestamp: float,        // Unix timestamp
  source: string,          // Source IP
  destination: string,     // Destination IP
  protocol: string,        // 'TCP', 'UDP', 'HTTP', 'HTTPS', 'DNS', etc.
  length: int,             // Packet size in bytes
  srcPort: int,            // Source port (0 if no port)
  dstPort: int,            // Destination port (0 if no port)
  sourceMac: string,       // MAC address (if available)
  destMac: string,         // MAC address (if available)
  data: [bytes]            // Raw packet data
}
```

### Host/Node Object

```javascript
{
  ip: string,
  hostname: string,        // Resolved DNS name (null if not resolved)
  mac: string,             // MAC address (null if unknown)
  packetsSent: int,
  packetsReceived: int,
  bytesSent: int,
  bytesReceived: int,
  protocols: Set,          // Set of protocols observed
  connections: int         // Number of unique connections
}
```

### Connection/Edge Object

```javascript
{
  source: string,          // Source IP
  destination: string,     // Destination IP
  protocol: string,        // Protocol name
  packets: int,            // Total packets in connection
  bytes: int,              // Total bytes in connection
  startTime: float,        // Unix timestamp of first packet
  lastTime: float          // Unix timestamp of last packet
}
```

### Alert Object

```javascript
{
  type: string,            // Alert category
  severity: string,        // 'high', 'medium', 'low'
  source: string,          // Source IP
  destination: string,     // Destination IP
  port: int,               // Port involved (if applicable)
  protocol: string,        // Protocol
  timestamp: float,        // When detected
  sourceMac: string,       // MAC address
  details: string          // Human-readable description
}
```

---

## Performance Limits

```javascript
const MAX_PACKETS_STORED = 10000;    // Limit total stored packets
const MAX_NODES = 500;               // Limit nodes in visualizer
const MAX_PACKETS_PER_BATCH = 100;   // Packets per batch event
```

**Management:**
- When MAX_PACKETS_STORED exceeded: Remove oldest 1,000
- When MAX_NODES exceeded: New nodes not created
- Per-node packet limit: 100 packets
- Per-edge packet limit: 100 packets

---

## File Upload vs Live Capture

```
FILE UPLOAD:
├─ User drops PCAP file
├─ POST /upload to backend
├─ Backend parses entire file
├─ Returns summary + all data
├─ updateStats() called once
├─ Sidebar displays static stats
└─ Timeline panel hidden

LIVE CAPTURE:
├─ Interface configured
├─ emit('start_capture')
├─ Backend streams packet_batch every 2s
├─ Frontend updates every 2s
├─ scheduleUIUpdate() called per batch
├─ Sidebar updates continuously
├─ Timeline panel visible and updates
└─ Can pause/resume with play button
```

---

## Debugging Tips

### Check Live Mode Status

```javascript
console.log('Live mode:', liveMode);
console.log('Visualizer nodes:', visualizer.nodes.size);
console.log('Stored packets:', parser.packets.length);
console.log('Summary:', parser.summary);
```

### Monitor Socket Events

```javascript
socket.onAny((event, ...args) => {
  console.log('Socket event:', event, args);
});
```

### View DOM Elements

```javascript
// Check sidebar stats visibility
document.getElementById('totalPackets').textContent

// Check info panel visibility
document.getElementById('infoPanel').style.display

// Check timeline panel
document.getElementById('timelineContainer').classList.contains('active')
```

### Check Backend Logs

```bash
# Flask console output shows:
# - [Backend] Client connected to WebSocket
# - [LiveCapture] Captured N packets
# - [DNS] Resolved IP -> hostname
# - [LiveCapture] Sending batch: X packets, Y unique hosts
```

---

## Common Modifications

### Change Batch Interval

**Backend File:** `/opt/bc_ctf-Etherchimp/backend/processing/live_capture.py`

```python
self.batch_interval = 2  # Change to 1, 3, 5, etc. seconds
```

### Change Max Nodes

**Frontend File:** `/opt/bc_ctf-Etherchimp/static/js/app.js`

```javascript
const MAX_NODES = 500;  // Change to 1000, 200, etc.
```

### Change Max Packets

**Frontend File:** `/opt/bc_ctf-Etherchimp/static/js/app.js`

```javascript
const MAX_PACKETS_STORED = 10000;  // Change to 5000, 20000, etc.
```

### Change Panel Position

**CSS File:** `/opt/bc_ctf-Etherchimp/static/css/styles.css`

```css
/* Info Panel - line 1240 */
.info-panel {
  bottom: 20px;  /* Change to move vertically */
  left: 20px;    /* Change to move horizontally */
}

/* Timeline Panel - line 1968 */
.timeline-container {
  bottom: 20px;  /* Change to move vertically */
  right: 20px;   /* Change to move horizontally */
}
```

