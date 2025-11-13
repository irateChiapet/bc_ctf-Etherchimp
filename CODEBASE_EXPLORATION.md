# EtherChimp Codebase Exploration Report

## 1. PROJECT OVERVIEW

**Project Name:** EtherChimp (PCAP Network Traffic Analyzer)
**Type:** Real-time network traffic visualization and analysis tool
**Technology Stack:**
- **Backend:** Python 3.13 with Flask and Flask-SocketIO
- **Frontend:** JavaScript (Vanilla JS, no frameworks)
- **Packet Processing:** Scapy library for packet capture and analysis
- **Visualization:** HTML5 Canvas (2D/3D network graph visualization)
- **Real-time Communication:** WebSocket (Socket.IO)

**Key Dependencies:**
- Flask 3.1.2 - Web framework
- Flask-SocketIO 5.5.1 - WebSocket support for real-time updates
- Scapy 2.6.1 - Packet capture and parsing
- Python-SocketIO 5.14.1 - WebSocket protocol implementation

---

## 2. PROJECT STRUCTURE

```
/opt/bc_ctf-Etherchimp/
├── app.py                          # Main Flask application entry point
├── templates/
│   └── run.html                    # Main UI HTML template
├── static/
│   ├── css/
│   │   └── styles.css             # Complete styling (2111 lines)
│   ├── js/
│   │   ├── app.js                 # Main application (4720 lines)
│   │   └── modules/               # Modular JavaScript components
│   │       ├── pcap-parser.js     # PCAP binary format parsing
│   │       ├── ui-updaters.js     # UI state management functions
│   │       ├── search-handler.js  # Search functionality
│   │       ├── timeline-controller.js # Timeline control logic
│   │       ├── stream-manager.js  # TCP/HTTP stream management
│   │       ├── file-handler.js    # File upload handling
│   │       └── packet-formatters.js # Packet data formatting
│   └── etherchimp.png             # Application logo
├── backend/
│   ├── routes/
│   │   └── api.py                # Flask routes & SocketIO handlers (247 lines)
│   ├── processing/
│   │   ├── pcap_processor.py     # PCAP file processing (219 lines)
│   │   ├── live_capture.py       # Live packet capture (376 lines)
│   │   ├── remote_capture.py     # Remote SSH-based capture
│   │   └── threat_detection.py   # Security threat detection
│   └── utils/
│       ├── helpers.py            # Utility functions
│       └── ip_filters.py         # IP filtering logic
├── uploads/                        # Directory for uploaded/captured PCAP files
└── requirements.txt               # Python dependencies

```

---

## 3. DASHBOARD PANELS AND UI COMPONENTS

### 3.1 LEFT SIDEBAR PANEL

**Location:** `#sidebar` (fixed 300px width, left side)
**File:** `/opt/bc_ctf-Etherchimp/templates/run.html` (lines 11-84)
**CSS:** `/opt/bc_ctf-Etherchimp/static/css/styles.css`

**Components:**
1. **Header Section** (lines 12-16)
   - EtherChimp logo and subtitle
   - Real-time Network Traffic Analysis

2. **Upload Section** (lines 19-26)
   - Drag-and-drop PCAP file upload area
   - File input for browsing

3. **Traffic Overview Stats** (lines 28-43)
   - Total Packets (`#totalPackets`)
   - Unique Hosts (`#uniqueHosts`)
   - Active Connections (`#activeConnections`)

4. **Data Analysis Stats** (lines 45-59)
   - Total Volume in MB (`#dataVolume`)
   - Average Packet Size in bytes (`#avgPacketSize`)
   - Protocols Detected (`#protocolCount`)

5. **Security Alerts Section** (lines 62-72)
   - Alert count display (`#alertCount`)
   - Alerts list (`#alertsList`)
   - Expandable alerts panel (`#alertsPanel`)

**CSS Styling:**
- Background: White gradient (#fff to #f0f0f0), Dark mode: #0a0a0a
- Width: 300px, flex layout, overflow-y: auto
- Border-right: 1px solid #ddd
- Smooth transitions for sidebar hide/show

**Update Mechanism:**
- Function: `updateStats()` in ui-updaters.js
- Called via: `scheduleUIUpdate()` which uses `requestAnimationFrame`
- Triggered on: File upload completion, live packet batch arrival
- Updates stats from `parser.summary` object populated from backend

---

### 3.2 BOTTOM-LEFT INFO PANEL

**Location:** Bottom-left corner of canvas area
**Element ID:** `#infoPanel`
**Position:** Absolute, `bottom: 20px; left: 20px;`
**File:** `templates/run.html` (lines 195-219)
**CSS:** `styles.css` (lines 1238-1254)

**Components:**
1. **Real-time Metrics Section** (lines 196-214)
   - Packets/sec (`#packetsPerSec`)
   - Bandwidth (`#bandwidth`) - in Mbps
   - Active Flows (`#activeFlows`)
   - Threats (`#threats`) - Red text color

2. **Selected Packet Data Section** (lines 215-218)
   - Hidden by default
   - Displays detailed packet information when node selected
   - Max-height: 200px with scroll
   - Monospace font, small size (11px)

**Styling:**
- Background: rgba(255,255,255,0.95) with backdrop blur
- Border: 1px solid #ccc
- Padding: 16px
- Min-width: 300px
- Border-radius: 12px
- Dark mode: rgba(0,0,0,0.9) with border #333

**Update Mechanism:**
- Updates via `updateStats()` function
- Data source: `parser.summary` object
- Metric calculations:
  - Packets/sec = total packets / duration
  - Bandwidth = (total bytes * 8 / duration) / 1,000,000 Mbps
  - Active Flows = number of unique connections
  - Threats = number of security alerts detected

**Update Frequency:**
- File mode: Single update after file processing completes
- Live mode: Updates on every `packet_batch` event from backend
- Backend batch interval: 2 seconds

---

### 3.3 BOTTOM-RIGHT TIMELINE PANEL

**Location:** Bottom-right corner of canvas area
**Element ID:** `#timelineContainer`
**Position:** Absolute, `bottom: 20px; right: 20px;`
**File:** `templates/run.html` (lines 254-268)
**CSS:** `styles.css` (lines 1965-2090)

**Components:**
1. **Timeline Header** (lines 255-257)
   - Title: "Timeline"
   - Current time display (`#timelineTime`)

2. **Timeline Slider** (lines 259-262)
   - Progress bar with gradient (#0099ff to #00d4ff)
   - Draggable handle (16px circle)
   - Smooth width transition (0.1s)

3. **Timeline Labels** (lines 264-267)
   - Start time (`#timelineStart`)
   - End time (`#timelineEnd`)
   - Format: 0.00s

**Styling:**
- Background: rgba(255,255,255,0.95) with backdrop blur
- Min-width: 400px
- Hidden by default (display: none)
- Activated with `.active` class
- Dark mode compatible

**Visibility:**
- Hidden in file mode (for static PCAP analysis)
- Activated in live capture mode via JavaScript
- Class toggle: `#timelineContainer.classList.add('active')`

**Update Mechanism:**
- TimelineController class manages timeline state
- Updates via: `updateUI()` method
- Tracks: Packet timestamps, playback position, packet filtering
- Slider updates on packet arrival and timeline scrubbing

**Interaction:**
- Click/drag slider to scrub through packets
- Display packets filtered by time range
- Updates network graph based on timeline position

---

## 4. REAL-TIME UPDATE MECHANISMS

### 4.1 WebSocket Communication (Socket.IO)

**Backend Setup:**
- File: `/opt/bc_ctf-Etherchimp/backend/routes/api.py` (lines 79-247)
- SocketIO instance created in `app.py` (line 18)
- Configuration: `SocketIO(app, cors_allowed_origins="*")`

**Event Handlers (Frontend Listeners):**

1. **`packet_batch` Event** (lines 4430-4626)
   - **Frequency:** Every 2 seconds from backend
   - **Data Includes:**
     - Packets array (limited to 100 per batch)
     - Pre-aggregated nodes with stats
     - Pre-aggregated edges (connections)
     - DNS cache updates
     - Statistics summary
   - **Processing:**
     - Updates visualizer nodes and edges
     - Filters for max 500 nodes to prevent performance issues
     - Stores packets in visualizer and parser
     - Limits stored packets to 10,000 maximum
   - **UI Updates:** Calls `scheduleUIUpdate()`

2. **`capture_started` Event** (lines 4332-4366, 4630-4638)
   - Emitted when live capture begins
   - Enables live mode flag
   - Shows save capture button
   - Initializes NetworkVisualizer if needed
   - Starts stream list update interval (1 second)

3. **`capture_stopped` Event** (lines 4369-4380, 4640-4645)
   - Disables live mode
   - Hides save capture button
   - Clears stream update interval

4. **`capture_restarted` Event** (lines 4383-4403, 4647-4655)
   - Clears visualization data (nodes, edges, packets)
   - Resets parser data
   - Shows restart notification

5. **`interface_ready` Event** (lines 4323-4329)
   - Auto-starts live capture when interface configured

6. **`pcap_saved` Event** (lines 4406-4408, 4697-4700)
   - Confirms PCAP file save with filename and packet count

7. **`capture_error` Event** (lines 4685-4694)
   - Handles capture errors
   - Disables live mode on error

---

### 4.2 Polling Mechanisms (setInterval)

**File:** `/opt/bc_ctf-Etherchimp/static/js/app.js`

1. **Stream List Update Loop** (lines 4633-4637)
   - Interval: 1 second
   - Function: `populateLiveStreamList(visualizer.edges)`
   - Active during: Live capture
   - Purpose: Keep TCP/HTTP stream list fresh

2. **Playback/Animation Loop** (line 3163)
   - Used during timeline playback animation
   - Automatically managed by `setInterval` in play mode

---

### 4.3 RequestAnimationFrame for UI Updates

**File:** `/opt/bc_ctf-Etherchimp/static/js/app.js` (lines 4416-4427)

```javascript
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
```

**Purpose:**
- Batches UI updates for optimal rendering performance
- Prevents excessive DOM manipulation
- Synchronized with browser refresh rate (60fps)

---

## 5. DATA FLOW FOR METRICS AND TRAFFIC

### 5.1 File Upload Mode Data Flow

```
1. User uploads PCAP file
   ↓
2. /upload endpoint called (api.py, line 52)
   ↓
3. pcap_processor.process_pcap() (pcap_processor.py, line 11)
   ├─ Reads PCAP file with Scapy
   ├─ Parses each packet
   ├─ Extracts IPs, ports, protocols, MACs
   ├─ Tracks threats
   ├─ Aggregates statistics
   ↓
4. Returns JSON response with:
   {
     'summary': {
       'totalPackets': int,
       'uniqueHosts': int,
       'activeConnections': int,
       'dataVolumeMB': float,
       'avgPacketSize': int,
       'protocolCount': int,
       'packetsPerSec': int,
       'bandwidthMbps': float,
       'threatsFound': int
     },
     'hosts': [...],
     'connections': [...],
     'packets': [...],
     'alerts': [...]
   }
   ↓
5. Frontend receives JSON via fetch
   ↓
6. parser.summary = response.summary
   ↓
7. updateStats() reads parser.summary
   ↓
8. Updates all #stat-value elements with localized numbers
```

### 5.2 Live Capture Mode Data Flow

```
1. User clicks play or auto-start on configured interface
   ↓
2. emit('start_capture', {}) sent to backend
   ↓
3. Backend creates LiveCapture instance (live_capture.py)
   ├─ Spawns capture thread
   ├─ Spawns batch sender thread (sends every 2 seconds)
   ├─ Spawns DNS resolver thread (if enabled)
   ↓
4. Packets captured via scapy.sniff()
   ├─ _process_packet() callback for each packet
   ├─ Extracts IP, port, protocol, MAC, timestamp
   ├─ Updates nodes dict (IP -> host data)
   ├─ Updates edges dict (IP pair -> connection data)
   ├─ Adds to packet_buffer
   ↓
5. Every 2 seconds: _batch_sender() emits 'packet_batch'
   ├─ Converts sets to lists for JSON serialization
   ├─ Includes up to 100 packets from buffer
   ├─ Includes all nodes with aggregated stats
   ├─ Includes all edges with aggregated stats
   ├─ Includes DNS cache with resolved hostnames
   ↓
6. Frontend receives 'packet_batch' event
   ├─ Updates visualizer.nodes map
   ├─ Updates visualizer.edges array
   ├─ Appends packets to parser.packets array
   ├─ Updates parser.hosts from node data
   ├─ Stores packets on node/edge objects for detail views
   ↓
7. scheduleUIUpdate() calls updateStats()
   ├─ Reads parser.summary (if available)
   ├─ Displays in #infoPanel and sidebar stats
   ↓
8. Continuous animation loop:
   - Canvas render at 60fps
   - Node physics simulation
   - Edge weight visualization
   - Particle effects for traffic
```

---

## 6. BACKEND ENDPOINTS AND DATA ENDPOINTS

**File:** `/opt/bc_ctf-Etherchimp/backend/routes/api.py`

### GET Endpoints

| Endpoint | Function | Returns |
|----------|----------|---------|
| `/` | Serves main HTML | `run.html` |
| `/autoload` | Checks for auto-load file | JSON: `{'autoload': bool}` or processed PCAP |
| `/test-search` | Debug search page | HTML test page |
| `/debug-search` | Debug search page | HTML debug page |

### POST Endpoints

| Endpoint | Function | Request | Returns |
|----------|----------|---------|---------|
| `/upload` | Upload PCAP file | multipart/form-data | JSON summary + hosts + connections + packets |

### WebSocket Events (SocketIO)

**Server Emits (Backend -> Frontend):**

| Event | Data | Trigger | Frequency |
|-------|------|---------|-----------|
| `interface_ready` | `{interface: string}` | Client connects with interface configured | Once on connect |
| `capture_started` | `{interface: string}` | Live capture starts | Once on start |
| `capture_stopped` | `{}` | Live capture stops | Once on stop |
| `capture_restarted` | `{interface: string}` | Capture saved and restarted | Once on restart |
| `pcap_saved` | `{filename: string, packet_count: int}` | PCAP file saved | Once per save |
| `packet_batch` | See data structure below | Live capture batching | Every 2 seconds |
| `capture_error` | `{error: string}` | Error occurs | On error |

**packet_batch Event Data Structure:**
```javascript
{
  packets: [
    {
      timestamp: float,
      source: IP,
      destination: IP,
      protocol: string,
      length: int,
      srcPort: int,
      dstPort: int,
      data: [bytes],
      sourceMac: string,
      destMac: string
    },
    ...
  ],
  count: int,
  nodes: [
    {
      ip: string,
      hostname: string|null,
      mac: string|null,
      packetsSent: int,
      packetsReceived: int,
      bytesSent: int,
      bytesReceived: int,
      protocols: [string],
      connections: int
    },
    ...
  ],
  edges: [
    {
      source: IP,
      destination: IP,
      protocol: string,
      packets: int,
      bytes: int
    },
    ...
  ],
  totalCaptured: int,
  dnsCache: { IP: hostname, ... },
  statistics: {
    uniqueHosts: int,
    activeConnections: int,
    totalPackets: int,
    totalNodes: int,
    totalEdges: int
  }
}
```

**Server Listens (Frontend -> Backend):**

| Event | Data | Handler | Effect |
|-------|------|---------|--------|
| `start_capture` | `{}` | handle_start_capture() | Starts LiveCapture or RemoteCapture |
| `stop_capture` | `{}` | handle_stop_capture() | Stops active capture |
| `save_and_restart_capture` | `{}` | handle_save_and_restart() | Saves PCAP and starts new session |
| `connect` | Auto | handle_connect() | Detects interface, emits interface_ready |

---

## 7. PARSER AND THREAT DETECTION

### PCAPParser Class (JavaScript)
**File:** `/opt/bc_ctf-Etherchimp/static/js/modules/pcap-parser.js`

**Properties:**
- `packets`: Array of parsed packet objects
- `hosts`: Map of IP -> host statistics
- `connections`: Map of connection key -> connection data
- `protocols`: Map of protocol name -> count
- `alerts`: Array of security alerts
- `summary`: Object with aggregated statistics

**Key Methods:**
- `parse(arrayBuffer, progressCallback)`: Parses PCAP binary format
- `parsePacket(data, ts_sec, ts_usec, orig_len)`: Parses individual packet
- `updateStats(packet)`: Updates all aggregated statistics
- `detectThreats(packet)`: Identifies security anomalies

### Threat Detection (JavaScript Implementation)
**Location:** `/opt/bc_ctf-Etherchimp/static/js/app.js` (lines 251-419)

**Threat Types Detected:**
1. **Port Scanning** - Source with 10+ unique destination ports
2. **IP Address Changes** - MAC/IP mapping changes (ARP spoofing indicator)
3. **Multiple IP Addresses** - Single MAC using 3+ different IPs
4. **Suspicious Port Activity** - Connections to backdoor ports (4444, 5555, 6666, 7777, 31337, 12345)
5. **ICMP Flooding** - 50+ ICMP packets in 1 second
6. **Connection Failures** - 20+ RST (TCP reset) packets

**Alert Structure:**
```javascript
{
  type: string,           // Alert category
  severity: 'high'|'medium'|'low',
  source: IP,
  destination: IP,
  port: int,
  protocol: string,
  timestamp: float,
  sourceMac: string,
  details: string         // Human-readable description
}
```

---

## 8. UI COMPONENTS AND INTERACTION

### Statistics Display (`#infoPanel`)
**CSS Classes Used:**
- `.info-panel` - Container (lines 1238-1254)
- `.info-title` - Section titles
- `.info-grid` - 2x2 grid layout
- `.info-item` - Individual metric card
- `.info-label` - Metric name
- `.info-value` - Metric value (color: #ff6b6b for threats)

**Real-time Metrics Displayed:**
- Packets/sec (updated from summary)
- Bandwidth in Mbps (calculated: (totalBytes * 8 / duration) / 1000000)
- Active Flows (equals active connections)
- Threats (red text, count of detected threats)

### Traffic Overview (`#sidebar .stats-container`)
**CSS Classes Used:**
- `.stats-container` - Scrollable container (flex: 1, overflow-y: auto)
- `.stat-group` - Groups of related stats
- `.stat-group-title` - Group headers (uppercase, small, gray)
- `.stat-card` - Individual stat display
- `.stat-label` - Stat description (11px, uppercase)
- `.stat-value` - Stat number (28px, bold, blue #0099ff)

**Display Values:**
- Total Packets (with comma localization)
- Unique Hosts (count)
- Active Connections (count)
- Total Volume (in MB, 2 decimal places)
- Average Packet Size (in bytes, rounded)
- Protocols Detected (count)

---

## 9. PERFORMANCE OPTIMIZATION STRATEGIES

### Memory Management
1. **Max Packets Stored:** 10,000 packets (MAX_PACKETS_STORED)
   - When exceeded: Remove oldest 1,000 packets
   
2. **Max Nodes:** 500 nodes (MAX_NODES)
   - Prevents visualization from becoming unusable
   
3. **Max Packets Per Batch:** 100 packets per 2-second batch
   - Limits network traffic and processing load
   
4. **Packet Limits Per Node/Edge:** 100 packets
   - For detail panel display

### Frontend Batching
- UI updates batched with `requestAnimationFrame`
- Only one update scheduled at a time
- Updates skip if no packets received

### Backend Aggregation
- Nodes and edges pre-aggregated on backend
- Only incremental updates sent every 2 seconds
- DNS resolution in background thread
- Threat detection in batch processing

### Visualization Optimization
- Canvas-based 2D/3D rendering
- Force-directed layout with physics simulation
- Particles system for traffic visualization
- Clustering for subnet grouping

---

## 10. KEY FILES REFERENCE

| File | Lines | Purpose |
|------|-------|---------|
| `/opt/bc_ctf-Etherchimp/app.py` | 102 | Flask app initialization, config, SocketIO setup |
| `/opt/bc_ctf-Etherchimp/templates/run.html` | 277 | Main UI layout (left sidebar + canvas area) |
| `/opt/bc_ctf-Etherchimp/static/css/styles.css` | 2111 | All styling for panels, dark mode, responsive |
| `/opt/bc_ctf-Etherchimp/static/js/app.js` | 4720 | Main application logic, visualizer, event handlers |
| `/opt/bc_ctf-Etherchimp/static/js/modules/ui-updaters.js` | 72 | updateStats() and updateAlerts() functions |
| `/opt/bc_ctf-Etherchimp/backend/routes/api.py` | 247 | Flask routes, SocketIO event handlers |
| `/opt/bc_ctf-Etherchimp/backend/processing/pcap_processor.py` | 219 | PCAP file parsing and aggregation |
| `/opt/bc_ctf-Etherchimp/backend/processing/live_capture.py` | 376 | Live packet capture with batching |

---

## 11. SUMMARY

The EtherChimp application provides real-time network traffic visualization with two main data display panels:

1. **Left Sidebar Panel** - Shows traffic overview statistics (packets, hosts, connections, volume, protocols) and security alerts. Updates automatically when PCAP loaded or during live capture.

2. **Bottom-Left Info Panel** - Displays real-time metrics (packets/sec, bandwidth, active flows, threats) with live updates every 2 seconds during capture.

3. **Bottom-Right Timeline Panel** - Shows timeline slider for PCAP playback (file mode) or live capture timestamp tracking.

The real-time update mechanism uses WebSocket (Socket.IO) with 2-second batch intervals for live capture, providing pre-aggregated data from the backend to prevent performance issues. All metrics are calculated and displayed with proper formatting (localization, units, color coding).

