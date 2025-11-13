# EtherChimp Architecture Overview

## High-Level System Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                          USER INTERFACE (Browser)                       │
│                                                                         │
│  ┌──────────────────┐    ┌──────────────────────────────────────────┐ │
│  │  LEFT SIDEBAR    │    │   CANVAS VISUALIZATION AREA              │ │
│  │  (300px fixed)   │    │                                          │ │
│  │                  │    │  ┌────────────────────────────────────┐ │ │
│  │  • Header        │    │  │   Network Graph Visualization      │ │ │
│  │  • Upload Area   │    │  │   (Force-directed, 2D/3D)          │ │ │
│  │  • Stats Cards   │    │  │                                    │ │ │
│  │  • Alerts Panel  │    │  │   ┌──────────────┐                │ │ │
│  │                  │    │  │   │ INFO PANEL   │ Bottom-Left    │ │ │
│  │  Updates via:    │    │  │   │ (Real-time   │                │ │ │
│  │  updateStats()   │    │  │   │  metrics)    │                │ │ │
│  │                  │    │  │   └──────────────┘                │ │ │
│  │  Frequency:      │    │  │                                    │ │ │
│  │  • File: Once    │    │  │  ┌──────────────────────────────┐ │ │
│  │  • Live: 2s      │    │  │  │  TIMELINE PANEL              │ │ │
│  │                  │    │  │  │  (Bottom-right, live mode)   │ │ │
│  │                  │    │  │  └──────────────────────────────┘ │ │
│  └──────────────────┘    │  └────────────────────────────────────┘ │
│                          │                                          │
│    Updates scheduled     │  Canvas renders at 60fps                │
│    via requestAnimFrame  │  Physics simulation                     │
└─────────────────────────────────────────────────────────────────────────┘
                                     △
                                     │
                          WebSocket (Socket.IO)
                                     │
                         ◇ packet_batch (2s)
                         ◇ capture_started
                         ◇ capture_stopped
                         ◇ capture_restarted
                         ◇ interface_ready
                         ◇ pcap_saved
                                     │
                                     ▽
┌─────────────────────────────────────────────────────────────────────────┐
│                    FLASK BACKEND (Python 3.13)                          │
│                                                                         │
│  ┌─────────────────────────────────────────────────────────────────┐  │
│  │  Flask Application (app.py)                                      │  │
│  │  ├─ Route: GET /              → Serves run.html                 │  │
│  │  ├─ Route: POST /upload       → Processes PCAP file             │  │
│  │  ├─ Route: GET /autoload      → Auto-load PCAP                 │  │
│  │  └─ SocketIO: Real-time events                                 │  │
│  └─────────────────────────────────────────────────────────────────┘  │
│                                                                         │
│  ┌──────────────────────┐         ┌──────────────────────────────┐   │
│  │  FILE UPLOAD PATH    │         │   LIVE CAPTURE PATH          │   │
│  │                      │         │                              │   │
│  │ 1. User uploads      │         │ 1. Interface configured      │   │
│  │    PCAP file         │         │                              │   │
│  │         ↓            │         │ 2. emit('start_capture')     │   │
│  │ 2. /upload endpoint  │         │         ↓                    │   │
│  │         ↓            │         │ 3. LiveCapture spawned:      │   │
│  │ 3. pcap_processor    │         │    • Capture thread          │   │
│  │    .process_pcap()   │         │    • Batch sender (2s)       │   │
│  │         ↓            │         │    • DNS resolver            │   │
│  │ 4. Parse packets     │         │         ↓                    │   │
│  │    Extract IPs       │         │ 4. Packets captured via      │   │
│  │    Calc stats        │         │    scapy.sniff()             │   │
│  │         ↓            │         │         ↓                    │   │
│  │ 5. Return JSON       │         │ 5. Batch aggregation         │   │
│  │    {summary, hosts,  │         │    emit('packet_batch')      │   │
│  │     connections,     │         │         ↓                    │   │
│  │     packets, alerts} │         │ 6. Frontend receives batch   │   │
│  │                      │         │                              │   │
│  └──────────────────────┘         └──────────────────────────────┘   │
│                                                                         │
│  Shared Data Sources:                                                  │
│  • pcap_processor.py (219 lines) - Packet parsing                     │
│  • live_capture.py (376 lines)   - Live capture                       │
│  • threat_detection.py           - Security alerts                    │
│  • ip_filters.py                 - IP filtering                       │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Data Flow Diagram: File Upload Mode

```
USER BROWSER                          BACKEND SERVER                    FILESYSTEM
    │                                    │                               │
    ├─ Select PCAP file                 │                               │
    │                                    │                               │
    ├─ Drop on #uploadArea               │                               │
    │                                    │                               │
    ├─ POST /upload (multipart)         │                               │
    ├────────────────────────────────────>                               │
    │                                    ├─ secure_filename()            │
    │                                    ├─ Save to /uploads/            │
    │                                    ├────────────────────────────────>
    │                                    │                               
    │                                    ├─ pcap_processor.process_pcap()
    │                                    │   ├─ rdpcap(filepath)
    │                                    │   ├─ Parse PCAP header
    │                                    │   ├─ Iterate packets:
    │                                    │   │  ├─ Extract Ethernet layer
    │                                    │   │  ├─ Extract IP layer
    │                                    │   │  ├─ Extract TCP/UDP ports
    │                                    │   │  ├─ Extract MAC addresses
    │                                    │   │  ├─ Detect protocol
    │                                    │   │  ├─ Update stats
    │                                    │   │  └─ Run threat detection
    │                                    │   ├─ Aggregate hosts data
    │                                    │   ├─ Aggregate connections
    │                                    │   └─ Calculate summary metrics
    │                                    │
    │                        JSON Response
    │<────────────────────────────────────
    │ {
    │   summary: {
    │     totalPackets, uniqueHosts,
    │     activeConnections, dataVolumeMB,
    │     avgPacketSize, protocolCount,
    │     packetsPerSec, bandwidthMbps,
    │     threatsFound
    │   },
    │   hosts: [...],
    │   connections: [...],
    │   packets: [...],
    │   alerts: [...]
    │ }
    │
    ├─ Store in parser.summary
    │
    ├─ Call updateStats()
    │
    ├─ Update DOM elements:
    │  ├─ #totalPackets.textContent
    │  ├─ #uniqueHosts.textContent
    │  ├─ #dataVolume.textContent
    │  ├─ #packetsPerSec.textContent
    │  ├─ #bandwidth.textContent
    │  └─ #threats.textContent
    │
    └─ Display results in UI
```

---

## Data Flow Diagram: Live Capture Mode

```
LIVE INTERFACE              BACKEND CAPTURE              WEBSOCKET                FRONTEND
      │                            │                         │                      │
      ├─ Packets flowing────────>┤                         │                      │
      │                      ┌─ Capture thread           │                      │
      │                      ├─ Buffer packets           │                      │
      │                      │  (add to packet_buffer)   │                      │
      │                      │                           │                      │
      │                      ├──────────────────────────────────────────────────>│
      │                      │   emit('packet_batch')    │                      │
      │                      │   Every 2 seconds         │                      │
      │                      │   Contains:               │                      │
      │                      │   • packets: [up to 100]  │                      │
      │                      │   • nodes: [aggregated]   │                      │
      │                      │   • edges: [aggregated]   │                      │
      │                      │   • dnsCache: {}          │                      │
      │                      │   • statistics: {}        │                      │
      │                      │                           │                      │
      │                      │                           │      Process batch:  │
      │                      │                           │      ├─ Update nodes
      │                      │                           │      ├─ Update edges
      │                      │                           │      ├─ Store packets
      │                      │                           │      ├─ Update parser
      │                      │                           │      └─ Schedule UI
      │                      │                           │         update
      │                      │                           │
      │                      │    Parallel: DNS thread   │      Update DOM:      │
      │                      ├────────────────────────────────>├─ #totalPackets
      │                      │    resolve() → dns_cache │      ├─ #packetsPerSec
      │                      │                           │      ├─ #bandwidth
      │                      │    Parallel: Threat       │      ├─ #activeFlows
      │                      │    detection              │      └─ #threats
      │                      │                           │
      │                      │    Parallel: MAC/IP       │      Redraw canvas:   │
      │                      │    tracking               │      ├─ Render nodes
      │                      │                           │      ├─ Render edges
      │                      │                           │      └─ Update particles
      │                      │                           │
      │    Continuous        │    Continuous            │      60fps animation   │
      │    packet flow       │    batching               │      requestAnimFrame  │
      │                      │                           │                        │
      └──────────────────────┴───────────────────────────┴────────────────────────┘
```

---

## Frontend Data State Management

```
PCAPParser Instance (Global: parser)
│
├─ .packets: []                    ← Stores all parsed packets
│  └─ limit: 10,000 packets
│     (older packets removed when exceeded)
│
├─ .hosts: Map<IP, HostData>      ← Aggregated host statistics
│  └─ HostData: {
│       ip, packetsSent, packetsReceived,
│       bytesSent, bytesReceived,
│       protocols: Set, connections: Set
│     }
│
├─ .connections: Map               ← Aggregated connection statistics
│  └─ ConnData: {
│       source, destination, protocol,
│       packets, bytes,
│       startTime, lastTime
│     }
│
├─ .alerts: []                     ← Security alerts detected
│  └─ AlertData: {
│       type, severity, source, destination,
│       protocol, timestamp, details
│     }
│
└─ .summary: {                     ← Aggregated metrics
     totalPackets, uniqueHosts,
     activeConnections, dataVolumeMB,
     avgPacketSize, protocolCount,
     duration, packetsPerSec,
     bandwidthMbps, threatsFound
   }

NetworkVisualizer Instance (Global: visualizer)
│
├─ .nodes: Map<IP, NodeObject>    ← Visual nodes for canvas
│  └─ NodeObject: {
│       ip, hostname, mac, x, y, z,
│       vx, vy, vz, radius,
│       packetsSent, packetsReceived,
│       bytesSent, bytesReceived,
│       protocols: Set, connections: int,
│       packets: [], lastActivity
│     }
│
├─ .edges: []                      ← Visual edges for canvas
│  └─ EdgeObject: {
│       key, source, target,
│       protocol, weight (packets),
│       bytes, packets: []
│     }
│
├─ .allPackets: []                 ← All packets for detail views
│  └─ limit: 10,000 packets
│
├─ .camera: {x, y, zoom}          ← Camera position for canvas
├─ .rotation: {x, y}              ← 3D rotation state
└─ .selectedNode/selectedEdge      ← Currently selected element
```

---

## UI Update Frequency Comparison

```
┌─────────────────────┬──────────────────┬─────────────────┬──────────────────┐
│ Component           │ File Mode        │ Live Mode       │ Update Mechanism │
├─────────────────────┼──────────────────┼─────────────────┼──────────────────┤
│ Sidebar Stats       │ 1x (on load)     │ Every 2s        │ scheduleUIUpdate │
│ Info Panel Metrics  │ 1x (on load)     │ Every 2s        │ packet_batch evt │
│ Network Graph       │ Drawn once       │ 60fps           │ requestAnimFrame │
│ Threat Alerts       │ 1x (on load)     │ Real-time       │ updateAlerts()   │
│ Stream List         │ N/A              │ Every 1s        │ setInterval(1s)  │
│ Timeline Panel      │ Hidden           │ Every 2s        │ updateUI()       │
│ Canvas Render       │ Once on load     │ Continuous 60fps│ animation loop   │
└─────────────────────┴──────────────────┴─────────────────┴──────────────────┘
```

---

## Performance Optimization Points

```
FRONTEND OPTIMIZATIONS:
├─ scheduleUIUpdate() 
│  └─ Batches DOM updates via requestAnimationFrame
│     (prevents thrashing)
│
├─ MAX_PACKETS_STORED = 10,000
│  └─ Trims oldest 1,000 packets when exceeded
│
├─ MAX_NODES = 500
│  └─ Prevents graph from becoming too dense
│
├─ MAX_PACKETS_PER_BATCH = 100
│  └─ Limits packets per 2-second batch
│
└─ Canvas-based rendering
   └─ Much faster than DOM for thousands of nodes

BACKEND OPTIMIZATIONS:
├─ Pre-aggregation on backend
│  └─ Sends nodes/edges instead of all packets
│
├─ Batch sender thread (2s interval)
│  └─ Combines packets into single event
│
├─ DNS resolution in background thread
│  └─ Doesn't block packet capture
│
├─ Threat detection in-stream
│  └─ No separate processing pass
│
└─ Scapy packet callback
   └─ Process as captured, not in batch

NETWORK OPTIMIZATIONS:
├─ WebSocket instead of polling
│  └─ Bi-directional, lower latency
│
├─ 2-second batching
│  └─ Reduces event frequency 60x vs per-packet
│
├─ Pre-aggregated nodes/edges
│  └─ Much smaller payload vs full packets
│
└─ DNS cache sharing
   └─ Avoids duplicate lookups
```

---

## Key File Dependencies

```
Frontend:
├─ templates/run.html
│  ├─ static/js/app.js (main application)
│  │  ├─ modules/pcap-parser.js (PCAPParser class)
│  │  ├─ modules/ui-updaters.js (updateStats function)
│  │  ├─ modules/timeline-controller.js (TimelineController)
│  │  ├─ modules/stream-manager.js (Stream list management)
│  │  ├─ modules/search-handler.js (Search functionality)
│  │  └─ modules/file-handler.js (File upload)
│  │
│  └─ static/css/styles.css
│     └─ Contains all styling for panels, dark mode

Backend:
├─ app.py
│  └─ backend/routes/api.py (Flask routes, SocketIO handlers)
│     ├─ backend/processing/pcap_processor.py (File processing)
│     ├─ backend/processing/live_capture.py (Live capture)
│     ├─ backend/processing/remote_capture.py (Remote capture)
│     ├─ backend/processing/threat_detection.py (Threat detection)
│     └─ backend/utils/ (Helpers, IP filtering)

External Libraries:
├─ Flask 3.1.2 (Web framework)
├─ Flask-SocketIO 5.5.1 (WebSocket)
├─ Scapy 2.6.1 (Packet processing)
└─ Socket.IO client (JavaScript, via CDN)
```

