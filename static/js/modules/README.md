# JavaScript Modules - Refactored Structure

This directory contains the modularized components extracted from the original monolithic `app.js` file (4,565 lines).

## Completed Modules

### Core Classes

1. **pcap-parser.js** (420 lines)
   - `PCAPParser` class
   - Binary PCAP file parsing
   - Packet header extraction (Ethernet, IPv4, IPv6, TCP, UDP)
   - Protocol identification
   - Statistics tracking (hosts, connections, protocols)
   - Threat detection system (port scans, suspicious ports, ICMP floods, ARP spoofing, etc.)

2. **timeline-controller.js** (177 lines)
   - `TimelineController` class
   - Timeline scrubber UI management
   - Playback controls (play/pause/seek)
   - Temporal filtering of network data
   - Time range formatting

### Utility Modules

3. **packet-formatters.js** (70 lines)
   - `formatHexDump()` - Formats packet data as hex dump
   - `formatAsciiDump()` - Formats packet data as ASCII
   - `togglePacketData()` - Shows/hides packet hex/ASCII dumps

4. **file-handler.js** (97 lines)
   - `handleFile()` - Handles PCAP file uploads
   - `processBackendData()` - Converts backend response to frontend format
   - Integrates with visualizer, timeline, and stream list

5. **stream-manager.js** (123 lines)
   - `populateStreamList()` - Populates TCP/HTTP stream list from static data
   - `populateLiveStreamList()` - Updates stream list for live capture
   - `selectStream()` / `selectLiveStream()` - Stream selection handlers

6. **search-handler.js** (103 lines)
   - `getSearchResults()` - Searches nodes and packets
   - `performRealtimeSearch()` - Real-time search with UI updates
   - `selectSearchResult()` - Focuses visualization on search results

7. **ui-updaters.js** (70 lines)
   - `updateStats()` - Updates statistics sidebar
   - `updateAlerts()` - Updates alerts list with click handlers

## Remaining Work

### Large Components Still in app.js

1. **NetworkVisualizer Class** (~2,454 lines, lines 422-2876)
   - Canvas-based network graph visualization
   - 3D rendering engine
   - Physics simulation (force-directed layout)
   - Multiple layout algorithms (force, clustered, circular, hierarchical)
   - Mouse/keyboard interaction handlers
   - Protocol filtering and animation
   - Line Rider feature
   - Live mode support
   - **Recommendation**: This should be further split into sub-modules:
     - `network-visualizer-core.js` - Main class and setup
     - `network-visualizer-layouts.js` - Layout algorithms
     - `network-visualizer-physics.js` - Force simulation
     - `network-visualizer-rendering.js` - Canvas drawing
     - `network-visualizer-interaction.js` - Event handlers

2. **Live Capture / WebSocket Handler** (~417 lines, lines 4149-4565)
   - Socket.IO initialization
   - WebSocket event handlers
   - Real-time packet batching
   - DNS cache updates
   - Live mode state management
   - `startLiveCapture()` / `stopLiveCapture()` functions

3. **Application Initialization** (~625 lines, lines 3128-3754)
   - Global variable declarations
   - DOM event listeners
   - File upload (drag & drop)
   - UI control setup (buttons, panels, search, alerts, etc.)
   - Theme toggle
   - Settings menu
   - **Recommendation**: Split into:
     - `app-init.js` - Main initialization
     - `ui-controls.js` - Button and control handlers

## Module Dependencies

```
┌─────────────────────────────────────────────────────────────┐
│                        app-init.js                          │
│              (main initialization & event handlers)          │
└────────────────────┬────────────────────────────────────────┘
                     │
         ┌───────────┼───────────┬──────────────┬─────────────┐
         │           │           │              │             │
    ┌────▼───┐  ┌───▼────┐ ┌────▼─────┐  ┌────▼────┐  ┌─────▼─────┐
    │ PCAP   │  │Network │ │Timeline  │  │  File   │  │  Live     │
    │ Parser │  │Visual- │ │Control   │  │ Handler │  │  Capture  │
    └────┬───┘  │ izer   │ └────┬─────┘  └────┬────┘  └─────┬─────┘
         │      └───┬────┘      │             │             │
         │          │           │             │             │
    ┌────▼──────────▼───────────▼─────────────▼─────────────▼─────┐
    │                     Utilities Layer                           │
    │  ┌───────────┐  ┌──────────┐  ┌────────┐  ┌───────────┐    │
    │  │  Packet   │  │  Stream  │  │Search  │  │    UI     │    │
    │  │Formatters │  │ Manager  │  │Handler │  │ Updaters  │    │
    │  └───────────┘  └──────────┘  └────────┘  └───────────┘    │
    └───────────────────────────────────────────────────────────────┘
```

## Integration Instructions

### Current Setup (Before Full Refactor)

The modules are extracted but `app.js` still contains:
- NetworkVisualizer class
- Live capture logic
- App initialization code

### To Use Extracted Modules

Add these script tags to your HTML **before** `app.js`:

```html
<!-- Core Classes -->
<script src="/static/js/modules/pcap-parser.js"></script>
<script src="/static/js/modules/timeline-controller.js"></script>

<!-- Utility Modules -->
<script src="/static/js/modules/packet-formatters.js"></script>
<script src="/static/js/modules/file-handler.js"></script>
<script src="/static/js/modules/stream-manager.js"></script>
<script src="/static/js/modules/search-handler.js"></script>
<script src="/static/js/modules/ui-updaters.js"></script>

<!-- Main app (still contains NetworkVisualizer, live capture, init) -->
<script src="/static/js/app.js"></script>
```

### Complete Refactor (Future)

Once all extraction is complete:

```html
<!-- Core Classes -->
<script src="/static/js/modules/pcap-parser.js"></script>
<script src="/static/js/modules/network-visualizer.js"></script>
<script src="/static/js/modules/timeline-controller.js"></script>

<!-- Utilities -->
<script src="/static/js/modules/packet-formatters.js"></script>
<script src="/static/js/modules/file-handler.js"></script>
<script src="/static/js/modules/stream-manager.js"></script>
<script src="/static/js/modules/search-handler.js"></script>
<script src="/static/js/modules/ui-updaters.js"></script>
<script src="/static/js/modules/live-capture.js"></script>

<!-- Main Application -->
<script src="/static/js/modules/app-init.js"></script>
```

## Benefits of This Refactoring

1. **Maintainability**: Smaller, focused files are easier to understand and modify
2. **Testability**: Individual modules can be unit tested in isolation
3. **Reusability**: Modules can be reused in other projects
4. **Collaboration**: Multiple developers can work on different modules
5. **Performance**: Potential for lazy loading and code splitting
6. **Organization**: Clear separation of concerns

## Next Steps

1. Extract NetworkVisualizer (consider splitting into sub-modules)
2. Extract live capture/WebSocket logic
3. Extract app initialization code
4. Remove extracted code from original `app.js`
5. Update HTML to load modular scripts
6. Test thoroughly to ensure nothing broke
7. Consider migrating to ES6 modules for better dependency management

## File Size Comparison

| File | Lines | Description |
|------|-------|-------------|
| **Original app.js** | 4,565 | Monolithic file |
| pcap-parser.js | 420 | PCAP parsing & threat detection |
| timeline-controller.js | 177 | Timeline UI |
| packet-formatters.js | 70 | Hex/ASCII formatting |
| file-handler.js | 97 | File upload handling |
| stream-manager.js | 123 | Stream list management |
| search-handler.js | 103 | Search functionality |
| ui-updaters.js | 70 | Stats & alerts UI |
| **Remaining in app.js** | ~3,500 | Visualizer, live capture, init |

**Progress**: ~1,060 lines extracted (23% of original file)
