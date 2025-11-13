# EtherChimp Documentation Index

## Overview

This directory contains comprehensive documentation of the EtherChimp codebase - a real-time network traffic visualization and analysis tool. The exploration covers the project structure, UI components, data flow mechanisms, and real-time update strategies.

---

## Documentation Files

### 1. QUICK_REFERENCE.md (START HERE)
**Best for:** Quick lookups, debugging, and implementation reference
**Contains:**
- Panel locations with HTML element IDs
- Update functions reference table
- Metric calculation formulas
- Socket.IO events documentation
- CSS classes and styling
- Backend endpoints
- Global variables
- Common data structures
- Performance limits
- Debugging tips
- Common code modifications

**Start here if you need:** Specific element IDs, function names, or quick code snippets

---

### 2. CODEBASE_EXPLORATION.md (COMPREHENSIVE GUIDE)
**Best for:** Understanding the complete system architecture and design decisions
**Contains:**
- Project overview and technology stack (Flask, Python, JavaScript)
- Detailed project structure breakdown
- **Dashboard Panels** (Left sidebar, Bottom-left info panel, Bottom-right timeline)
- Real-time update mechanisms (WebSocket, polling, requestAnimationFrame)
- Complete data flow for both file upload and live capture modes
- Backend endpoints documentation
- Parser and threat detection capabilities
- UI components and interaction patterns
- Performance optimization strategies
- Key files reference with line counts

**Start here if you need:** Understanding how the entire system works together

---

### 3. ARCHITECTURE.md (SYSTEM DESIGN)
**Best for:** Understanding data flow, system design, and dependencies
**Contains:**
- High-level system architecture diagram
- Detailed data flow diagrams (ASCII art):
  - File upload mode flow
  - Live capture mode flow
- Frontend data state management structures
- UI update frequency comparison table
- Performance optimization breakdown
- File dependency mapping

**Start here if you need:** Visual representation of data flows and system design

---

### 4. EXPLORATION_SUMMARY.txt (EXECUTIVE SUMMARY)
**Best for:** Quick overview of findings and next steps
**Contains:**
- Project summary
- Key findings (9 main areas covered)
- Documentation overview
- Key discoveries
- File location summary
- Next steps for developers

**Start here if you need:** A high-level summary before diving into details

---

## Quick Navigation by Task

### I need to find...

#### Dashboard Panel Elements
- **Location:** QUICK_REFERENCE.md > "Panel Locations & Element IDs"
- **Details:** CODEBASE_EXPLORATION.md > Section 3 "Dashboard Panels and UI Components"

#### How Metrics Are Updated
- **Quick reference:** QUICK_REFERENCE.md > "Update Functions Quick Lookup"
- **Detailed explanation:** CODEBASE_EXPLORATION.md > Section 5 "Data Flow for Metrics and Traffic"
- **Visual diagram:** ARCHITECTURE.md > "Data Flow Diagram: File Upload Mode" and "Live Capture Mode"

#### Real-time Update Mechanism
- **Overview:** EXPLORATION_SUMMARY.txt > Section 4 "Real-time Update Mechanisms"
- **Detailed analysis:** CODEBASE_EXPLORATION.md > Section 4 "Real-Time Update Mechanisms"
- **Socket.IO events:** CODEBASE_EXPLORATION.md > Section 6 "Backend Endpoints and Data Endpoints"

#### Backend Endpoints
- **Summary table:** QUICK_REFERENCE.md > "Backend Endpoints Summary"
- **Detailed documentation:** CODEBASE_EXPLORATION.md > Section 6 "Backend Endpoints and Data Endpoints"

#### File Locations
- **Quick list:** QUICK_REFERENCE.md > Near end of document
- **Complete structure:** CODEBASE_EXPLORATION.md > Section 2 "Project Structure"
- **With line counts:** CODEBASE_EXPLORATION.md > Section 10 "Key Files Reference"

#### Performance Limits
- **Constants:** QUICK_REFERENCE.md > "Performance Limits"
- **Detailed explanation:** CODEBASE_EXPLORATION.md > Section 9 "Performance Optimization Strategies"
- **Breakdown:** ARCHITECTURE.md > "Performance Optimization Points"

#### Metric Calculations
- **Formulas:** QUICK_REFERENCE.md > "Metric Calculations"
- **Implementation:** CODEBASE_EXPLORATION.md > Section 5 "Data Flow for Metrics and Traffic"

#### Threat Detection Types
- **List of threats:** EXPLORATION_SUMMARY.txt > Section 9
- **Implementation details:** CODEBASE_EXPLORATION.md > Section 7 "Parser and Threat Detection"

---

## File Structure Reference

```
/opt/bc_ctf-Etherchimp/
├── DOCUMENTATION_INDEX.md              ← You are here
├── QUICK_REFERENCE.md                 ← Quick lookups
├── CODEBASE_EXPLORATION.md            ← Comprehensive guide
├── ARCHITECTURE.md                     ← System design & data flows
├── EXPLORATION_SUMMARY.txt            ← Executive summary
│
├── app.py                             ← Flask app (102 lines)
├── templates/
│   └── run.html                       ← Main UI (277 lines)
├── static/
│   ├── css/
│   │   └── styles.css                 ← Styling (2111 lines)
│   └── js/
│       ├── app.js                     ← Main app (4720 lines)
│       └── modules/
│           ├── ui-updaters.js         ← Stats update functions
│           ├── pcap-parser.js         ← PCAP parsing
│           ├── timeline-controller.js ← Timeline logic
│           ├── stream-manager.js      ← Stream management
│           ├── search-handler.js      ← Search functionality
│           └── file-handler.js        ← File upload
│
└── backend/
    ├── routes/
    │   └── api.py                     ← API & SocketIO (247 lines)
    ├── processing/
    │   ├── pcap_processor.py          ← File processing (219 lines)
    │   ├── live_capture.py            ← Live capture (376 lines)
    │   ├── remote_capture.py          ← Remote capture
    │   └── threat_detection.py        ← Threat detection
    └── utils/
        ├── helpers.py                 ← Utilities
        └── ip_filters.py              ← IP filtering
```

---

## Key Concepts Explained

### Left Sidebar (#sidebar)
- **Fixed width:** 300px
- **Contains:** Upload area, traffic stats, alerts
- **Updates:** Every 2 seconds in live mode, once in file mode
- **See:** QUICK_REFERENCE.md > "Panel Locations & Element IDs"

### Bottom-Left Info Panel (#infoPanel)
- **Position:** Absolute, bottom: 20px, left: 20px
- **Contains:** Packets/sec, Bandwidth, Active Flows, Threats
- **Updates:** Every 2 seconds via `scheduleUIUpdate()`
- **See:** CODEBASE_EXPLORATION.md > Section 3.2

### Bottom-Right Timeline Panel (#timelineContainer)
- **Position:** Absolute, bottom: 20px, right: 20px
- **Contains:** Timeline slider with progress bar
- **Visible:** Only during live capture
- **See:** CODEBASE_EXPLORATION.md > Section 3.3

### packet_batch Event (PRIMARY UPDATE)
- **Frequency:** Every 2 seconds
- **Source:** Backend
- **Contains:** Packets, aggregated nodes, aggregated edges, DNS cache
- **Handler:** app.js lines 4430-4626
- **See:** CODEBASE_EXPLORATION.md > Section 4.1

### scheduleUIUpdate() Function (UPDATE BATCHING)
- **Location:** app.js lines 4416-4427
- **Purpose:** Batch UI updates for performance
- **Uses:** requestAnimationFrame
- **Prevents:** DOM thrashing
- **See:** QUICK_REFERENCE.md > "Update Functions Quick Lookup"

---

## Common Searches

### "How are stats updated?"
1. QUICK_REFERENCE.md > "Update Trigger Points"
2. CODEBASE_EXPLORATION.md > Section 5 > "Data Flow Diagrams"
3. Static/js/modules/ui-updaters.js > `updateStats()` function

### "What is packet_batch event?"
1. QUICK_REFERENCE.md > "Socket.IO Events" > "Listen"
2. CODEBASE_EXPLORATION.md > Section 4.1 > "`packet_batch` Event"
3. Backend/routes/api.py > `_batch_sender()` method

### "Where is element X?"
1. QUICK_REFERENCE.md > "Panel Locations & Element IDs"
2. Templates/run.html > Search for element ID
3. Static/css/styles.css > Search for CSS class

### "How often do updates happen?"
1. QUICK_REFERENCE.md > "UI Update Frequency Comparison"
2. CODEBASE_EXPLORATION.md > Section 4 > "Real-time Update Mechanisms"
3. ARCHITECTURE.md > "UI Update Frequency Comparison"

### "What are the performance limits?"
1. QUICK_REFERENCE.md > "Performance Limits"
2. CODEBASE_EXPLORATION.md > Section 9 > "Performance Optimization Strategies"
3. Static/js/app.js > Lines 4411-4413

---

## Development Quick Start

1. **Understand the project:** Read EXPLORATION_SUMMARY.txt
2. **Learn the UI structure:** Check QUICK_REFERENCE.md > "Panel Locations"
3. **Study the data flow:** Review ARCHITECTURE.md > "Data Flow Diagrams"
4. **Examine key files:**
   - Backend: app.py, backend/routes/api.py
   - Frontend: templates/run.html, static/js/app.js
5. **Reference metrics:** QUICK_REFERENCE.md > "Metric Calculations"
6. **Debug issues:** QUICK_REFERENCE.md > "Debugging Tips"

---

## Technologies Covered

- **Backend:** Python 3.13, Flask 3.1.2, Flask-SocketIO 5.5.1, Scapy 2.6.1
- **Frontend:** Vanilla JavaScript (no frameworks), HTML5, CSS3
- **Communication:** WebSocket (Socket.IO)
- **Data Format:** JSON, Binary PCAP

---

## Sections Overview

| Topic | Document | Section |
|-------|----------|---------|
| Element IDs | QUICK_REFERENCE | Panel Locations |
| Update Functions | QUICK_REFERENCE | Update Functions |
| Calculations | QUICK_REFERENCE | Metric Calculations |
| Socket Events | QUICK_REFERENCE | Socket.IO Events |
| Data Structures | QUICK_REFERENCE | Common Data Structures |
| CSS Classes | QUICK_REFERENCE | CSS Classes for Styling |
| Endpoints | QUICK_REFERENCE | Backend Endpoints |
| Complete Overview | CODEBASE_EXPLORATION | All sections |
| System Design | ARCHITECTURE | All sections |
| Summary | EXPLORATION_SUMMARY | All sections |

---

## Last Updated

**Date:** 2025-11-12
**Explored by:** Codebase Exploration Tool
**Status:** Complete - All major components documented

---

## Notes

- All file paths are absolute paths starting with `/opt/bc_ctf-Etherchimp/`
- Line numbers reference the actual source files (may change with updates)
- Performance limits are constants that can be modified
- WebSocket batch interval is 2 seconds by default (configurable)
- Threat detection is automatic during packet processing
- Dark mode is fully supported throughout the application

---

## For More Information

- **Implementation Details:** Read source file comments
- **Specific Functions:** Search QUICK_REFERENCE.md for function name
- **Data Structures:** See QUICK_REFERENCE.md > "Common Data Structures"
- **Performance:** See ARCHITECTURE.md > "Performance Optimization Points"
- **Frontend:** See Static/js/app.js (4720 lines of comprehensive code)

