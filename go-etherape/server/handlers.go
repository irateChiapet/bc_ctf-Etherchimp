package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"go-etherape/replay"
)

// handleIndex serves the main HTML page
func (m *Manager) handleIndex(w http.ResponseWriter, r *http.Request) {
	// Only serve index.html for root path
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	// Read and serve the index.html file
	indexFile := "static/index.html"
	data, err := os.ReadFile(indexFile)
	if err != nil {
		http.Error(w, "Failed to load page", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(data)
}

// handleGraphAPI returns the current graph snapshot as JSON
func (m *Manager) handleGraphAPI(w http.ResponseWriter, r *http.Request) {
	snapshot := m.graphMgr.GetSnapshot()

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(snapshot); err != nil {
		http.Error(w, "Failed to encode graph data", http.StatusInternalServerError)
		return
	}
}

// handleListPcaps returns list of available pcap files
func (m *Manager) handleListPcaps(w http.ResponseWriter, r *http.Request) {
	pcapFiles, err := replay.GetPcapFiles("pcaps")
	if err != nil {
		http.Error(w, "Failed to list pcap files", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(pcapFiles); err != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}
}

// handleReplayPcap loads and processes a pcap file for replay
func (m *Manager) handleReplayPcap(w http.ResponseWriter, r *http.Request) {
	// Get filename from query parameter
	filename := r.URL.Query().Get("filename")
	if filename == "" {
		http.Error(w, "Missing filename parameter", http.StatusBadRequest)
		return
	}

	// Get time offset from query parameter (in seconds)
	offsetSeconds := 0.0
	if offset := r.URL.Query().Get("offset"); offset != "" {
		fmt.Sscanf(offset, "%f", &offsetSeconds)
	}

	// Open pcap file
	reader, err := replay.NewReader(filename)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to open pcap: %v", err), http.StatusInternalServerError)
		return
	}
	defer reader.Close()

	// Get packets up to the specified time
	packetsWithTime := reader.GetPacketsUpToTime(offsetSeconds)

	// Build graph snapshot from packets
	snapshot := replay.BuildSnapshotFromPackets(packetsWithTime)

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(snapshot); err != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}
}

// handleDownloadCurrentPcap returns the current live capture pcap file
func (m *Manager) handleDownloadCurrentPcap(w http.ResponseWriter, r *http.Request) {
	// Get the most recent pcap file
	pcapFiles, err := replay.GetPcapFiles("pcaps")
	if err != nil || len(pcapFiles) == 0 {
		http.Error(w, "No pcap files available", http.StatusNotFound)
		return
	}

	// Get most recent file
	currentFile := pcapFiles[0]

	// Serve file for download
	w.Header().Set("Content-Type", "application/vnd.tcpdump.pcap")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", currentFile.Filename))

	http.ServeFile(w, r, currentFile.Path)
}
