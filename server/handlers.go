package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"go-etherape/replay"
	"go-etherape/stream"
)

// Input validation constants
const (
	maxFilenameLength = 255
	maxOffsetSeconds  = 86400 * 365 // 1 year max offset
	minOffsetSeconds  = 0
)

// validFilenameRegex allows only safe characters in filenames
// Note: hyphen must be at end of character class to be treated as literal
var validFilenameRegex = regexp.MustCompile(`^[a-zA-Z0-9_.-]+\.pcap$`)

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

// validateFilename validates and sanitizes the filename parameter
func validateFilename(filename string) (string, error) {
	// Check for empty filename
	if filename == "" {
		return "", fmt.Errorf("filename is required")
	}

	// Check length
	if len(filename) > maxFilenameLength {
		return "", fmt.Errorf("filename too long (max %d characters)", maxFilenameLength)
	}

	// Get base filename to prevent path traversal
	filename = filepath.Base(filename)

	// Check for path traversal attempts
	if strings.Contains(filename, "..") || strings.HasPrefix(filename, "/") || strings.HasPrefix(filename, "\\") {
		return "", fmt.Errorf("invalid filename: path traversal not allowed")
	}

	// Validate filename format (alphanumeric, underscore, hyphen, dot, must end in .pcap)
	if !validFilenameRegex.MatchString(filename) {
		return "", fmt.Errorf("invalid filename format: must contain only alphanumeric characters, underscores, hyphens, dots, and end with .pcap")
	}

	return filename, nil
}

// validateOffset validates and parses the offset parameter
func validateOffset(offsetStr string) (float64, error) {
	if offsetStr == "" {
		return 0.0, nil
	}

	// Parse as float
	offset, err := strconv.ParseFloat(offsetStr, 64)
	if err != nil {
		return 0.0, fmt.Errorf("invalid offset format: must be a number")
	}

	// Validate range
	if offset < minOffsetSeconds {
		return 0.0, fmt.Errorf("offset must be non-negative")
	}

	if offset > maxOffsetSeconds {
		return 0.0, fmt.Errorf("offset too large (max %d seconds)", maxOffsetSeconds)
	}

	return offset, nil
}

// handleReplayPcap loads and processes a pcap file for replay
func (m *Manager) handleReplayPcap(w http.ResponseWriter, r *http.Request) {
	// Validate and sanitize filename
	filename, err := validateFilename(r.URL.Query().Get("filename"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Validate and parse offset
	offsetSeconds, err := validateOffset(r.URL.Query().Get("offset"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Construct safe path within pcaps directory
	safePath := filepath.Join("pcaps", filename)

	// Verify the file exists and is within the pcaps directory
	absPath, err := filepath.Abs(safePath)
	if err != nil {
		http.Error(w, "Invalid file path", http.StatusBadRequest)
		return
	}

	pcapsDir, err := filepath.Abs("pcaps")
	if err != nil {
		http.Error(w, "Server configuration error", http.StatusInternalServerError)
		return
	}

	if !strings.HasPrefix(absPath, pcapsDir+string(filepath.Separator)) {
		http.Error(w, "Access denied", http.StatusForbidden)
		return
	}

	// Open pcap file using the safe path
	reader, err := replay.NewReader(safePath)
	if err != nil {
		http.Error(w, "Failed to open pcap file", http.StatusNotFound)
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

// handleListStreams returns a list of all tracked streams
func (m *Manager) handleListStreams(w http.ResponseWriter, r *http.Request) {
	if m.streamMgr == nil {
		http.Error(w, "Stream tracking not available", http.StatusServiceUnavailable)
		return
	}

	// Check for protocol filter
	protocol := r.URL.Query().Get("protocol")
	var streams []stream.StreamInfo

	if protocol != "" {
		streams = m.streamMgr.GetStreamsByProtocol(stream.StreamProtocol(protocol))
	} else {
		streams = m.streamMgr.GetStreams()
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(streams); err != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}
}

// handleGetStream returns detailed information for a specific stream
func (m *Manager) handleGetStream(w http.ResponseWriter, r *http.Request) {
	if m.streamMgr == nil {
		http.Error(w, "Stream tracking not available", http.StatusServiceUnavailable)
		return
	}

	// Get stream ID from query parameter
	streamID := r.URL.Query().Get("id")
	if streamID == "" {
		http.Error(w, "Stream ID is required", http.StatusBadRequest)
		return
	}

	// Validate stream ID format (basic sanity check)
	if len(streamID) > 200 || strings.ContainsAny(streamID, "<>\"'&") {
		http.Error(w, "Invalid stream ID format", http.StatusBadRequest)
		return
	}

	streamDetail, err := m.streamMgr.GetStream(streamID)
	if err != nil {
		http.Error(w, "Stream not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(streamDetail); err != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}
}

// handleGetStreamStats returns stream tracking statistics
func (m *Manager) handleGetStreamStats(w http.ResponseWriter, r *http.Request) {
	if m.streamMgr == nil {
		http.Error(w, "Stream tracking not available", http.StatusServiceUnavailable)
		return
	}

	stats := m.streamMgr.GetStats()

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(stats); err != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}
}
