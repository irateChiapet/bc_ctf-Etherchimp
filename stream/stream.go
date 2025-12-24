package stream

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"go-etherape/capture"
)

// StreamType represents the transport protocol
type StreamType string

const (
	StreamTypeTCP StreamType = "TCP"
	StreamTypeUDP StreamType = "UDP"
)

// StreamProtocol represents the detected application protocol
type StreamProtocol string

const (
	ProtocolHTTP      StreamProtocol = "HTTP"
	ProtocolHTTPS     StreamProtocol = "HTTPS"
	ProtocolDNS       StreamProtocol = "DNS"
	ProtocolSMTP      StreamProtocol = "SMTP"
	ProtocolFTP       StreamProtocol = "FTP"
	ProtocolSSH       StreamProtocol = "SSH"
	ProtocolTelnet    StreamProtocol = "Telnet"
	ProtocolMySQL     StreamProtocol = "MySQL"
	ProtocolPostgres  StreamProtocol = "PostgreSQL"
	ProtocolRedis     StreamProtocol = "Redis"
	ProtocolSlurm     StreamProtocol = "Slurm"
	ProtocolUnknown   StreamProtocol = "Unknown"
)

// StreamPacket represents a single packet in a stream
type StreamPacket struct {
	Timestamp time.Time `json:"timestamp"`
	Direction string    `json:"direction"` // "request" or "response"
	Length    int       `json:"length"`
	Payload   []byte    `json:"-"`          // Raw payload (not serialized directly)
	PayloadB64 string   `json:"payload"`    // Base64 encoded for JSON
}

// Stream represents a TCP or UDP stream
type Stream struct {
	ID           string         `json:"id"`
	Type         StreamType     `json:"type"`
	Protocol     StreamProtocol `json:"protocol"`
	SrcIP        string         `json:"srcIp"`
	SrcPort      uint16         `json:"srcPort"`
	DstIP        string         `json:"dstIp"`
	DstPort      uint16         `json:"dstPort"`
	StartTime    time.Time      `json:"startTime"`
	LastSeen     time.Time      `json:"lastSeen"`
	PacketCount  int            `json:"packetCount"`
	ByteCount    int64          `json:"byteCount"`
	Packets      []StreamPacket `json:"packets,omitempty"`
	Summary      string         `json:"summary"`
	RequestData  []byte         `json:"-"`
	ResponseData []byte         `json:"-"`
}

// StreamInfo is a lightweight version for listing
type StreamInfo struct {
	ID          string         `json:"id"`
	Type        StreamType     `json:"type"`
	Protocol    StreamProtocol `json:"protocol"`
	SrcIP       string         `json:"srcIp"`
	SrcPort     uint16         `json:"srcPort"`
	DstIP       string         `json:"dstIp"`
	DstPort     uint16         `json:"dstPort"`
	StartTime   time.Time      `json:"startTime"`
	LastSeen    time.Time      `json:"lastSeen"`
	PacketCount int            `json:"packetCount"`
	ByteCount   int64          `json:"byteCount"`
	Summary     string         `json:"summary"`
}

// StreamDetail includes full payload data
type StreamDetail struct {
	StreamInfo
	Packets         []StreamPacket `json:"packets"`
	RequestPayload  string         `json:"requestPayload"`  // Base64
	ResponsePayload string         `json:"responsePayload"` // Base64
	DecodedContent  string         `json:"decodedContent"`  // Human-readable content
}

// Manager manages stream tracking and reconstruction
type Manager struct {
	streams    map[string]*Stream
	maxStreams int
	mu         sync.RWMutex
}

// NewManager creates a new stream manager
func NewManager(maxStreams int) *Manager {
	if maxStreams <= 0 {
		maxStreams = 1000
	}
	return &Manager{
		streams:    make(map[string]*Stream),
		maxStreams: maxStreams,
	}
}

// generateStreamID creates a unique stream identifier
func generateStreamID(srcIP string, srcPort uint16, dstIP string, dstPort uint16, streamType StreamType) string {
	// Normalize direction for consistent ID (lower IP:port first)
	src := fmt.Sprintf("%s:%d", srcIP, srcPort)
	dst := fmt.Sprintf("%s:%d", dstIP, dstPort)

	if src > dst {
		src, dst = dst, src
	}

	return fmt.Sprintf("%s-%s-%s", streamType, src, dst)
}

// AddPacket adds a packet to the appropriate stream
func (m *Manager) AddPacket(pkt *capture.PacketInfo) {
	// Skip nil packets or packets without port info (non-TCP/UDP)
	if pkt == nil || (pkt.SrcPort == 0 && pkt.DstPort == 0) {
		return
	}

	// Determine stream type based on protocol
	var streamType StreamType
	switch pkt.Protocol.Name {
	case "UDP", "DNS":
		streamType = StreamTypeUDP
	case "TCP", "HTTP", "HTTPS", "SSH", "FTP", "SMTP", "MySQL", "PostgreSQL":
		streamType = StreamTypeTCP
	default:
		// For any other protocol with ports, assume TCP
		streamType = StreamTypeTCP
	}

	streamID := generateStreamID(pkt.SrcIP, pkt.SrcPort, pkt.DstIP, pkt.DstPort, streamType)

	m.mu.Lock()
	defer m.mu.Unlock()

	stream, exists := m.streams[streamID]
	now := time.Now()

	if !exists {
		// Check if we need to evict old streams
		if len(m.streams) >= m.maxStreams {
			m.evictOldestStream()
		}

		stream = &Stream{
			ID:        streamID,
			Type:      streamType,
			SrcIP:     pkt.SrcIP,
			SrcPort:   pkt.SrcPort,
			DstIP:     pkt.DstIP,
			DstPort:   pkt.DstPort,
			StartTime: now,
			LastSeen:  now,
			Packets:   make([]StreamPacket, 0),
		}
		m.streams[streamID] = stream
	}

	// Determine packet direction
	direction := "request"
	if pkt.SrcPort == stream.DstPort || pkt.SrcIP == stream.DstIP {
		direction = "response"
	}

	// Add packet to stream
	streamPkt := StreamPacket{
		Timestamp:  now,
		Direction:  direction,
		Length:     len(pkt.Payload),
		Payload:    pkt.Payload,
		PayloadB64: base64.StdEncoding.EncodeToString(pkt.Payload),
	}

	// Limit packets per stream
	if len(stream.Packets) < 500 {
		stream.Packets = append(stream.Packets, streamPkt)
	}

	// Accumulate payload data
	if direction == "request" {
		stream.RequestData = append(stream.RequestData, pkt.Payload...)
	} else {
		stream.ResponseData = append(stream.ResponseData, pkt.Payload...)
	}

	// Limit payload sizes (1MB each)
	if len(stream.RequestData) > 1024*1024 {
		stream.RequestData = stream.RequestData[:1024*1024]
	}
	if len(stream.ResponseData) > 1024*1024 {
		stream.ResponseData = stream.ResponseData[:1024*1024]
	}

	stream.PacketCount++
	stream.ByteCount += int64(pkt.Length)
	stream.LastSeen = now

	// Detect protocol and update summary
	stream.Protocol = detectProtocol(pkt, stream)
	stream.Summary = generateSummary(stream)
}

// evictOldestStream removes the oldest stream
func (m *Manager) evictOldestStream() {
	var oldestID string
	var oldestTime time.Time

	for id, stream := range m.streams {
		if oldestID == "" || stream.LastSeen.Before(oldestTime) {
			oldestID = id
			oldestTime = stream.LastSeen
		}
	}

	if oldestID != "" {
		delete(m.streams, oldestID)
	}
}

// detectProtocol identifies the application protocol
func detectProtocol(pkt *capture.PacketInfo, stream *Stream) StreamProtocol {
	// Use capture's detected protocol first
	switch pkt.Protocol.Name {
	case "HTTP":
		return ProtocolHTTP
	case "HTTPS":
		return ProtocolHTTPS
	case "DNS":
		return ProtocolDNS
	case "SSH":
		return ProtocolSSH
	case "FTP":
		return ProtocolFTP
	case "SMTP":
		return ProtocolSMTP
	case "Telnet":
		return ProtocolTelnet
	case "MySQL":
		return ProtocolMySQL
	case "PostgreSQL":
		return ProtocolPostgres
	case "Redis":
		return ProtocolRedis
	case "Slurm":
		return ProtocolSlurm
	}

	// Detect from port numbers
	ports := []uint16{pkt.SrcPort, pkt.DstPort}
	for _, port := range ports {
		switch port {
		case 80, 8080, 8000, 3000:
			return ProtocolHTTP
		case 443, 8443:
			return ProtocolHTTPS
		case 53:
			return ProtocolDNS
		case 22:
			return ProtocolSSH
		case 21:
			return ProtocolFTP
		case 25, 587, 465:
			return ProtocolSMTP
		case 23:
			return ProtocolTelnet
		case 3306:
			return ProtocolMySQL
		case 5432:
			return ProtocolPostgres
		case 6379:
			return ProtocolRedis
		case 6817, 6818:
			return ProtocolSlurm
		}
	}

	// Detect from payload patterns
	payload := stream.RequestData
	if len(payload) > 0 {
		payloadStr := string(payload[:min(len(payload), 100)])

		if strings.HasPrefix(payloadStr, "GET ") ||
			strings.HasPrefix(payloadStr, "POST ") ||
			strings.HasPrefix(payloadStr, "PUT ") ||
			strings.HasPrefix(payloadStr, "DELETE ") ||
			strings.HasPrefix(payloadStr, "HEAD ") ||
			strings.HasPrefix(payloadStr, "OPTIONS ") ||
			strings.HasPrefix(payloadStr, "HTTP/") {
			return ProtocolHTTP
		}

		if strings.HasPrefix(payloadStr, "SSH-") {
			return ProtocolSSH
		}

		if strings.HasPrefix(payloadStr, "EHLO ") ||
			strings.HasPrefix(payloadStr, "HELO ") ||
			strings.HasPrefix(payloadStr, "MAIL FROM:") {
			return ProtocolSMTP
		}
	}

	return ProtocolUnknown
}

// generateSummary creates a human-readable summary
func generateSummary(stream *Stream) string {
	switch stream.Protocol {
	case ProtocolHTTP:
		return extractHTTPSummary(stream)
	case ProtocolDNS:
		return extractDNSSummary(stream)
	case ProtocolSSH:
		return "SSH Session"
	case ProtocolSMTP:
		return extractSMTPSummary(stream)
	case ProtocolFTP:
		return "FTP Session"
	case ProtocolSlurm:
		return "Slurm RPC"
	default:
		return fmt.Sprintf("%s stream (%d packets)", stream.Type, stream.PacketCount)
	}
}

// extractHTTPSummary extracts HTTP request info
func extractHTTPSummary(stream *Stream) string {
	if len(stream.RequestData) == 0 {
		return "HTTP (no data)"
	}

	// Parse first line of HTTP request
	data := string(stream.RequestData[:min(len(stream.RequestData), 500)])
	lines := strings.Split(data, "\r\n")
	if len(lines) > 0 {
		firstLine := lines[0]
		// Match HTTP request line: METHOD /path HTTP/1.x
		re := regexp.MustCompile(`^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+(\S+)\s+HTTP`)
		if matches := re.FindStringSubmatch(firstLine); len(matches) >= 3 {
			method := matches[1]
			path := matches[2]
			if len(path) > 50 {
				path = path[:50] + "..."
			}
			return fmt.Sprintf("%s %s", method, path)
		}
	}

	return "HTTP Request"
}

// extractDNSSummary extracts DNS query info
func extractDNSSummary(stream *Stream) string {
	// DNS parsing is complex, just show basic info
	return fmt.Sprintf("DNS Query (%d bytes)", stream.ByteCount)
}

// extractSMTPSummary extracts SMTP info
func extractSMTPSummary(stream *Stream) string {
	if len(stream.RequestData) == 0 {
		return "SMTP (no data)"
	}

	data := string(stream.RequestData[:min(len(stream.RequestData), 500)])

	// Look for MAIL FROM
	re := regexp.MustCompile(`MAIL FROM:<([^>]+)>`)
	if matches := re.FindStringSubmatch(data); len(matches) >= 2 {
		return fmt.Sprintf("SMTP from %s", matches[1])
	}

	return "SMTP Session"
}

// GetStreams returns a list of all streams (lightweight info only)
func (m *Manager) GetStreams() []StreamInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()

	streams := make([]StreamInfo, 0, len(m.streams))
	for _, stream := range m.streams {
		streams = append(streams, StreamInfo{
			ID:          stream.ID,
			Type:        stream.Type,
			Protocol:    stream.Protocol,
			SrcIP:       stream.SrcIP,
			SrcPort:     stream.SrcPort,
			DstIP:       stream.DstIP,
			DstPort:     stream.DstPort,
			StartTime:   stream.StartTime,
			LastSeen:    stream.LastSeen,
			PacketCount: stream.PacketCount,
			ByteCount:   stream.ByteCount,
			Summary:     stream.Summary,
		})
	}

	// Sort by last seen (most recent first)
	sort.Slice(streams, func(i, j int) bool {
		return streams[i].LastSeen.After(streams[j].LastSeen)
	})

	return streams
}

// GetStream returns detailed stream info including payloads
func (m *Manager) GetStream(id string) (*StreamDetail, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	stream, exists := m.streams[id]
	if !exists {
		return nil, fmt.Errorf("stream not found: %s", id)
	}

	detail := &StreamDetail{
		StreamInfo: StreamInfo{
			ID:          stream.ID,
			Type:        stream.Type,
			Protocol:    stream.Protocol,
			SrcIP:       stream.SrcIP,
			SrcPort:     stream.SrcPort,
			DstIP:       stream.DstIP,
			DstPort:     stream.DstPort,
			StartTime:   stream.StartTime,
			LastSeen:    stream.LastSeen,
			PacketCount: stream.PacketCount,
			ByteCount:   stream.ByteCount,
			Summary:     stream.Summary,
		},
		Packets:         stream.Packets,
		RequestPayload:  base64.StdEncoding.EncodeToString(stream.RequestData),
		ResponsePayload: base64.StdEncoding.EncodeToString(stream.ResponseData),
		DecodedContent:  decodeStreamContent(stream),
	}

	return detail, nil
}

// decodeStreamContent creates human-readable content
func decodeStreamContent(stream *Stream) string {
	var buf bytes.Buffer

	switch stream.Protocol {
	case ProtocolHTTP:
		// Show request
		if len(stream.RequestData) > 0 {
			buf.WriteString("=== REQUEST ===\n")
			buf.Write(sanitizeForDisplay(stream.RequestData))
			buf.WriteString("\n\n")
		}
		// Show response
		if len(stream.ResponseData) > 0 {
			buf.WriteString("=== RESPONSE ===\n")
			buf.Write(sanitizeForDisplay(stream.ResponseData))
		}

	case ProtocolSMTP:
		buf.WriteString("=== SMTP SESSION ===\n")
		if len(stream.RequestData) > 0 {
			buf.Write(sanitizeForDisplay(stream.RequestData))
		}

	default:
		// For other protocols, show raw data in hex + ASCII
		buf.WriteString("=== REQUEST DATA ===\n")
		if len(stream.RequestData) > 0 {
			buf.WriteString(formatHexDump(stream.RequestData[:min(len(stream.RequestData), 4096)]))
		} else {
			buf.WriteString("(empty)\n")
		}
		buf.WriteString("\n=== RESPONSE DATA ===\n")
		if len(stream.ResponseData) > 0 {
			buf.WriteString(formatHexDump(stream.ResponseData[:min(len(stream.ResponseData), 4096)]))
		} else {
			buf.WriteString("(empty)\n")
		}
	}

	return buf.String()
}

// sanitizeForDisplay removes non-printable characters
func sanitizeForDisplay(data []byte) []byte {
	result := make([]byte, 0, len(data))
	for _, b := range data {
		if b >= 32 && b < 127 || b == '\n' || b == '\r' || b == '\t' {
			result = append(result, b)
		} else {
			result = append(result, '.')
		}
	}
	return result
}

// formatHexDump creates a hex dump with ASCII
func formatHexDump(data []byte) string {
	var buf bytes.Buffer

	for i := 0; i < len(data); i += 16 {
		// Offset
		buf.WriteString(fmt.Sprintf("%08x  ", i))

		// Hex bytes
		for j := 0; j < 16; j++ {
			if i+j < len(data) {
				buf.WriteString(fmt.Sprintf("%02x ", data[i+j]))
			} else {
				buf.WriteString("   ")
			}
			if j == 7 {
				buf.WriteString(" ")
			}
		}

		buf.WriteString(" |")

		// ASCII
		for j := 0; j < 16 && i+j < len(data); j++ {
			b := data[i+j]
			if b >= 32 && b < 127 {
				buf.WriteByte(b)
			} else {
				buf.WriteByte('.')
			}
		}

		buf.WriteString("|\n")
	}

	return buf.String()
}

// GetStreamsByProtocol returns streams filtered by protocol
func (m *Manager) GetStreamsByProtocol(protocol StreamProtocol) []StreamInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()

	streams := make([]StreamInfo, 0)
	for _, stream := range m.streams {
		if stream.Protocol == protocol {
			streams = append(streams, StreamInfo{
				ID:          stream.ID,
				Type:        stream.Type,
				Protocol:    stream.Protocol,
				SrcIP:       stream.SrcIP,
				SrcPort:     stream.SrcPort,
				DstIP:       stream.DstIP,
				DstPort:     stream.DstPort,
				StartTime:   stream.StartTime,
				LastSeen:    stream.LastSeen,
				PacketCount: stream.PacketCount,
				ByteCount:   stream.ByteCount,
				Summary:     stream.Summary,
			})
		}
	}

	sort.Slice(streams, func(i, j int) bool {
		return streams[i].LastSeen.After(streams[j].LastSeen)
	})

	return streams
}

// Clear removes all streams
func (m *Manager) Clear() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.streams = make(map[string]*Stream)
}

// GetStats returns stream statistics
func (m *Manager) GetStats() map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()

	protocolCounts := make(map[StreamProtocol]int)
	for _, stream := range m.streams {
		protocolCounts[stream.Protocol]++
	}

	return map[string]interface{}{
		"totalStreams":   len(m.streams),
		"protocolCounts": protocolCounts,
	}
}

// MarshalJSON custom JSON marshaling for StreamDetail
func (s *StreamDetail) MarshalJSON() ([]byte, error) {
	type Alias StreamDetail
	return json.Marshal(&struct {
		*Alias
	}{
		Alias: (*Alias)(s),
	})
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
