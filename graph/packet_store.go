package graph

import (
	"encoding/base64"
	"sync"
	"time"

	"go-etherape/capture"
)

// PacketData represents a captured packet with payload
type PacketData struct {
	ID          int              `json:"id"`
	Timestamp   time.Time        `json:"timestamp"`
	SrcIP       string           `json:"src"`
	DstIP       string           `json:"dst"`
	SrcPort     uint16           `json:"srcPort"`
	DstPort     uint16           `json:"dstPort"`
	Protocol    string           `json:"protocol"`
	Length      int              `json:"length"`
	Payload     string           `json:"payload"` // Base64 encoded payload
	Summary     string           `json:"summary"`
}

// PacketStore manages a sliding window of recent packets
type PacketStore struct {
	packets    []PacketData
	maxPackets int
	nextID     int
	mu         sync.RWMutex
}

// NewPacketStore creates a new packet store
func NewPacketStore(maxPackets int) *PacketStore {
	return &PacketStore{
		packets:    make([]PacketData, 0, maxPackets),
		maxPackets: maxPackets,
		nextID:     1,
	}
}

// AddPacket adds a packet to the store
func (ps *PacketStore) AddPacket(pkt *capture.PacketInfo) {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	// Create packet data with base64 encoded payload
	packetData := PacketData{
		ID:        ps.nextID,
		Timestamp: time.Now(),
		SrcIP:     pkt.SrcIP,
		DstIP:     pkt.DstIP,
		SrcPort:   pkt.SrcPort,
		DstPort:   pkt.DstPort,
		Protocol:  pkt.Protocol.Name,
		Length:    pkt.Length,
		Payload:   base64.StdEncoding.EncodeToString(pkt.Payload),
		Summary:   pkt.Protocol.Name + " packet",
	}

	ps.nextID++

	// Add to packets list
	ps.packets = append(ps.packets, packetData)

	// Maintain sliding window
	if len(ps.packets) > ps.maxPackets {
		ps.packets = ps.packets[1:]
	}
}

// GetPackets returns all stored packets
func (ps *PacketStore) GetPackets() []PacketData {
	ps.mu.RLock()
	defer ps.mu.RUnlock()

	// Return a copy to avoid race conditions
	result := make([]PacketData, len(ps.packets))
	copy(result, ps.packets)
	return result
}

// GetRecentPackets returns the most recent N packets
func (ps *PacketStore) GetRecentPackets(n int) []PacketData {
	ps.mu.RLock()
	defer ps.mu.RUnlock()

	if n <= 0 || n > len(ps.packets) {
		n = len(ps.packets)
	}

	// Return the last N packets
	start := len(ps.packets) - n
	result := make([]PacketData, n)
	copy(result, ps.packets[start:])
	return result
}
