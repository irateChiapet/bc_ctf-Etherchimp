package graph

import (
	"sync"
	"time"

	"go-etherape/capture"
)

// Node represents a network node (IP address)
type Node struct {
	IP         string    `json:"id"`
	Hostname   string    `json:"label"`
	IPs        []string  `json:"ips"` // All IPs that map to this hostname
	PacketCount int      `json:"packetCount"`
	ByteCount  int64     `json:"byteCount"`
	LastSeen   time.Time `json:"lastSeen"`
}

// Edge represents a connection between two nodes
type Edge struct {
	ID          string            `json:"id"`
	From        string            `json:"from"`
	To          string            `json:"to"`
	Protocol    capture.Protocol  `json:"protocol"`
	PacketCount int               `json:"packetCount"`
	ByteCount   int64             `json:"byteCount"`
	LastSeen    time.Time         `json:"lastSeen"`
}

// GraphSnapshot represents the current state of the graph
type GraphSnapshot struct {
	Nodes   []Node       `json:"nodes"`
	Edges   []Edge       `json:"edges"`
	Packets []PacketData `json:"packets"`
}

// Manager manages the network graph data
type Manager struct {
	nodes           map[string]*Node  // Key: node ID (hostname or IP)
	edges           map[string]*Edge
	ipToNodeID      map[string]string // Maps IP -> node ID (for lookup)
	hostnameToNodeID map[string]string // Maps hostname -> node ID (for merging)
	packetStore     *PacketStore
	mu              sync.RWMutex
}

// NewManager creates a new graph manager
func NewManager() *Manager {
	return &Manager{
		nodes:            make(map[string]*Node),
		edges:            make(map[string]*Edge),
		ipToNodeID:       make(map[string]string),
		hostnameToNodeID: make(map[string]string),
		packetStore:      NewPacketStore(1000), // Store last 1000 packets
	}
}

// AddOrUpdateNode adds a new node or updates an existing one
func (m *Manager) AddOrUpdateNode(ip, hostname string, bytes int) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Determine if we should merge based on hostname
	useHostname := hostname != "" && hostname != ip
	var nodeID string
	var existingNodeID string

	// Check if this IP already belongs to a node
	if existing, ok := m.ipToNodeID[ip]; ok {
		existingNodeID = existing
	}

	// If hostname is valid and different from IP, check if it's already mapped
	if useHostname {
		if existing, ok := m.hostnameToNodeID[hostname]; ok {
			// This hostname already exists, use its node
			nodeID = existing
		} else {
			// New hostname, use it as node ID
			nodeID = hostname
			m.hostnameToNodeID[hostname] = nodeID
		}
	} else {
		// No hostname resolution, use IP as node ID
		nodeID = ip
	}

	// If IP was previously part of a different node, merge the nodes
	if existingNodeID != "" && existingNodeID != nodeID {
		// Merge old node into new node
		if oldNode, exists := m.nodes[existingNodeID]; exists {
			// Transfer data if new node doesn't exist yet
			if _, newExists := m.nodes[nodeID]; !newExists {
				m.nodes[nodeID] = oldNode
				m.nodes[nodeID].IP = nodeID // Update ID
				m.nodes[nodeID].Hostname = hostname
			} else {
				// Merge stats into existing node
				m.nodes[nodeID].PacketCount += oldNode.PacketCount
				m.nodes[nodeID].ByteCount += oldNode.ByteCount
				m.nodes[nodeID].IPs = append(m.nodes[nodeID].IPs, oldNode.IPs...)
			}
			// Delete old node
			delete(m.nodes, existingNodeID)
		}

		// Update all edges that used the old node ID
		for edgeID, edge := range m.edges {
			updated := false
			if edge.From == existingNodeID {
				edge.From = nodeID
				updated = true
			}
			if edge.To == existingNodeID {
				edge.To = nodeID
				updated = true
			}
			if updated {
				// Update edge ID
				newEdgeID := edge.From + "->" + edge.To
				if newEdgeID != edgeID {
					delete(m.edges, edgeID)
					m.edges[newEdgeID] = edge
					edge.ID = newEdgeID
				}
			}
		}
	}

	// Update IP mapping
	m.ipToNodeID[ip] = nodeID

	// Add or update the node
	node, exists := m.nodes[nodeID]
	if !exists {
		ips := []string{ip}
		m.nodes[nodeID] = &Node{
			IP:          nodeID,
			Hostname:    hostname,
			IPs:         ips,
			PacketCount: 1,
			ByteCount:   int64(bytes),
			LastSeen:    time.Now(),
		}
	} else {
		node.PacketCount++
		node.ByteCount += int64(bytes)
		node.LastSeen = time.Now()

		// Add IP to list if not already present
		found := false
		for _, existingIP := range node.IPs {
			if existingIP == ip {
				found = true
				break
			}
		}
		if !found {
			node.IPs = append(node.IPs, ip)
		}

		// Update hostname if resolved and not set
		if useHostname && node.Hostname == node.IP {
			node.Hostname = hostname
		}
	}
}

// AddOrUpdateEdge adds a new edge or updates an existing one
func (m *Manager) AddOrUpdateEdge(srcIP, dstIP string, protocol capture.Protocol, bytes int) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Map IPs to node IDs (might be hostnames)
	srcNodeID := srcIP
	if nodeID, ok := m.ipToNodeID[srcIP]; ok {
		srcNodeID = nodeID
	}

	dstNodeID := dstIP
	if nodeID, ok := m.ipToNodeID[dstIP]; ok {
		dstNodeID = nodeID
	}

	edgeID := srcNodeID + "->" + dstNodeID
	edge, exists := m.edges[edgeID]

	if !exists {
		m.edges[edgeID] = &Edge{
			ID:          edgeID,
			From:        srcNodeID,
			To:          dstNodeID,
			Protocol:    protocol,
			PacketCount: 1,
			ByteCount:   int64(bytes),
			LastSeen:    time.Now(),
		}
	} else {
		edge.PacketCount++
		edge.ByteCount += int64(bytes)
		edge.LastSeen = time.Now()
		// Update protocol if it's more specific
		if protocol.Name != "TCP" && protocol.Name != "UDP" {
			edge.Protocol = protocol
		}
	}
}

// GetSnapshot returns a snapshot of the current graph state
func (m *Manager) GetSnapshot() GraphSnapshot {
	m.mu.RLock()
	defer m.mu.RUnlock()

	nodes := make([]Node, 0, len(m.nodes))
	for _, node := range m.nodes {
		nodes = append(nodes, *node)
	}

	edges := make([]Edge, 0, len(m.edges))
	for _, edge := range m.edges {
		edges = append(edges, *edge)
	}

	// Get recent packets (limit to 100 for performance)
	packets := m.packetStore.GetRecentPackets(100)

	return GraphSnapshot{
		Nodes:   nodes,
		Edges:   edges,
		Packets: packets,
	}
}

// AddPacket adds a packet to the packet store
func (m *Manager) AddPacket(pkt *capture.PacketInfo) {
	m.packetStore.AddPacket(pkt)
}


// RemoveStaleNodes removes nodes that haven't been seen recently
func (m *Manager) RemoveStaleNodes(threshold time.Duration) int {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	removed := 0

	// Remove stale nodes
	for ip, node := range m.nodes {
		if now.Sub(node.LastSeen) > threshold {
			delete(m.nodes, ip)
			removed++
		}
	}

	return removed
}

// RemoveStaleEdges removes edges that haven't been seen recently
func (m *Manager) RemoveStaleEdges(threshold time.Duration) int {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	removed := 0

	// Remove stale edges
	for id, edge := range m.edges {
		if now.Sub(edge.LastSeen) > threshold {
			delete(m.edges, id)
			removed++
		}
	}

	return removed
}

// GetNodeCount returns the current number of nodes
func (m *Manager) GetNodeCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.nodes)
}

// GetEdgeCount returns the current number of edges
func (m *Manager) GetEdgeCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.edges)
}

// Clear removes all nodes, edges, and packets from the graph
func (m *Manager) Clear() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.nodes = make(map[string]*Node)
	m.edges = make(map[string]*Edge)
	m.ipToNodeID = make(map[string]string)
	m.hostnameToNodeID = make(map[string]string)
	m.packetStore = NewPacketStore(1000)
}
