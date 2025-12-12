package replay

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"go-etherape/capture"
	"go-etherape/graph"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

// PcapInfo contains metadata about a pcap file
type PcapInfo struct {
	Filename    string    `json:"filename"`
	Path        string    `json:"path"`
	StartTime   time.Time `json:"startTime"`
	EndTime     time.Time `json:"endTime"`
	PacketCount int       `json:"packetCount"`
	FileSize    int64     `json:"fileSize"`
	ModTime     time.Time `json:"modTime"`
	DurationSec float64   `json:"durationSec"`
}

// PacketWithTime represents a packet with its timestamp
type PacketWithTime struct {
	Info      *capture.PacketInfo
	Timestamp time.Time
}

// Reader manages pcap file reading for replay
type Reader struct {
	handle    *pcap.Handle
	packets   []PacketWithTime
	startTime time.Time
	endTime   time.Time
}

// GetPcapFiles scans the pcaps directory and returns info about available files
func GetPcapFiles(pcapDir string) ([]PcapInfo, error) {
	files, err := os.ReadDir(pcapDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read pcaps directory: %v", err)
	}

	var pcapInfos []PcapInfo

	for _, file := range files {
		if file.IsDir() || filepath.Ext(file.Name()) != ".pcap" {
			continue
		}

		fullPath := filepath.Join(pcapDir, file.Name())
		info, err := file.Info()
		if err != nil {
			continue
		}

		// Quick scan to get packet metadata
		metadata, err := scanPcapMetadata(fullPath)
		if err != nil {
			// File might be corrupted, skip
			continue
		}

		pcapInfos = append(pcapInfos, PcapInfo{
			Filename:    file.Name(),
			Path:        fullPath,
			StartTime:   metadata.StartTime,
			EndTime:     metadata.EndTime,
			PacketCount: metadata.PacketCount,
			FileSize:    info.Size(),
			ModTime:     info.ModTime(),
			DurationSec: metadata.EndTime.Sub(metadata.StartTime).Seconds(),
		})
	}

	// Sort by modification time, newest first
	sort.Slice(pcapInfos, func(i, j int) bool {
		return pcapInfos[i].ModTime.After(pcapInfos[j].ModTime)
	})

	return pcapInfos, nil
}

// scanPcapMetadata does a quick scan to get timestamps and packet count
func scanPcapMetadata(filename string) (PcapInfo, error) {
	handle, err := pcap.OpenOffline(filename)
	if err != nil {
		return PcapInfo{}, err
	}
	defer handle.Close()

	var startTime, endTime time.Time
	packetCount := 0

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	for packet := range packetSource.Packets() {
		timestamp := packet.Metadata().Timestamp

		if packetCount == 0 {
			startTime = timestamp
		}
		endTime = timestamp
		packetCount++
	}

	return PcapInfo{
		StartTime:   startTime,
		EndTime:     endTime,
		PacketCount: packetCount,
	}, nil
}

// NewReader creates a new pcap replay reader
func NewReader(filename string) (*Reader, error) {
	handle, err := pcap.OpenOffline(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to open pcap file: %v", err)
	}

	reader := &Reader{
		handle:  handle,
		packets: make([]PacketWithTime, 0),
	}

	// Pre-load all packets for fast seeking
	if err := reader.loadPackets(); err != nil {
		handle.Close()
		return nil, err
	}

	return reader, nil
}

// loadPackets reads all packets from the pcap file
func (r *Reader) loadPackets() error {
	packetSource := gopacket.NewPacketSource(r.handle, r.handle.LinkType())

	for packet := range packetSource.Packets() {
		packetInfo := capture.ProcessPacket(packet)
		if packetInfo == nil {
			continue
		}

		timestamp := packet.Metadata().Timestamp

		if len(r.packets) == 0 {
			r.startTime = timestamp
		}
		r.endTime = timestamp

		r.packets = append(r.packets, PacketWithTime{
			Info:      packetInfo,
			Timestamp: timestamp,
		})
	}

	return nil
}

// GetPacketsUpToTime returns all packets up to a given timestamp offset
func (r *Reader) GetPacketsUpToTime(offsetSeconds float64) []PacketWithTime {
	if len(r.packets) == 0 {
		return []PacketWithTime{}
	}

	targetTime := r.startTime.Add(time.Duration(offsetSeconds * float64(time.Second)))

	// Binary search for efficiency
	idx := sort.Search(len(r.packets), func(i int) bool {
		return r.packets[i].Timestamp.After(targetTime)
	})

	return r.packets[:idx]
}

// GetStartTime returns the timestamp of the first packet
func (r *Reader) GetStartTime() time.Time {
	return r.startTime
}

// GetEndTime returns the timestamp of the last packet
func (r *Reader) GetEndTime() time.Time {
	return r.endTime
}

// GetDuration returns the total duration of the capture
func (r *Reader) GetDuration() time.Duration {
	return r.endTime.Sub(r.startTime)
}

// Close closes the pcap handle
func (r *Reader) Close() error {
	if r.handle != nil {
		r.handle.Close()
	}
	return nil
}

// BuildSnapshotFromPackets creates a graph snapshot from a list of packets
func BuildSnapshotFromPackets(packetsWithTime []PacketWithTime) graph.GraphSnapshot {
	// Create temporary graph manager for replay
	tempGraph := graph.NewManager()

	// Create DNS cache for synchronous lookups
	dnsCache := make(map[string]string)

	// Process each packet
	for _, pwt := range packetsWithTime {
		pkt := pwt.Info

		// Resolve hostnames with simple caching
		srcHostname := resolveIPSync(pkt.SrcIP, dnsCache)
		dstHostname := resolveIPSync(pkt.DstIP, dnsCache)

		// Update graph
		tempGraph.AddOrUpdateNode(pkt.SrcIP, srcHostname, pkt.Length)
		tempGraph.AddOrUpdateNode(pkt.DstIP, dstHostname, pkt.Length)
		tempGraph.AddOrUpdateEdge(pkt.SrcIP, pkt.DstIP, pkt.Protocol, pkt.Length)
		tempGraph.AddPacket(pkt)
	}

	return tempGraph.GetSnapshot()
}

// resolveIPSync performs synchronous DNS resolution with caching
func resolveIPSync(ip string, cache map[string]string) string {
	// Check cache first
	if hostname, ok := cache[ip]; ok {
		return hostname
	}

	// Perform reverse lookup
	names, err := net.LookupAddr(ip)
	if err != nil || len(names) == 0 {
		cache[ip] = ip
		return ip
	}

	hostname := names[0]
	// Remove trailing dot if present
	hostname = strings.TrimSuffix(hostname, ".")

	// Cache the result
	cache[ip] = hostname

	return hostname
}
