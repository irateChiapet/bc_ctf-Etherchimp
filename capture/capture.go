package capture

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

// PacketInfo contains parsed packet information
type PacketInfo struct {
	SrcIP    string
	DstIP    string
	SrcPort  uint16
	DstPort  uint16
	Protocol Protocol
	Length   int
	Payload  []byte // Raw packet payload data
}

// Capture manages packet capture from a network interface
type Capture struct {
	handle      *pcap.Handle
	packetChan  chan *PacketInfo
	pcapWriter  *pcapgo.Writer
	pcapFile    *os.File
	pcapDir     string
	enablePcap  bool
	paused      bool
	pauseChan   chan bool
	resumeChan  chan bool
}

// NewCapture creates a new packet capture instance
func NewCapture(iface string, packetChan chan *PacketInfo) (*Capture, error) {
	// Open device for capture
	handle, err := pcap.OpenLive(iface, 1600, true, pcap.BlockForever)
	if err != nil {
		return nil, fmt.Errorf("failed to open interface %s: %v", iface, err)
	}

	c := &Capture{
		handle:     handle,
		packetChan: packetChan,
		pcapDir:    "pcaps",
		enablePcap: true, // Enable pcap saving by default
		paused:     false,
		pauseChan:  make(chan bool, 1),
		resumeChan: make(chan bool, 1),
	}

	// Create pcaps directory if it doesn't exist
	if c.enablePcap {
		if err := os.MkdirAll(c.pcapDir, 0755); err != nil {
			log.Printf("Warning: Failed to create pcaps directory: %v", err)
			c.enablePcap = false
		} else {
			// Create initial pcap file
			if err := c.createPcapFile(); err != nil {
				log.Printf("Warning: Failed to create pcap file: %v", err)
				c.enablePcap = false
			}
		}
	}

	return c, nil
}

// createPcapFile creates a new pcap file with timestamp
func (c *Capture) createPcapFile() error {
	// Close existing file if open
	if c.pcapFile != nil {
		c.pcapFile.Close()
	}

	// Generate filename with timestamp
	timestamp := time.Now().Format("2006-01-02_15-04-05")
	filename := filepath.Join(c.pcapDir, fmt.Sprintf("capture_%s.pcap", timestamp))

	// Create file
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create pcap file: %v", err)
	}

	// Create pcap writer
	writer := pcapgo.NewWriter(file)
	if err := writer.WriteFileHeader(1600, c.handle.LinkType()); err != nil {
		file.Close()
		return fmt.Errorf("failed to write pcap header: %v", err)
	}

	c.pcapFile = file
	c.pcapWriter = writer

	log.Printf("Created pcap file: %s", filename)
	return nil
}

// Start begins packet capture and runs until context is cancelled
func (c *Capture) Start(ctx context.Context) {
	defer c.handle.Close()
	defer func() {
		if c.pcapFile != nil {
			c.pcapFile.Close()
			log.Println("Closed pcap file")
		}
	}()

	packetSource := gopacket.NewPacketSource(c.handle, c.handle.LinkType())
	log.Println("Packet capture started")
	if c.enablePcap {
		log.Printf("Saving packets to: %s/", c.pcapDir)
	}

	for {
		select {
		case <-ctx.Done():
			log.Println("Packet capture stopped")
			return
		case <-c.pauseChan:
			c.paused = true
			log.Println("Packet capture paused")
			// Wait for resume signal
			<-c.resumeChan
			c.paused = false
			log.Println("Packet capture resumed")
		case packet := <-packetSource.Packets():
			if !c.paused {
				c.processPacket(packet)
			}
		}
	}
}

// ProcessPacket extracts information from a packet (exported for replay usage)
func ProcessPacket(packet gopacket.Packet) *PacketInfo {
	// Extract IP addresses
	var srcIP, dstIP string

	// Try IPv4 first
	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		srcIP = ip.SrcIP.String()
		dstIP = ip.DstIP.String()
	} else if ipLayer := packet.Layer(layers.LayerTypeIPv6); ipLayer != nil {
		// Try IPv6
		ip, _ := ipLayer.(*layers.IPv6)
		srcIP = ip.SrcIP.String()
		dstIP = ip.DstIP.String()
	} else if arpLayer := packet.Layer(layers.LayerTypeARP); arpLayer != nil {
		// Handle ARP packets
		arp, _ := arpLayer.(*layers.ARP)
		srcIP = fmt.Sprintf("%d.%d.%d.%d", arp.SourceProtAddress[0], arp.SourceProtAddress[1],
			arp.SourceProtAddress[2], arp.SourceProtAddress[3])
		dstIP = fmt.Sprintf("%d.%d.%d.%d", arp.DstProtAddress[0], arp.DstProtAddress[1],
			arp.DstProtAddress[2], arp.DstProtAddress[3])
	} else {
		// Skip packets without IP information
		return nil
	}

	// Extract port information from transport layer
	var srcPort, dstPort uint16
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		srcPort = uint16(tcp.SrcPort)
		dstPort = uint16(tcp.DstPort)
	} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		srcPort = uint16(udp.SrcPort)
		dstPort = uint16(udp.DstPort)
	}
	// Note: ICMP and ARP don't have ports, so srcPort and dstPort will be 0

	// Detect protocol
	protocol := DetectProtocol(packet)

	// Get packet length and payload
	payload := packet.Data()
	length := len(payload)

	// Copy payload to avoid data race (packet data may be reused)
	payloadCopy := make([]byte, length)
	copy(payloadCopy, payload)

	return &PacketInfo{
		SrcIP:    srcIP,
		DstIP:    dstIP,
		SrcPort:  srcPort,
		DstPort:  dstPort,
		Protocol: protocol,
		Length:   length,
		Payload:  payloadCopy,
	}
}

// Pause pauses packet capture
func (c *Capture) Pause() {
	select {
	case c.pauseChan <- true:
	default:
		// Already paused or pause signal already sent
	}
}

// Resume resumes packet capture
func (c *Capture) Resume() {
	select {
	case c.resumeChan <- true:
	default:
		// Already resumed or resume signal already sent
	}
}

// processPacket extracts information from a packet and sends it to the channel
func (c *Capture) processPacket(packet gopacket.Packet) {
	// Write packet to pcap file if enabled
	if c.enablePcap && c.pcapWriter != nil {
		metadata := packet.Metadata()
		if err := c.pcapWriter.WritePacket(metadata.CaptureInfo, packet.Data()); err != nil {
			log.Printf("Warning: Failed to write packet to pcap: %v", err)
		}
	}

	// Process packet using shared function
	packetInfo := ProcessPacket(packet)
	if packetInfo == nil {
		return
	}

	// Send packet info to channel (non-blocking)
	select {
	case c.packetChan <- packetInfo:
	default:
		// Channel is full, drop packet to avoid blocking
	}
}
