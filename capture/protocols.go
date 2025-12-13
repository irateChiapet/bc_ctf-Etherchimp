package capture

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// Protocol represents a detected network protocol with its display properties
type Protocol struct {
	Name  string
	Color string
}

// Protocol color scheme
var (
	ProtocolTCP        = Protocol{"TCP", "#3498db"}
	ProtocolUDP        = Protocol{"UDP", "#2ecc71"}
	ProtocolICMP       = Protocol{"ICMP", "#f39c12"}
	ProtocolHTTP       = Protocol{"HTTP", "#e67e22"}
	ProtocolHTTPS      = Protocol{"HTTPS", "#9b59b6"}
	ProtocolDNS        = Protocol{"DNS", "#1abc9c"}
	ProtocolSSH        = Protocol{"SSH", "#e74c3c"}
	ProtocolFTP        = Protocol{"FTP", "#ff6b9d"}
	ProtocolSMTP       = Protocol{"SMTP", "#8b4513"}
	ProtocolMySQL      = Protocol{"MySQL", "#34495e"}
	ProtocolPostgreSQL = Protocol{"PostgreSQL", "#16a085"}
	ProtocolARP        = Protocol{"ARP", "#95a5a6"}
	ProtocolIPv6       = Protocol{"IPv6", "#7f8c8d"}
	ProtocolOther      = Protocol{"Other", "#ecf0f1"}
)

// DetectProtocol analyzes a packet and returns the detected protocol
func DetectProtocol(packet gopacket.Packet) Protocol {
	// Check for ARP
	if packet.Layer(layers.LayerTypeARP) != nil {
		return ProtocolARP
	}

	// Check for ICMP
	if packet.Layer(layers.LayerTypeICMPv4) != nil || packet.Layer(layers.LayerTypeICMPv6) != nil {
		return ProtocolICMP
	}

	// Check for TCP-based protocols
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		return detectTCPProtocol(tcp)
	}

	// Check for UDP-based protocols
	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		return detectUDPProtocol(udp)
	}

	// Check if it's IPv6
	if packet.Layer(layers.LayerTypeIPv6) != nil {
		return ProtocolIPv6
	}

	return ProtocolOther
}

// detectTCPProtocol detects application-layer protocols over TCP
func detectTCPProtocol(tcp *layers.TCP) Protocol {
	srcPort := uint16(tcp.SrcPort)
	dstPort := uint16(tcp.DstPort)

	// Check common TCP ports
	switch {
	case srcPort == 80 || dstPort == 80:
		return ProtocolHTTP
	case srcPort == 443 || dstPort == 443:
		return ProtocolHTTPS
	case srcPort == 22 || dstPort == 22:
		return ProtocolSSH
	case srcPort == 21 || dstPort == 21:
		return ProtocolFTP
	case srcPort == 20 || dstPort == 20:
		return ProtocolFTP // FTP data
	case srcPort == 25 || dstPort == 25:
		return ProtocolSMTP
	case srcPort == 587 || dstPort == 587:
		return ProtocolSMTP // Submission
	case srcPort == 3306 || dstPort == 3306:
		return ProtocolMySQL
	case srcPort == 5432 || dstPort == 5432:
		return ProtocolPostgreSQL
	case srcPort == 8080 || dstPort == 8080:
		return ProtocolHTTP // Alternative HTTP
	case srcPort == 8443 || dstPort == 8443:
		return ProtocolHTTPS // Alternative HTTPS
	default:
		return ProtocolTCP
	}
}

// detectUDPProtocol detects application-layer protocols over UDP
func detectUDPProtocol(udp *layers.UDP) Protocol {
	srcPort := uint16(udp.SrcPort)
	dstPort := uint16(udp.DstPort)

	// Check common UDP ports
	switch {
	case srcPort == 53 || dstPort == 53:
		return ProtocolDNS
	default:
		return ProtocolUDP
	}
}

// GetAllProtocols returns a list of all supported protocols with their colors
func GetAllProtocols() []Protocol {
	return []Protocol{
		ProtocolTCP,
		ProtocolUDP,
		ProtocolICMP,
		ProtocolHTTP,
		ProtocolHTTPS,
		ProtocolDNS,
		ProtocolSSH,
		ProtocolFTP,
		ProtocolSMTP,
		ProtocolMySQL,
		ProtocolPostgreSQL,
		ProtocolARP,
		ProtocolIPv6,
		ProtocolOther,
	}
}
