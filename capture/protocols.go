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
	ProtocolInfluxDB   = Protocol{"InfluxDB", "#22ADF6"}
	ProtocolSlurm      = Protocol{"Slurm", "#ff7f50"}
	ProtocolARP        = Protocol{"ARP", "#95a5a6"}
	ProtocolIPv6       = Protocol{"IPv6", "#7f8c8d"}
	ProtocolOther      = Protocol{"Other", "#ecf0f1"}
)

// DetectProtocol analyzes a packet and returns the detected protocol.
// Works with both IPv4 and IPv6 packets - gopacket extracts transport layers from either.
func DetectProtocol(packet gopacket.Packet) Protocol {
	// Check for ARP (IPv4 only)
	if packet.Layer(layers.LayerTypeARP) != nil {
		return ProtocolARP
	}

	// Check for ICMP (both IPv4 and IPv6)
	if packet.Layer(layers.LayerTypeICMPv4) != nil || packet.Layer(layers.LayerTypeICMPv6) != nil {
		return ProtocolICMP
	}

	// Check for TCP-based protocols (works for both IPv4 and IPv6)
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		return detectTCPProtocol(tcp)
	}

	// Check for UDP-based protocols (works for both IPv4 and IPv6)
	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		return detectUDPProtocol(udp)
	}

	// IPv6 packets without TCP/UDP/ICMP (e.g., neighbor discovery, router advertisements)
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
	case srcPort == 8086 || dstPort == 8086:
		return ProtocolInfluxDB
	case srcPort == 6817 || dstPort == 6817:
		return ProtocolSlurm // slurmctld
	case srcPort == 6818 || dstPort == 6818:
		return ProtocolSlurm // slurmd
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
		ProtocolInfluxDB,
		ProtocolSlurm,
		ProtocolARP,
		ProtocolIPv6,
		ProtocolOther,
	}
}
