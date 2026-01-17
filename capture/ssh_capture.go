package capture

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"golang.org/x/crypto/ssh"
)

// SSHCaptureConfig holds configuration for SSH-based remote capture
type SSHCaptureConfig struct {
	Host       string // SSH host (host:port format)
	Interface  string // Remote interface to capture from
	PrivateKey string // Path to private key file (for key-based auth)
	Username   string // SSH username
	Password   string // SSH password (for password-based auth)
}

// SSHCapture manages packet capture from a remote host via SSH
type SSHCapture struct {
	config      SSHCaptureConfig
	packetChan  chan *PacketInfo
	sshClient   *ssh.Client
	sshSession  *ssh.Session
	pcapWriter  *pcapgo.Writer
	pcapFile    *os.File
	pcapDir     string
	enablePcap  bool
	paused      bool
	pauseChan   chan bool
	resumeChan  chan bool
}

// NewSSHCapture creates a new SSH-based packet capture instance
func NewSSHCapture(config SSHCaptureConfig, packetChan chan *PacketInfo) (*SSHCapture, error) {
	c := &SSHCapture{
		config:     config,
		packetChan: packetChan,
		pcapDir:    "pcaps",
		enablePcap: true,
		paused:     false,
		pauseChan:  make(chan bool, 1),
		resumeChan: make(chan bool, 1),
	}

	// Create pcaps directory if it doesn't exist
	if c.enablePcap {
		if err := os.MkdirAll(c.pcapDir, 0755); err != nil {
			log.Printf("Warning: Failed to create pcaps directory: %v", err)
			c.enablePcap = false
		}
	}

	return c, nil
}

// buildSSHConfig builds SSH client configuration based on auth method
func (c *SSHCapture) buildSSHConfig() (*ssh.ClientConfig, error) {
	var authMethods []ssh.AuthMethod

	if c.config.PrivateKey != "" {
		// Key-based authentication
		key, err := os.ReadFile(c.config.PrivateKey)
		if err != nil {
			return nil, fmt.Errorf("failed to read private key: %v", err)
		}

		signer, err := ssh.ParsePrivateKey(key)
		if err != nil {
			return nil, fmt.Errorf("failed to parse private key: %v", err)
		}

		authMethods = append(authMethods, ssh.PublicKeys(signer))
	} else if c.config.Password != "" {
		// Password-based authentication
		authMethods = append(authMethods, ssh.Password(c.config.Password))
	} else {
		return nil, fmt.Errorf("no authentication method provided (need -pkey or -pass)")
	}

	config := &ssh.ClientConfig{
		User:            c.config.Username,
		Auth:            authMethods,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // In production, use known_hosts
		Timeout:         30 * time.Second,
	}

	return config, nil
}

// Start begins SSH packet capture and runs until context is cancelled
func (c *SSHCapture) Start(ctx context.Context) {
	defer func() {
		if c.sshSession != nil {
			c.sshSession.Close()
		}
		if c.sshClient != nil {
			c.sshClient.Close()
		}
		if c.pcapFile != nil {
			c.pcapFile.Close()
			log.Println("Closed pcap file")
		}
	}()

	// Build SSH config
	sshConfig, err := c.buildSSHConfig()
	if err != nil {
		log.Printf("SSH config error: %v", err)
		return
	}

	// Connect to SSH server
	log.Printf("Connecting to SSH server %s...", c.config.Host)
	client, err := ssh.Dial("tcp", c.config.Host, sshConfig)
	if err != nil {
		log.Printf("Failed to connect to SSH server: %v", err)
		return
	}
	c.sshClient = client
	log.Printf("SSH connection established")

	// Create session
	session, err := client.NewSession()
	if err != nil {
		log.Printf("Failed to create SSH session: %v", err)
		return
	}
	c.sshSession = session

	// Get stdout pipe for tcpdump output
	stdout, err := session.StdoutPipe()
	if err != nil {
		log.Printf("Failed to get stdout pipe: %v", err)
		return
	}

	// Get stderr for error messages
	stderr, err := session.StderrPipe()
	if err != nil {
		log.Printf("Failed to get stderr pipe: %v", err)
		return
	}

	// Log stderr in background
	go func() {
		buf := make([]byte, 1024)
		for {
			n, err := stderr.Read(buf)
			if n > 0 {
				log.Printf("SSH stderr: %s", string(buf[:n]))
			}
			if err != nil {
				return
			}
		}
	}()

	// Build tcpdump command
	// -U: packet-buffered output (unbuffered)
	// -w -: write to stdout
	// -i: interface
	// -s 0: capture full packets
	// Exclude SSH management connection to avoid recording our own control traffic
	sshHost, sshPort, err := net.SplitHostPort(c.config.Host)
	if err != nil {
		// If no port specified, assume host only and default SSH port
		sshHost = c.config.Host
		sshPort = "22"
	}
	// BPF filter to exclude traffic to/from the SSH management connection
	bpfFilter := fmt.Sprintf("not (host %s and port %s)", sshHost, sshPort)
	tcpdumpCmd := fmt.Sprintf("sudo tcpdump -U -w - -i %s -s 0 '%s'", c.config.Interface, bpfFilter)
	log.Printf("Starting remote capture: %s", tcpdumpCmd)

	// Start tcpdump
	if err := session.Start(tcpdumpCmd); err != nil {
		log.Printf("Failed to start tcpdump: %v", err)
		return
	}

	log.Println("Remote packet capture started")

	// Create pcap file for local storage
	if c.enablePcap {
		if err := c.createPcapFile(); err != nil {
			log.Printf("Warning: Failed to create pcap file: %v", err)
			c.enablePcap = false
		} else {
			log.Printf("Saving packets to: %s/", c.pcapDir)
		}
	}

	// Read and process pcap stream
	c.processPcapStream(ctx, stdout)

	// Wait for session to complete
	if err := session.Wait(); err != nil {
		log.Printf("SSH session ended: %v", err)
	}

	log.Println("Remote packet capture stopped")
}

// createPcapFile creates a new pcap file with timestamp
func (c *SSHCapture) createPcapFile() error {
	if c.pcapFile != nil {
		c.pcapFile.Close()
	}

	timestamp := time.Now().Format("2006-01-02_15-04-05")
	filename := fmt.Sprintf("%s/ssh_capture_%s.pcap", c.pcapDir, timestamp)

	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create pcap file: %v", err)
	}

	writer := pcapgo.NewWriter(file)
	// Write pcap header with Ethernet link type
	if err := writer.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		file.Close()
		return fmt.Errorf("failed to write pcap header: %v", err)
	}

	c.pcapFile = file
	c.pcapWriter = writer

	log.Printf("Created pcap file: %s", filename)
	return nil
}

// processPcapStream reads and processes the pcap stream from SSH
func (c *SSHCapture) processPcapStream(ctx context.Context, reader io.Reader) {
	// Create a pcap reader from the stream
	pcapReader, err := pcapgo.NewReader(reader)
	if err != nil {
		log.Printf("Failed to create pcap reader: %v", err)
		return
	}

	linkType := pcapReader.LinkType()

	for {
		select {
		case <-ctx.Done():
			return
		case <-c.pauseChan:
			c.paused = true
			log.Println("SSH packet capture paused")
			<-c.resumeChan
			c.paused = false
			log.Println("SSH packet capture resumed")
		default:
			if c.paused {
				time.Sleep(100 * time.Millisecond)
				continue
			}

			// Read next packet
			data, ci, err := pcapReader.ReadPacketData()
			if err != nil {
				if err == io.EOF {
					log.Println("SSH pcap stream ended")
					return
				}
				log.Printf("Error reading packet: %v", err)
				continue
			}

			// Write to local pcap file
			if c.enablePcap && c.pcapWriter != nil {
				if err := c.pcapWriter.WritePacket(ci, data); err != nil {
					log.Printf("Warning: Failed to write packet to pcap: %v", err)
				}
			}

			// Parse packet
			packet := gopacket.NewPacket(data, linkType, gopacket.Default)
			packetInfo := ProcessPacket(packet)
			if packetInfo == nil {
				continue
			}

			// Send packet info to channel (non-blocking)
			select {
			case c.packetChan <- packetInfo:
			default:
				// Channel is full, drop packet
			}
		}
	}
}

// Pause pauses SSH packet capture
func (c *SSHCapture) Pause() {
	select {
	case c.pauseChan <- true:
	default:
	}
}

// Resume resumes SSH packet capture
func (c *SSHCapture) Resume() {
	select {
	case c.resumeChan <- true:
	default:
	}
}
