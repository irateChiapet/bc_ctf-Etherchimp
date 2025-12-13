package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"go-etherape/capture"
	"go-etherape/daemon"
	"go-etherape/graph"
	"go-etherape/server"

	"github.com/google/gopacket/pcap"
)

func main() {
	// Parse command-line flags
	iface := flag.String("i", "", "Network interface to capture from (required)")
	port := flag.Int("p", 8443, "HTTPS server port")
	bindIP := flag.String("ip", "0.0.0.0", "IP address to bind server to")
	daemonCmd := flag.String("daemon", "", "Daemon command: start, stop, pause, resume, status")
	background := flag.Bool("background", false, "Run in background (internal use)")
	flag.Parse()

	// Handle daemon commands
	if *daemonCmd != "" {
		handleDaemonCommand(*daemonCmd)
		return
	}

	// Setup logging for background mode
	if *background {
		if err := daemon.SetupLogging(true); err != nil {
			log.Fatalf("Failed to setup logging: %v", err)
		}
		// Ensure PID file is removed on exit
		defer daemon.RemovePIDFileOnExit()
	}

	// Validate required flags
	if *iface == "" {
		fmt.Println("Error: Network interface (-i) is required")
		flag.Usage()
		os.Exit(1)
	}

	// Validate network interface exists
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatalf("Failed to enumerate network interfaces: %v", err)
	}

	interfaceExists := false
	for _, device := range devices {
		if device.Name == *iface {
			interfaceExists = true
			break
		}
	}

	if !interfaceExists {
		log.Fatalf("Network interface '%s' not found. Available interfaces:", *iface)
	}

	log.Printf("Starting go-etherape...")
	log.Printf("  Interface: %s", *iface)
	log.Printf("  Server: https://%s:%d", *bindIP, *port)

	// Create context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Initialize graph manager
	graphMgr := graph.NewManager()

	// Start DNS resolver
	dnsResolver := graph.NewDNSResolver()
	dnsResolver.Start(ctx)

	// Start decay manager
	decayMgr := graph.NewDecayManager(graphMgr, 60) // 60 second timeout
	decayMgr.Start(ctx)

	// Initialize packet capture
	packetChan := make(chan *capture.PacketInfo, 1000)
	captureEngine, err := capture.NewCapture(*iface, packetChan)
	if err != nil {
		log.Fatalf("Failed to initialize packet capture: %v", err)
	}

	// Setup signal handlers for pause/resume
	pauseSigChan := make(chan os.Signal, 1)
	resumeSigChan := make(chan os.Signal, 1)
	signal.Notify(pauseSigChan, syscall.SIGUSR1)
	signal.Notify(resumeSigChan, syscall.SIGUSR2)

	// Handle pause/resume signals
	go func() {
		for {
			select {
			case <-pauseSigChan:
				log.Println("Received pause signal")
				captureEngine.Pause()
			case <-resumeSigChan:
				log.Println("Received resume signal")
				captureEngine.Resume()
			case <-ctx.Done():
				return
			}
		}
	}()

	// Start packet capture
	go captureEngine.Start(ctx)

	// Process packets and update graph
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case pkt := <-packetChan:
				// Resolve hostnames asynchronously
				srcHostname := dnsResolver.Resolve(pkt.SrcIP)
				dstHostname := dnsResolver.Resolve(pkt.DstIP)

				// Update graph
				graphMgr.AddOrUpdateNode(pkt.SrcIP, srcHostname, pkt.Length)
				graphMgr.AddOrUpdateNode(pkt.DstIP, dstHostname, pkt.Length)
				graphMgr.AddOrUpdateEdge(pkt.SrcIP, pkt.DstIP, pkt.Protocol, pkt.Length)

				// Store packet with payload for inspection
				graphMgr.AddPacket(pkt)
			}
		}
	}()

	// Initialize and start HTTPS server
	srv := server.NewServer(*bindIP, *port, graphMgr)
	go func() {
		if err := srv.Start(); err != nil {
			log.Fatalf("Server failed: %v", err)
		}
	}()

	log.Printf("Server started successfully. Visit https://%s:%d (accept the self-signed certificate warning)", *bindIP, *port)
	log.Printf("Press Ctrl+C to stop...")

	// Wait for interrupt signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan

	log.Println("Shutting down gracefully...")
	cancel()
	srv.Shutdown(context.Background())
	log.Println("Shutdown complete")
}

// handleDaemonCommand handles daemon control commands
func handleDaemonCommand(cmd string) {
	switch cmd {
	case "start":
		if err := daemon.Daemonize(); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to start daemon: %v\n", err)
			os.Exit(1)
		}
	case "stop":
		if err := daemon.Stop(); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to stop daemon: %v\n", err)
			os.Exit(1)
		}
	case "pause":
		if err := daemon.Pause(); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to pause daemon: %v\n", err)
			os.Exit(1)
		}
	case "resume":
		if err := daemon.Resume(); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to resume daemon: %v\n", err)
			os.Exit(1)
		}
	case "status":
		daemon.Status()
	default:
		fmt.Fprintf(os.Stderr, "Unknown daemon command: %s\n", cmd)
		fmt.Println("Valid commands: start, stop, pause, resume, status")
		os.Exit(1)
	}
}
