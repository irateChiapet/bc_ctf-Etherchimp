package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"go-etherape/capture"
	"go-etherape/daemon"
	"go-etherape/graph"
	"go-etherape/replay"
	"go-etherape/server"
	"go-etherape/stream"

	"github.com/google/gopacket/pcap"
)

func main() {
	// Parse command-line flags
	iface := flag.String("i", "", "Network interface to capture from (required for capture mode)")
	replayFile := flag.String("f", "", "Pcap file path for replay-only mode (disables live capture)")
	port := flag.Int("p", 8443, "HTTPS server port")
	bindIP := flag.String("ip", "0.0.0.0", "IP address to bind server to")
	daemonCmd := flag.String("daemon", "", "Daemon command: start, stop, pause, resume, status, rotate-logs, log-status, cleanup-logs")
	background := flag.Bool("background", false, "Run in background (internal use)")

	// Rate limiting flags
	rateLimit := flag.Float64("rate-limit", 10.0, "API requests per second per client")
	rateBurst := flag.Int("rate-burst", 50, "Maximum burst size for rate limiting")

	// Log rotation flags
	logMaxSize := flag.String("log-max-size", "10MB", "Maximum log file size before rotation (e.g., 10MB, 1GB)")
	logMaxBackups := flag.Int("log-max-backups", 5, "Maximum number of backup log files to keep")
	logMaxAge := flag.Int("log-max-age", 30, "Maximum age of backup log files in days (0 = no limit)")
	logCompress := flag.Bool("log-compress", true, "Compress rotated log files")
	logCheckInterval := flag.Int("log-check-interval", 60, "Log rotation check interval in seconds")
	enableLogRotation := flag.Bool("enable-log-rotation", true, "Enable automatic log rotation")

	flag.Parse()

	// Build log rotation config from flags
	logRotateConfig := buildLogRotateConfig(*logMaxSize, *logMaxBackups, *logMaxAge, *logCompress, *logCheckInterval)

	// Handle daemon commands
	if *daemonCmd != "" {
		handleDaemonCommand(*daemonCmd, logRotateConfig)
		return
	}

	// Setup logging for background mode
	if *background {
		if err := daemon.SetupLogging(true); err != nil {
			log.Fatalf("Failed to setup logging: %v", err)
		}
		// Ensure PID file is removed on exit
		defer daemon.RemovePIDFileOnExit()

		// Start log rotation if enabled
		if *enableLogRotation {
			if err := daemon.StartLogRotation(logRotateConfig); err != nil {
				log.Printf("Warning: Failed to start log rotation: %v", err)
			} else {
				defer daemon.StopLogRotation()
			}
		}
	}

	// Determine mode based on flags
	replayOnlyMode := *replayFile != ""

	// Validate flags based on mode
	if replayOnlyMode {
		// Replay-only mode: -f is specified, -i is not allowed
		if *iface != "" {
			fmt.Println("Error: Cannot use -i (interface) with -f (replay file)")
			fmt.Println("  -f enables replay-only mode which does not capture from interfaces")
			os.Exit(1)
		}

		// Validate replay file exists
		if _, err := os.Stat(*replayFile); os.IsNotExist(err) {
			log.Fatalf("Replay file not found: %s", *replayFile)
		}
	} else {
		// Capture mode: -i is required
		if *iface == "" {
			fmt.Println("Error: Either -i (interface) or -f (replay file) is required")
			fmt.Println("  -i: Network interface for live capture mode")
			fmt.Println("  -f: Pcap file for replay-only mode")
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
	}

	// Create context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Initialize graph manager
	graphMgr := graph.NewManager()

	// Initialize stream manager (track last 1000 streams)
	streamMgr := stream.NewManager(1000)

	if replayOnlyMode {
		// REPLAY-ONLY MODE
		log.Printf("Starting go-etherape in REPLAY-ONLY mode...")
		log.Printf("  Replay file: %s", *replayFile)
		log.Printf("  Server: https://%s:%d", *bindIP, *port)

		// Load the initial pcap file and populate the graph
		reader, err := replay.NewReader(*replayFile)
		if err != nil {
			log.Fatalf("Failed to load replay file: %v", err)
		}

		// Get all packets from the file (full replay)
		allPackets := reader.GetPacketsUpToTime(reader.GetDuration().Seconds() + 1)
		reader.Close()

		log.Printf("  Loaded %d packets from replay file", len(allPackets))
		log.Printf("  Duration: %.2f seconds", reader.GetDuration().Seconds())

		// Populate graph with all packets
		for _, pwt := range allPackets {
			pkt := pwt.Info
			graphMgr.AddOrUpdateNode(pkt.SrcIP, pkt.SrcIP, pkt.Length)
			graphMgr.AddOrUpdateNode(pkt.DstIP, pkt.DstIP, pkt.Length)
			graphMgr.AddOrUpdateEdge(pkt.SrcIP, pkt.DstIP, pkt.Protocol, pkt.Length)
			graphMgr.AddPacket(pkt)
			streamMgr.AddPacket(pkt)
		}

		log.Printf("  Stream tracking: enabled")
	} else {
		// CAPTURE MODE (original behavior)
		log.Printf("Starting go-etherape...")
		log.Printf("  Interface: %s", *iface)
		log.Printf("  Server: https://%s:%d", *bindIP, *port)
		log.Printf("  Stream tracking: enabled")

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

					// Add packet to stream tracking
					streamMgr.AddPacket(pkt)
				}
			}
		}()
	}

	// Build server config with rate limiting
	serverConfig := server.ServerConfig{
		BindIP: *bindIP,
		Port:   *port,
		RateLimitConfig: server.RateLimitConfig{
			RequestsPerSecond: *rateLimit,
			BurstSize:         *rateBurst,
			CleanupInterval:   5 * time.Minute,
			ClientMaxAge:      10 * time.Minute,
		},
		StreamMgr:      streamMgr,
		ReplayOnlyMode: replayOnlyMode,
	}

	// Initialize and start HTTPS server
	srv := server.NewServerWithConfig(serverConfig, graphMgr)
	go func() {
		if err := srv.Start(); err != nil {
			log.Fatalf("Server failed: %v", err)
		}
	}()

	if replayOnlyMode {
		log.Printf("Replay-only server started. Visit https://%s:%d (accept the self-signed certificate warning)", *bindIP, *port)
		log.Printf("Live capture is disabled. Use the web UI to analyze the loaded pcap file.")
	} else {
		log.Printf("Server started successfully. Visit https://%s:%d (accept the self-signed certificate warning)", *bindIP, *port)
	}
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
func handleDaemonCommand(cmd string, logConfig daemon.LogRotateConfig) {
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
	case "rotate-logs":
		fmt.Println("Rotating logs...")
		if err := daemon.RotateLogs(logConfig); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to rotate logs: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Log rotation complete")
	case "log-status":
		daemon.GetLogRotateStatus()
	case "cleanup-logs":
		fmt.Println("Cleaning up all log files...")
		if err := daemon.CleanupAllLogs(); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to cleanup logs: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Log cleanup complete")
	default:
		fmt.Fprintf(os.Stderr, "Unknown daemon command: %s\n", cmd)
		fmt.Println("Valid commands: start, stop, pause, resume, status, rotate-logs, log-status, cleanup-logs")
		os.Exit(1)
	}
}

// buildLogRotateConfig parses CLI flags into a LogRotateConfig
func buildLogRotateConfig(maxSize string, maxBackups, maxAge int, compress bool, checkInterval int) daemon.LogRotateConfig {
	config := daemon.DefaultLogRotateConfig()

	// Parse size string
	if size, err := daemon.ParseSizeString(maxSize); err == nil && size > 0 {
		config.MaxSizeBytes = size
	}

	if maxBackups >= 0 {
		config.MaxBackups = maxBackups
	}
	if maxAge >= 0 {
		config.MaxAgeDays = maxAge
	}
	config.Compress = compress
	if checkInterval > 0 {
		config.CheckInterval = time.Duration(checkInterval) * time.Second
	}

	return config
}
