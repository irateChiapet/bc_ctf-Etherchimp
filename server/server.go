package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
	"time"

	"go-etherape/graph"
	"go-etherape/stream"
)

// Server manages the HTTPS server
type Server struct {
	addr        string
	graphMgr    *Manager
	streamMgr   *stream.Manager
	server      *http.Server
	hub         *Hub
	rateLimiter *RateLimiter
}

// ServerConfig holds server configuration options
type ServerConfig struct {
	BindIP          string
	Port            int
	RateLimitConfig RateLimitConfig
	StreamMgr       *stream.Manager
	ReplayOnlyMode  bool
}

// DefaultServerConfig returns sensible defaults
func DefaultServerConfig(bindIP string, port int) ServerConfig {
	return ServerConfig{
		BindIP:          bindIP,
		Port:            port,
		RateLimitConfig: DefaultRateLimitConfig(),
	}
}

// NewServer creates a new HTTPS server
func NewServer(bindIP string, port int, graphMgr *graph.Manager) *Server {
	return NewServerWithConfig(DefaultServerConfig(bindIP, port), graphMgr)
}

// NewServerWithConfig creates a new HTTPS server with custom configuration
func NewServerWithConfig(config ServerConfig, graphMgr *graph.Manager) *Server {
	addr := fmt.Sprintf("%s:%d", config.BindIP, config.Port)
	hub := NewHub(graphMgr)

	return &Server{
		addr:        addr,
		graphMgr:    &Manager{graphMgr: graphMgr, streamMgr: config.StreamMgr},
		streamMgr:   config.StreamMgr,
		hub:         hub,
		rateLimiter: NewRateLimiter(config.RateLimitConfig),
	}
}

// Manager wraps the graph and stream managers for server use
type Manager struct {
	graphMgr  *graph.Manager
	streamMgr *stream.Manager
}

// Start starts the HTTPS server
func (s *Server) Start() error {
	// Generate TLS certificate if it doesn't exist
	certFile := "server.crt"
	keyFile := "server.key"

	if _, err := os.Stat(certFile); os.IsNotExist(err) {
		log.Println("Generating self-signed TLS certificate...")
		if err := generateSelfSignedCert(certFile, keyFile); err != nil {
			return fmt.Errorf("failed to generate certificate: %v", err)
		}
		log.Println("Certificate generated successfully")
	}

	// Start WebSocket hub
	go s.hub.Run()

	// Setup routes with rate limiting on API endpoints
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.graphMgr.handleIndex)
	mux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		handleWebSocket(s.hub, w, r)
	})
	// Apply rate limiting to API endpoints
	mux.HandleFunc("/api/graph", s.rateLimiter.RateLimitHandlerFunc(s.graphMgr.handleGraphAPI))
	mux.HandleFunc("/api/pcaps", s.rateLimiter.RateLimitHandlerFunc(s.graphMgr.handleListPcaps))
	mux.HandleFunc("/api/replay", s.rateLimiter.RateLimitHandlerFunc(s.graphMgr.handleReplayPcap))
	mux.HandleFunc("/api/download", s.rateLimiter.RateLimitHandlerFunc(s.graphMgr.handleDownloadCurrentPcap))
	// Stream API endpoints
	mux.HandleFunc("/api/streams", s.rateLimiter.RateLimitHandlerFunc(s.graphMgr.handleListStreams))
	mux.HandleFunc("/api/stream", s.rateLimiter.RateLimitHandlerFunc(s.graphMgr.handleGetStream))
	mux.HandleFunc("/api/streams/stats", s.rateLimiter.RateLimitHandlerFunc(s.graphMgr.handleGetStreamStats))
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	// Create HTTPS server
	s.server = &http.Server{
		Addr:         s.addr,
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start server
	return s.server.ListenAndServeTLS(certFile, keyFile)
}

// Shutdown gracefully shuts down the server
func (s *Server) Shutdown(ctx context.Context) error {
	return s.server.Shutdown(ctx)
}

// generateSelfSignedCert creates a self-signed TLS certificate
func generateSelfSignedCert(certFile, keyFile string) error {
	// Generate private key
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}

	// Create certificate template
	notBefore := time.Now()
	notAfter := notBefore.Add(365 * 24 * time.Hour) // Valid for 1 year

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"go-etherape"},
			CommonName:   "localhost",
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
	}

	// Create certificate
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return err
	}

	// Write certificate to file
	certOut, err := os.Create(certFile)
	if err != nil {
		return err
	}
	defer certOut.Close()

	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		return err
	}

	// Write private key to file
	keyOut, err := os.Create(keyFile)
	if err != nil {
		return err
	}
	defer keyOut.Close()

	privBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return err
	}

	if err := pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes}); err != nil {
		return err
	}

	return nil
}
