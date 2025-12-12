package graph

import (
	"context"
	"net"
	"sync"
	"time"
)

// DNSResolver performs reverse DNS lookups with caching
type DNSResolver struct {
	cache      map[string]string
	cacheMu    sync.RWMutex
	lookupChan chan string
}

// NewDNSResolver creates a new DNS resolver
func NewDNSResolver() *DNSResolver {
	return &DNSResolver{
		cache:      make(map[string]string),
		lookupChan: make(chan string, 100),
	}
}

// Start begins the DNS resolution worker pool
func (r *DNSResolver) Start(ctx context.Context) {
	// Start multiple worker goroutines for concurrent lookups
	for i := 0; i < 10; i++ {
		go r.worker(ctx)
	}
}

// worker processes DNS lookup requests
func (r *DNSResolver) worker(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case ip := <-r.lookupChan:
			r.performLookup(ip)
		}
	}
}

// Resolve returns the hostname for an IP, using cache or triggering a lookup
func (r *DNSResolver) Resolve(ip string) string {
	// Check cache first
	r.cacheMu.RLock()
	hostname, exists := r.cache[ip]
	r.cacheMu.RUnlock()

	if exists {
		return hostname
	}

	// Queue for lookup (non-blocking)
	select {
	case r.lookupChan <- ip:
	default:
		// Channel full, skip this lookup
	}

	// Return IP for now (will be updated once lookup completes)
	return ip
}

// performLookup does the actual reverse DNS lookup with timeout
func (r *DNSResolver) performLookup(ip string) {
	// Check if already in cache (might have been added by another worker)
	r.cacheMu.RLock()
	_, exists := r.cache[ip]
	r.cacheMu.RUnlock()

	if exists {
		return
	}

	// Perform lookup with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	names, err := net.DefaultResolver.LookupAddr(ctx, ip)

	hostname := ip
	if err == nil && len(names) > 0 {
		hostname = names[0]
		// Remove trailing dot if present
		if len(hostname) > 0 && hostname[len(hostname)-1] == '.' {
			hostname = hostname[:len(hostname)-1]
		}
	}

	// Store in cache
	r.cacheMu.Lock()
	r.cache[ip] = hostname
	r.cacheMu.Unlock()
}

// GetCacheSize returns the current number of cached entries
func (r *DNSResolver) GetCacheSize() int {
	r.cacheMu.RLock()
	defer r.cacheMu.RUnlock()
	return len(r.cache)
}

// ResolveSync performs synchronous DNS resolution (for replay mode)
func (r *DNSResolver) ResolveSync(ip string) string {
	// Check cache first
	r.cacheMu.RLock()
	if hostname, ok := r.cache[ip]; ok {
		r.cacheMu.RUnlock()
		return hostname
	}
	r.cacheMu.RUnlock()

	// Perform reverse lookup with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	names, err := net.DefaultResolver.LookupAddr(ctx, ip)
	if err != nil || len(names) == 0 {
		r.cacheMu.Lock()
		r.cache[ip] = ip
		r.cacheMu.Unlock()
		return ip
	}

	hostname := names[0]
	// Remove trailing dot if present
	if len(hostname) > 0 && hostname[len(hostname)-1] == '.' {
		hostname = hostname[:len(hostname)-1]
	}

	// Cache the result
	r.cacheMu.Lock()
	r.cache[ip] = hostname
	r.cacheMu.Unlock()

	return hostname
}
