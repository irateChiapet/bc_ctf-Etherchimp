package server

import (
	"net/http"
	"sync"
	"time"
)

// RateLimiter implements a token bucket rate limiter per IP address
type RateLimiter struct {
	mu           sync.RWMutex
	clients      map[string]*clientBucket
	rate         float64       // tokens per second
	burst        int           // max tokens (bucket size)
	cleanupEvery time.Duration // how often to clean up stale entries
	maxAge       time.Duration // max age before a client entry is removed
}

// clientBucket tracks rate limit state for a single client
type clientBucket struct {
	tokens     float64
	lastUpdate time.Time
	lastAccess time.Time
}

// RateLimitConfig holds configuration for the rate limiter
type RateLimitConfig struct {
	RequestsPerSecond float64 // tokens added per second
	BurstSize         int     // maximum tokens (allows bursts)
	CleanupInterval   time.Duration
	ClientMaxAge      time.Duration
}

// DefaultRateLimitConfig returns sensible defaults
func DefaultRateLimitConfig() RateLimitConfig {
	return RateLimitConfig{
		RequestsPerSecond: 10.0,          // 10 requests per second sustained
		BurstSize:         50,            // allow bursts of up to 50 requests
		CleanupInterval:   5 * time.Minute,
		ClientMaxAge:      10 * time.Minute,
	}
}

// NewRateLimiter creates a new rate limiter with the given configuration
func NewRateLimiter(config RateLimitConfig) *RateLimiter {
	rl := &RateLimiter{
		clients:      make(map[string]*clientBucket),
		rate:         config.RequestsPerSecond,
		burst:        config.BurstSize,
		cleanupEvery: config.CleanupInterval,
		maxAge:       config.ClientMaxAge,
	}

	// Start background cleanup goroutine
	go rl.cleanupLoop()

	return rl
}

// Allow checks if a request from the given IP should be allowed
func (rl *RateLimiter) Allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	bucket, exists := rl.clients[ip]

	if !exists {
		// New client, create bucket with full tokens
		rl.clients[ip] = &clientBucket{
			tokens:     float64(rl.burst) - 1, // consume one token for this request
			lastUpdate: now,
			lastAccess: now,
		}
		return true
	}

	// Calculate tokens to add based on time elapsed
	elapsed := now.Sub(bucket.lastUpdate).Seconds()
	bucket.tokens += elapsed * rl.rate

	// Cap at burst size
	if bucket.tokens > float64(rl.burst) {
		bucket.tokens = float64(rl.burst)
	}

	bucket.lastUpdate = now
	bucket.lastAccess = now

	// Check if we have tokens available
	if bucket.tokens >= 1 {
		bucket.tokens--
		return true
	}

	return false
}

// cleanupLoop periodically removes stale client entries
func (rl *RateLimiter) cleanupLoop() {
	ticker := time.NewTicker(rl.cleanupEvery)
	defer ticker.Stop()

	for range ticker.C {
		rl.cleanup()
	}
}

// cleanup removes client entries that haven't been accessed recently
func (rl *RateLimiter) cleanup() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	for ip, bucket := range rl.clients {
		if now.Sub(bucket.lastAccess) > rl.maxAge {
			delete(rl.clients, ip)
		}
	}
}

// GetClientIP extracts the client IP from the request
func GetClientIP(r *http.Request) string {
	// Check X-Forwarded-For header (be cautious with this in production)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Take the first IP in the list
		for i := 0; i < len(xff); i++ {
			if xff[i] == ',' {
				return xff[:i]
			}
		}
		return xff
	}

	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}

	// Fall back to RemoteAddr (strip port)
	ip := r.RemoteAddr
	for i := len(ip) - 1; i >= 0; i-- {
		if ip[i] == ':' {
			return ip[:i]
		}
		if ip[i] == ']' {
			// IPv6 address without port
			return ip
		}
	}
	return ip
}

// RateLimitMiddleware creates HTTP middleware that enforces rate limits
func (rl *RateLimiter) RateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := GetClientIP(r)

		if !rl.Allow(ip) {
			w.Header().Set("Retry-After", "1")
			http.Error(w, "Rate limit exceeded. Please slow down.", http.StatusTooManyRequests)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// RateLimitHandlerFunc wraps a handler function with rate limiting
func (rl *RateLimiter) RateLimitHandlerFunc(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := GetClientIP(r)

		if !rl.Allow(ip) {
			w.Header().Set("Retry-After", "1")
			http.Error(w, "Rate limit exceeded. Please slow down.", http.StatusTooManyRequests)
			return
		}

		handler(w, r)
	}
}

// Stats returns current rate limiter statistics
func (rl *RateLimiter) Stats() map[string]interface{} {
	rl.mu.RLock()
	defer rl.mu.RUnlock()

	return map[string]interface{}{
		"active_clients":      len(rl.clients),
		"rate_per_second":     rl.rate,
		"burst_size":          rl.burst,
		"cleanup_interval_ms": rl.cleanupEvery.Milliseconds(),
		"client_max_age_ms":   rl.maxAge.Milliseconds(),
	}
}
