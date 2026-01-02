package core

import (
	"net/http"
	"sync"
	"time"
)

// ✅ SECURITY FIX: Rate limiter to prevent brute force attacks
type RateLimiter struct {
	attempts map[string][]time.Time
	mu       sync.RWMutex
	max      int
	window   time.Duration
}

func NewRateLimiter(max int, window time.Duration) *RateLimiter {
	rl := &RateLimiter{
		attempts: make(map[string][]time.Time),
		max:      max,
		window:   window,
	}
	
	// Clean up old entries periodically
	go rl.cleanup()
	
	return rl
}

func (rl *RateLimiter) Allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	
	now := time.Now()
	attempts := rl.attempts[ip]
	
	// Remove old attempts outside the window
	var recent []time.Time
	for _, t := range attempts {
		if now.Sub(t) < rl.window {
			recent = append(recent, t)
		}
	}
	
	// Check if limit exceeded
	if len(recent) >= rl.max {
		return false
	}
	
	// Add current attempt
	recent = append(recent, now)
	rl.attempts[ip] = recent
	
	return true
}

func (rl *RateLimiter) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	
	for range ticker.C {
		rl.mu.Lock()
		now := time.Now()
		for ip, attempts := range rl.attempts {
			var recent []time.Time
			for _, t := range attempts {
				if now.Sub(t) < rl.window {
					recent = append(recent, t)
				}
			}
			if len(recent) == 0 {
				delete(rl.attempts, ip)
			} else {
				rl.attempts[ip] = recent
			}
		}
		rl.mu.Unlock()
	}
}

func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header first
	ip := r.Header.Get("X-Forwarded-For")
	if ip == "" {
		ip = r.Header.Get("X-Real-IP")
	}
	if ip == "" {
		ip = r.RemoteAddr
	}
	return ip
}

