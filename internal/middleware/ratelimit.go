package middleware

import (
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

// RateLimit defines the limit for a specific endpoint or group
type RateLimit struct {
	Requests int
	Window   time.Duration
}

// RateLimiter handles rate limiting using in-memory storage
type RateLimiter struct {
	mu       sync.RWMutex
	requests map[string]*clientRequests
	limits   map[string]*RateLimit
}

type clientRequests struct {
	count   int
	resetAt time.Time
}

var (
	AuthFlowLimit = &RateLimit{
		Requests: 5,
		Window:   time.Minute * 5,
	}
	TokenOpsLimit = &RateLimit{
		Requests: 30,
		Window:   time.Minute,
	}
	VerificationLimit = &RateLimit{
		Requests: 60,
		Window:   time.Minute,
	}
	DefaultLimit = &RateLimit{
		Requests: 100,
		Window:   time.Minute,
	}
)

func NewRateLimiter() *RateLimiter {
	rl := &RateLimiter{
		requests: make(map[string]*clientRequests),
		limits:   make(map[string]*RateLimit),
	}

	rl.limits["auth"] = AuthFlowLimit
	rl.limits["token"] = TokenOpsLimit
	rl.limits["verify"] = VerificationLimit
	rl.limits["default"] = DefaultLimit

	go rl.cleanupLoop()
	return rl
}

func getEndpointGroup(path string) string {
	switch {
	case strings.Contains(path, "/discord") || strings.Contains(path, "/callback"):
		return "auth"
	case strings.Contains(path, "/api/verify"):
		return "verify"
	case strings.Contains(path, "/api/refresh") ||
		strings.Contains(path, "/api/store-auth"):
		return "token"
	default:
		return "default"
	}
}

func (rl *RateLimiter) cleanupLoop() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		rl.cleanup()
	}
}

func (rl *RateLimiter) cleanup() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	for key, req := range rl.requests {
		if now.After(req.resetAt) {
			delete(rl.requests, key)
		}
	}
}

func (rl *RateLimiter) RateLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := r.RemoteAddr
		group := getEndpointGroup(r.URL.Path)
		key := ip + ":" + group

		limit := rl.limits[group]
		if limit == nil {
			limit = DefaultLimit
		}

		rl.mu.Lock()
		now := time.Now()

		req, exists := rl.requests[key]
		if !exists || now.After(req.resetAt) {
			rl.requests[key] = &clientRequests{
				count:   1,
				resetAt: now.Add(limit.Window),
			}
			rl.mu.Unlock()

			w.Header().Set("X-RateLimit-Limit", strconv.Itoa(limit.Requests))
			w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(limit.Requests-1))
			w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(now.Add(limit.Window).Unix(), 10))
			w.Header().Set("X-RateLimit-Group", group)

			next.ServeHTTP(w, r)
			return
		}

		if req.count >= limit.Requests {
			rl.mu.Unlock()
			log.Warn().
				Str("ip", ip).
				Str("group", group).
				Int("count", req.count).
				Time("reset_at", req.resetAt).
				Msg("Rate limit exceeded")

			w.Header().Set("X-RateLimit-Limit", strconv.Itoa(limit.Requests))
			w.Header().Set("X-RateLimit-Remaining", "0")
			w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(req.resetAt.Unix(), 10))
			w.Header().Set("X-RateLimit-Group", group)
			http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
			return
		}

		req.count++
		remaining := limit.Requests - req.count
		resetAt := req.resetAt
		rl.mu.Unlock()

		w.Header().Set("X-RateLimit-Limit", strconv.Itoa(limit.Requests))
		w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(remaining))
		w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(resetAt.Unix(), 10))
		w.Header().Set("X-RateLimit-Group", group)

		next.ServeHTTP(w, r)
	})
}
