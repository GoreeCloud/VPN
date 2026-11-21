package main

// The management bearer token is high privilege. This listener guard rejects
// DNS rebinding authorities and cross-site browser requests before the API.
// Source IP is taken from the direct TCP peer, never X-Forwarded-For.
import (
	"encoding/json"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"
)

type sourceBudget struct {
	tokens  float64
	updated time.Time
}

type directLimiter struct {
	mu      sync.Mutex
	buckets map[netip.Addr]sourceBudget
	now     func() time.Time
}

func newDirectLimiter() *directLimiter {
	return &directLimiter{buckets: make(map[netip.Addr]sourceBudget), now: time.Now}
}

func (l *directLimiter) allow(remote string) bool {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		return false
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	addr = addr.Unmap()
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if _, seen := l.buckets[addr]; !seen && len(l.buckets) >= 4096 {
		for key, b := range l.buckets {
			if now.Sub(b.updated) > 5*time.Minute {
				delete(l.buckets, key)
			}
		}
		if len(l.buckets) >= 4096 {
			return false
		}
	}
	b, exists := l.buckets[addr]
	if !exists {
		b = sourceBudget{tokens: 24, updated: now}
	}
	elapsed := now.Sub(b.updated).Seconds()
	if elapsed > 0 {
		b.tokens += elapsed * 2
		if b.tokens > 24 {
			b.tokens = 24
		}
	}
	b.updated = now
	if b.tokens < 1 {
		l.buckets[addr] = b
		return false
	}
	b.tokens--
	l.buckets[addr] = b
	return true
}

func guardError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": message})
}

// boundManagement enforces exact HTTP Host and browser Origin authority
// corresponding to the explicit bound endpoint. A reverse proxy is not a
// trusted deployment path for this developer-preview static admin bearer.
func boundManagement(next http.Handler, listener string, tlsEnabled bool) http.Handler {
	authority := listener
	if host, port, err := net.SplitHostPort(listener); err == nil {
		authority = net.JoinHostPort(host, port)
	}
	scheme := "http"
	if tlsEnabled {
		scheme = "https"
	}
	origin := scheme + "://" + authority
	limiter := newDirectLimiter()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != authority {
			guardError(w, http.StatusMisdirectedRequest, "unrecognized management authority")
			return
		}
		origins := r.Header.Values("Origin")
		if len(origins) > 1 || (len(origins) == 1 && origins[0] != origin) {
			guardError(w, http.StatusForbidden, "cross-origin management request denied")
			return
		}
		sites := r.Header.Values("Sec-Fetch-Site")
		if len(sites) > 1 || (len(sites) == 1 && strings.EqualFold(sites[0], "cross-site")) {
			guardError(w, http.StatusForbidden, "cross-site management request denied")
			return
		}
		if !limiter.allow(r.RemoteAddr) {
			w.Header().Set("Retry-After", "1")
			guardError(w, http.StatusTooManyRequests, "management request limit reached")
			return
		}
		next.ServeHTTP(w, r)
	})
}
