package remoteconfig

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestGoreeCloudRateLimitedRemoteConfigDoesNotRenewCacheLease(t *testing.T) {
	var limited atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if limited.Load() {
			w.Header().Set("Retry-After", "3600")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		_ = json.NewEncoder(w).Encode(rawConfig{
			ServerURL:    "https://metrics.example.invalid/push",
			VersionSince: "1.0.0", VersionUntil: "2.0.0", PeriodMinutes: 30,
		})
	}))
	defer server.Close()

	manager := NewManager(server.URL, 0)
	if initial := manager.RefreshIfNeeded(context.Background()); initial == nil {
		t.Fatal("initial telemetry authorization not established")
	}
	limited.Store(true)
	manager.mu.Lock()
	initialSuccess := manager.lastSucceeded
	manager.mu.Unlock()

	if cached := manager.RefreshIfNeeded(context.Background()); cached == nil {
		t.Fatal("temporary rate limiting discarded the bounded cached configuration")
	}
	manager.mu.Lock()
	if !manager.lastSucceeded.Equal(initialSuccess) {
		manager.mu.Unlock()
		t.Fatal("rate-limited fetch renewed authorization lease")
	}
	manager.lastSucceeded = time.Now().Add(-maxCachedConfigAge - time.Second)
	manager.mu.Unlock()
	if expired := manager.RefreshIfNeeded(context.Background()); expired != nil {
		t.Fatal("server rate limit permitted cached telemetry after lease expiration")
	}
}
