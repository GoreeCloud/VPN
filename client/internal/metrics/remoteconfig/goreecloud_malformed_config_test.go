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

func TestGoreeCloudInvalidSuccessRevokesCachedDestination(t *testing.T) {
	var invalid atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if invalid.Load() {
			_, _ = w.Write([]byte("{invalid"))
			return
		}
		_ = json.NewEncoder(w).Encode(rawConfig{
			ServerURL:    "https://metrics.example.invalid/ingest",
			VersionSince: "1.0.0", VersionUntil: "2.0.0", PeriodMinutes: 30,
		})
	}))
	defer server.Close()
	mgr := NewManager(server.URL, time.Minute)
	if mgr.RefreshIfNeeded(context.Background()) == nil {
		t.Fatal("initial config missing")
	}
	invalid.Store(true)
	mgr.mu.Lock()
	mgr.lastFetched = time.Now().Add(-time.Hour)
	mgr.mu.Unlock()
	if got := mgr.RefreshIfNeeded(context.Background()); got != nil {
		t.Fatal("invalid successful config reused cached telemetry destination")
	}
	mgr.mu.Lock()
	retained := mgr.lastConfig != nil || !mgr.lastSucceeded.IsZero()
	mgr.mu.Unlock()
	if retained {
		t.Fatal("invalid configuration retained prior destination or lease")
	}
	invalid.Store(false)
	if mgr.RefreshIfNeeded(context.Background()) == nil {
		t.Fatal("valid config did not recover")
	}
}
