package remoteconfig

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestGoreeCloudOversizedValidPrefixDoesNotAuthorizeTelemetry(t *testing.T) {
	var oversized atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(rawConfig{
			ServerURL:     "https://metrics.example.invalid/ingest",
			VersionSince:  "1.0.0",
			VersionUntil:  "2.0.0",
			PeriodMinutes: 30,
		})
		if oversized.Load() {
			_, _ = w.Write([]byte(strings.Repeat(" ", 5000)))
		}
	}))
	defer server.Close()
	mgr := NewManager(server.URL, time.Minute)
	if mgr.RefreshIfNeeded(context.Background()) == nil {
		t.Fatal("initial valid configuration was not loaded")
	}
	oversized.Store(true)
	mgr.mu.Lock()
	mgr.lastFetched = time.Now().Add(-time.Hour)
	mgr.mu.Unlock()
	if got := mgr.RefreshIfNeeded(context.Background()); got != nil {
		t.Fatal("oversized configuration reused an old telemetry destination")
	}
	mgr.mu.Lock()
	retained := mgr.lastConfig != nil || !mgr.lastSucceeded.IsZero()
	mgr.mu.Unlock()
	if retained {
		t.Fatal("oversized configuration retained authorization lease")
	}
}
