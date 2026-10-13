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

func TestGoreeCloudInvalidConfigFieldsRevokeCache(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*rawConfig)
	}{
		{"invalid since", func(c *rawConfig) { c.VersionSince = "not-a-version" }},
		{"invalid until", func(c *rawConfig) { c.VersionUntil = "not-a-version" }},
		{"empty destination", func(c *rawConfig) { c.ServerURL = "" }},
		{"unsafe destination", func(c *rawConfig) { c.ServerURL = "http://example.invalid/metrics" }},
		{"invalid interval", func(c *rawConfig) { c.PeriodMinutes = 0 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var invalid atomic.Bool
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				raw := rawConfig{ServerURL: "https://metrics.example.invalid/ingest",
					VersionSince: "1.0.0", VersionUntil: "2.0.0", PeriodMinutes: 30}
				if invalid.Load() {
					tc.change(&raw)
				}
				_ = json.NewEncoder(w).Encode(raw)
			}))
			defer server.Close()
			mgr := NewManager(server.URL, time.Minute)
			if mgr.RefreshIfNeeded(context.Background()) == nil {
				t.Fatal("missing initial configuration")
			}
			invalid.Store(true)
			mgr.mu.Lock()
			mgr.lastFetched = time.Now().Add(-time.Hour)
			mgr.mu.Unlock()
			if mgr.RefreshIfNeeded(context.Background()) != nil {
				t.Fatal("invalid successful configuration retained cache")
			}
			mgr.mu.Lock()
			retained := mgr.lastConfig != nil || !mgr.lastSucceeded.IsZero()
			mgr.mu.Unlock()
			if retained {
				t.Fatal("invalid configuration left cached destination")
			}
		})
	}
}
