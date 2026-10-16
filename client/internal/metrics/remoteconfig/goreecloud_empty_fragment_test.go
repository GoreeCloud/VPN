package remoteconfig

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestGoreeCloudExplicitEmptyFragmentNotValidEndpoint(t *testing.T) {
	if validConfigEndpoint("https://metrics.example.invalid/ingest#") {
		t.Fatal("empty fragment delimiter must not be a valid telemetry endpoint")
	}
	if !validConfigEndpoint("https://metrics.example.invalid/part%23valid") {
		t.Fatal("encoded path fragment character should remain allowed")
	}
}

func TestGoreeCloudExplicitEmptyFragmentRevokesCachedTelemetry(t *testing.T) {
	var invalid atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		dest := "https://metrics.example.invalid/ingest"
		if invalid.Load() {
			dest += "#"
		}
		_ = json.NewEncoder(w).Encode(rawConfig{
			ServerURL: dest, VersionSince: "1.0.0", VersionUntil: "2.0.0", PeriodMinutes: 30,
		})
	}))
	defer server.Close()
	manager := NewManager(server.URL, 0)
	if manager.RefreshIfNeeded(context.Background()) == nil {
		t.Fatal("initial valid remote configuration was rejected")
	}
	invalid.Store(true)
	if got := manager.RefreshIfNeeded(context.Background()); got != nil {
		t.Fatal("ambiguous config endpoint preserved telemetry authorization")
	}
	if manager.lastConfig != nil || !manager.lastSucceeded.IsZero() {
		t.Fatal("cached telemetry lease was not revoked")
	}
}
