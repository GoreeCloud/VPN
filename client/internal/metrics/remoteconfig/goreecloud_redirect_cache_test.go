package remoteconfig

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGoreeCloudRedirectRevokesCachedTelemetryDestination(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests++
		if requests == 1 {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"server_url":"https://collector.example.invalid","version-since":"1.0.0","version-until":"2.0.0","period_minutes":30}`))
			return
		}
		w.Header().Set("Location", "https://unapproved.example.invalid/config")
		w.WriteHeader(http.StatusTemporaryRedirect)
	}))
	defer server.Close()

	manager := NewManager(server.URL, 0)
	if manager.RefreshIfNeeded(context.Background()) == nil {
		t.Fatal("initial valid remote config was rejected")
	}
	if result := manager.RefreshIfNeeded(context.Background()); result != nil {
		t.Fatal("a redirect policy violation retained a cached telemetry destination")
	}
	if manager.lastConfig != nil {
		t.Fatal("redirected remote config was still cached")
	}
	if requests != 2 {
		t.Fatalf("expected exactly two requests, got %d", requests)
	}
}
