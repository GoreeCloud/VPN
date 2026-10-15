package remoteconfig

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGoreeCloudExplicitEmptyFragmentRejected(t *testing.T) {
	for _, endpoint := range []string{
		"https://config.example.invalid/#",
		"https://metrics.example.invalid/ingest#",
		"http://127.0.0.1:8080/#",
	} {
		if validConfigEndpoint(endpoint) {
			t.Errorf("fragment-delimited endpoint %q unexpectedly accepted", endpoint)
		}
	}
	for _, endpoint := range []string{
		"https://config.example.invalid/next",
		"http://127.0.0.1:8080/next",
	} {
		if !validConfigEndpoint(endpoint) {
			t.Errorf("valid explicit endpoint %q rejected", endpoint)
		}
	}
}

func TestGoreeCloudInvalidFragmentRevokesCachedRemoteDestination(t *testing.T) {
	invalid := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		destination := "https://metrics.example.invalid/ingest"
		if invalid {
			destination += "#"
		}
		_ = json.NewEncoder(w).Encode(rawConfig{
			ServerURL: destination, VersionSince: "1.0.0",
			VersionUntil: "2.0.0", PeriodMinutes: 30,
		})
	}))
	defer server.Close()

	mgr := NewManager(server.URL, 0)
	if mgr.RefreshIfNeeded(context.Background()) == nil {
		t.Fatal("initial valid remote destination was not accepted")
	}
	invalid = true
	if got := mgr.RefreshIfNeeded(context.Background()); got != nil {
		t.Fatal("invalid fragment-delimited destination retained telemetry")
	}
	if mgr.lastConfig != nil || !mgr.lastSucceeded.IsZero() {
		t.Fatal("cached destination authorization was not revoked")
	}
}
