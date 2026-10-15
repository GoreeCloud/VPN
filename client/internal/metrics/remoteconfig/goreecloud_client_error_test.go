package remoteconfig

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestGoreeCloudClientErrorRevokesCachedTelemetry(t *testing.T) {
	for _, status := range []int{http.StatusBadRequest, http.StatusMethodNotAllowed, http.StatusUnprocessableEntity} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			var current atomic.Int32
			current.Store(http.StatusOK)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(int(current.Load()))
				_ = json.NewEncoder(w).Encode(rawConfig{
					ServerURL: "https://metrics.example.invalid/ingest",
					VersionSince: "1.0.0", VersionUntil: "2.0.0", PeriodMinutes: 30,
				})
			}))
			defer server.Close()
			mgr := NewManager(server.URL, 0)
			if mgr.RefreshIfNeeded(context.Background()) == nil {
				t.Fatal("initial valid telemetry config not accepted")
			}
			current.Store(int32(status))
			if got := mgr.RefreshIfNeeded(context.Background()); got != nil {
				t.Fatalf("status %d retained telemetry authorization", status)
			}
			if mgr.lastConfig != nil || !mgr.lastSucceeded.IsZero() {
				t.Fatalf("status %d preserved a cached destination or lease", status)
			}
		})
	}
}

func TestGoreeCloudRateLimitPreservesBoundedTelemetryLease(t *testing.T) {
	var current atomic.Int32
	current.Store(http.StatusOK)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(int(current.Load()))
		_ = json.NewEncoder(w).Encode(rawConfig{
			ServerURL: "https://metrics.example.invalid/ingest",
			VersionSince: "1.0.0", VersionUntil: "2.0.0", PeriodMinutes: 30,
		})
	}))
	defer server.Close()
	mgr := NewManager(server.URL, 0)
	if mgr.RefreshIfNeeded(context.Background()) == nil {
		t.Fatal("initial config not accepted")
	}
	current.Store(http.StatusTooManyRequests)
	if got := mgr.RefreshIfNeeded(context.Background()); got == nil {
		t.Fatal("429 unexpectedly invalidated a still-current cached lease")
	}
}
