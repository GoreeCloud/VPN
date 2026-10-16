package remoteconfig

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestGoreeCloudUnexpectedSuccessStatusesRevokeConfig(t *testing.T) {
	for _, status := range []int{http.StatusCreated, http.StatusAccepted, http.StatusPartialContent} {
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
				t.Fatal("initial configuration unavailable")
			}
			current.Store(int32(status))
			if got := mgr.RefreshIfNeeded(context.Background()); got != nil {
				t.Fatalf("status %d unexpectedly accepted", status)
			}
			if mgr.lastConfig != nil || !mgr.lastSucceeded.IsZero() {
				t.Fatalf("status %d retained cached configuration", status)
			}
		})
	}
}
