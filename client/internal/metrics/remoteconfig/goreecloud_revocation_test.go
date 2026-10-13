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

// An explicit server revocation must immediately invalidate a previously
// cached destination, even while its outage-tolerance lease is unexpired.
func TestGoreeCloudExplicitRemoteConfigRevocation(t *testing.T) {
	for _, code := range []int{
		http.StatusNoContent,
		http.StatusUnauthorized,
		http.StatusForbidden,
		http.StatusNotFound,
		http.StatusGone,
	} {
		t.Run(http.StatusText(code), func(t *testing.T) {
			var responseCode atomic.Int32
			responseCode.Store(http.StatusOK)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				code := int(responseCode.Load())
				if code != http.StatusOK {
					w.WriteHeader(code)
					return
				}
				_ = json.NewEncoder(w).Encode(rawConfig{
					ServerURL:     "https://metrics.example.invalid/collect",
					VersionSince:  "1.0.0",
					VersionUntil:  "2.0.0",
					PeriodMinutes: 30,
				})
			}))
			defer server.Close()
			manager := NewManager(server.URL, time.Minute)
			if got := manager.RefreshIfNeeded(context.Background()); got == nil {
				t.Fatal("initial remote configuration fetch failed")
			}
			manager.mu.Lock()
			manager.lastFetched = time.Now().Add(-time.Hour)
			manager.mu.Unlock()
			responseCode.Store(int32(code))

			if got := manager.RefreshIfNeeded(context.Background()); got != nil {
				t.Fatalf("revoked config returned telemetry destination on HTTP %d", code)
			}
			manager.mu.Lock()
			retained := manager.lastConfig != nil
			retainedLease := !manager.lastSucceeded.IsZero()
			manager.mu.Unlock()
			if retained || retainedLease {
				t.Fatal("revoked destination and successful lease timestamp must be erased")
			}

			responseCode.Store(http.StatusOK)
			if got := manager.RefreshIfNeeded(context.Background()); got == nil {
				t.Fatal("re-authorized configuration did not recover")
			}
		})
	}
}
