package remoteconfig

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestGoreeCloudTrailingConfigJSONRevokesTelemetry(t *testing.T) {
	var trailing atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, `{"server_url":"https://metrics.example.invalid/ingest","version-since":"1.0.0","version-until":"2.0.0","period_minutes":30}`)
		if trailing.Load() {
			_, _ = fmt.Fprint(w, `{"server_url":"https://unexpected.example.invalid/ingest"}`)
		}
	}))
	defer server.Close()

	manager := NewManager(server.URL, 0)
	if manager.RefreshIfNeeded(context.Background()) == nil {
		t.Fatal("initial valid telemetry configuration rejected")
	}
	trailing.Store(true)
	if manager.RefreshIfNeeded(context.Background()) != nil {
		t.Fatal("multi-object telemetry configuration retained authorization")
	}
	if manager.lastConfig != nil || !manager.lastSucceeded.IsZero() {
		t.Fatal("trailing JSON left cached telemetry destination or lease")
	}
}
