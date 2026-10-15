package remoteconfig

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestGoreeCloudUnknownConfigMemberRevokesCachedTelemetry(t *testing.T) {
	var unknown atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		extra := ""
		if unknown.Load() {
			extra = `,"unexpected_policy":"untrusted"`
		}
		_, _ = fmt.Fprintf(w, `{"server_url":"https://metrics.example.invalid/push","version-since":"1.0.0","version-until":"2.0.0","period_minutes":30%s}`, extra)
	}))
	defer server.Close()
	mgr := NewManager(server.URL, 0)
	if mgr.RefreshIfNeeded(context.Background()) == nil {
		t.Fatal("initial valid telemetry configuration missing")
	}
	unknown.Store(true)
	if cfg := mgr.RefreshIfNeeded(context.Background()); cfg != nil {
		t.Fatal("unknown remote configuration member retained telemetry authorization")
	}
	if mgr.lastConfig != nil || !mgr.lastSucceeded.IsZero() {
		t.Fatal("unknown member did not clear cached destination and lease")
	}
}
