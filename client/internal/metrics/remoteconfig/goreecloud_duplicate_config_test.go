package remoteconfig

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGoreeCloudDuplicateRemoteConfigFieldsFailClosed(t *testing.T) {
	cases := []struct{ name, payload string }{
		{"duplicate endpoint", `{"server_url":"https://collector.example.invalid","server_url":"https://other.example.invalid","version-since":"1.0.0","version-until":"2.0.0","period_minutes":30}`},
		{"duplicate version", `{"server_url":"https://collector.example.invalid","version-since":"1.0.0","version-since":"1.1.0","version-until":"2.0.0","period_minutes":30}`},
		{"duplicate interval", `{"server_url":"https://collector.example.invalid","version-since":"1.0.0","version-until":"2.0.0","period_minutes":30,"period_minutes":40}`},
		{"case-insensitive duplicate endpoint", `{"server_url":"https://collector.example.invalid","SERVER_URL":"https://other.example.invalid","version-since":"1.0.0","version-until":"2.0.0","period_minutes":30}`},
		{"escaped duplicate endpoint", `{"server_url":"https://collector.example.invalid","server\u005furl":"https://other.example.invalid","version-since":"1.0.0","version-until":"2.0.0","period_minutes":30}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(tc.payload))
			}))
			defer server.Close()
			manager := NewManager(server.URL, testMinRefresh)
			if result := manager.RefreshIfNeeded(context.Background()); result != nil {
				t.Fatal("ambiguous duplicate-field telemetry config was accepted")
			}
			if manager.lastConfig != nil {
				t.Fatal("duplicate-field telemetry config was cached")
			}
		})
	}
}

func TestGoreeCloudDuplicateConfigRevokesCachedTelemetryDestination(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests++
		w.Header().Set("Content-Type", "application/json")
		if requests == 1 {
			_, _ = w.Write([]byte(`{"server_url":"https://collector.example.invalid","version-since":"1.0.0","version-until":"2.0.0","period_minutes":30}`))
			return
		}
		_, _ = w.Write([]byte(`{"server_url":"https://collector.example.invalid","server_url":"https://changed.example.invalid","version-since":"1.0.0","version-until":"2.0.0","period_minutes":30}`))
	}))
	defer server.Close()
	manager := NewManager(server.URL, 0)
	if result := manager.RefreshIfNeeded(context.Background()); result == nil {
		t.Fatal("initial valid configuration was not accepted")
	}
	if result := manager.RefreshIfNeeded(context.Background()); result != nil {
		t.Fatal("ambiguous config retained an old telemetry destination")
	}
	if manager.lastConfig != nil {
		t.Fatal("invalid response left a telemetry destination cached")
	}
	if requests != 2 {
		t.Fatalf("expected two fetches, got %d", requests)
	}
}
