package remoteconfig

import (
    "context"
    "encoding/json"
    "net/http"
    "net/http/httptest"
    "testing"
    "time"
)

func TestGoreeCloudCanceledRefreshPreservesOnlyUnexpiredLease(t *testing.T) {
    server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
        _ = json.NewEncoder(w).Encode(rawConfig{
            ServerURL: "https://metrics.example.invalid/ingest",
            VersionSince: "1.0.0", VersionUntil: "2.0.0", PeriodMinutes: 30,
        })
    }))
    defer server.Close()
    manager := NewManager(server.URL, 0)
    if manager.RefreshIfNeeded(context.Background()) == nil {
        t.Fatal("initial configuration rejected")
    }
    manager.mu.Lock()
    initial := manager.lastSucceeded
    manager.mu.Unlock()

    canceled, cancel := context.WithCancel(context.Background())
    cancel()
    if manager.RefreshIfNeeded(canceled) == nil {
        t.Fatal("cancellation discarded valid cached config")
    }
    manager.mu.Lock()
    unchanged := manager.lastSucceeded.Equal(initial)
    manager.lastSucceeded = time.Now().Add(-maxCachedConfigAge-time.Second)
    manager.mu.Unlock()
    if !unchanged {
        t.Fatal("canceled request renewed telemetry authorization")
    }
    if manager.RefreshIfNeeded(canceled) != nil {
        t.Fatal("expired telemetry lease survived canceled request")
    }
    if manager.RefreshIfNeeded(context.Background()) == nil {
        t.Fatal("valid configuration did not recover after cancellation")
    }
}
