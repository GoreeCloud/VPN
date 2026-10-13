package remoteconfig

import (
	"context"
	"testing"
	"time"
)

func TestGoreeCloudCachedConfigExpiresAfterSuccessfulFetchLease(t *testing.T) {
	server := newConfigServer(t, rawConfig{
		ServerURL:     "https://ingest.example.invalid/metrics",
		VersionSince:  "1.0.0",
		VersionUntil:  "2.0.0",
		PeriodMinutes: 60,
	})
	mgr := NewManager(server.URL, 48*time.Hour)
	if initial := mgr.RefreshIfNeeded(context.Background()); initial == nil {
		t.Fatal("initial remote config should succeed")
	}
	server.Close()

	mgr.mu.Lock()
	mgr.lastFetched = time.Now().Add(-49 * time.Hour)
	mgr.lastSucceeded = time.Now().Add(-maxCachedConfigAge + time.Minute)
	mgr.mu.Unlock()
	if cached := mgr.RefreshIfNeeded(context.Background()); cached == nil {
		t.Fatal("brief outage should retain the bounded cached configuration")
	}

	// A failed request must not renew the authorization lifetime.
	mgr.mu.Lock()
	mgr.lastSucceeded = time.Now().Add(-maxCachedConfigAge - time.Minute)
	mgr.mu.Unlock()
	if expired := mgr.RefreshIfNeeded(context.Background()); expired != nil {
		t.Fatal("cached remote telemetry configuration survived its lease")
	}
	mgr.mu.Lock()
	stillRetained := mgr.lastConfig != nil
	mgr.mu.Unlock()
	if stillRetained {
		t.Fatal("expired telemetry destination should be discarded")
	}
}

func TestGoreeCloudFutureDatedConfigLeaseFailsClosed(t *testing.T) {
	mgr := NewManager("http://127.0.0.1:0/config", 48*time.Hour)
	mgr.mu.Lock()
	mgr.lastConfig = &Config{}
	mgr.lastSucceeded = time.Now().Add(time.Hour)
	mgr.lastFetched = time.Now()
	mgr.mu.Unlock()
	if got := mgr.RefreshIfNeeded(context.Background()); got != nil {
		t.Fatal("future-dated cached telemetry destination was retained")
	}
}

func TestGoreeCloudLeaseBoundary(t *testing.T) {
	now := time.Date(2026, 10, 12, 0, 0, 0, 0, time.UTC)
	mgr := &Manager{lastConfig: &Config{}, lastSucceeded: now.Add(-maxCachedConfigAge)}
	if mgr.cacheLeaseValid(now) {
		t.Fatal("expired configuration must be rejected")
	}
	mgr.lastSucceeded = now.Add(-maxCachedConfigAge + time.Nanosecond)
	if !mgr.cacheLeaseValid(now) {
		t.Fatal("valid configuration expired too early")
	}
}
