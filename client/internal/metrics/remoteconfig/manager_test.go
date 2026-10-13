package remoteconfig

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testMinRefresh = 100 * time.Millisecond

func TestManager_FetchSuccess(t *testing.T) {
	server := newConfigServer(t, rawConfig{
		ServerURL:     "https://ingest.example.com",
		VersionSince:  "1.0.0",
		VersionUntil:  "2.0.0",
		PeriodMinutes: 60,
	})
	defer server.Close()

	mgr := NewManager(server.URL, testMinRefresh)
	config := mgr.RefreshIfNeeded(context.Background())

	require.NotNil(t, config)
	assert.Equal(t, "https://ingest.example.com", config.ServerURL.String())
	assert.Equal(t, "1.0.0", config.VersionSince.String())
	assert.Equal(t, "2.0.0", config.VersionUntil.String())
	assert.Equal(t, 60*time.Minute, config.Interval)
}

func TestManager_CachesConfig(t *testing.T) {
	var fetchCount atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetchCount.Add(1)
		err := json.NewEncoder(w).Encode(rawConfig{
			ServerURL:     "https://ingest.example.com",
			VersionSince:  "1.0.0",
			VersionUntil:  "2.0.0",
			PeriodMinutes: 60,
		})
		require.NoError(t, err)
	}))
	defer server.Close()

	mgr := NewManager(server.URL, testMinRefresh)

	// First call fetches
	config1 := mgr.RefreshIfNeeded(context.Background())
	require.NotNil(t, config1)
	assert.Equal(t, int32(1), fetchCount.Load())

	// Second call uses cache (within minRefreshInterval)
	config2 := mgr.RefreshIfNeeded(context.Background())
	require.NotNil(t, config2)
	assert.Equal(t, int32(1), fetchCount.Load())
	assert.Equal(t, config1, config2)
}

func TestManager_RefetchesWhenStale(t *testing.T) {
	var fetchCount atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetchCount.Add(1)
		err := json.NewEncoder(w).Encode(rawConfig{
			ServerURL:     "https://ingest.example.com",
			VersionSince:  "1.0.0",
			VersionUntil:  "2.0.0",
			PeriodMinutes: 60,
		})
		require.NoError(t, err)
	}))
	defer server.Close()

	mgr := NewManager(server.URL, testMinRefresh)

	// First fetch
	mgr.RefreshIfNeeded(context.Background())
	assert.Equal(t, int32(1), fetchCount.Load())

	// Wait for config to become stale
	time.Sleep(testMinRefresh + 10*time.Millisecond)

	// Should refetch
	mgr.RefreshIfNeeded(context.Background())
	assert.Equal(t, int32(2), fetchCount.Load())
}

func TestManager_FetchFailureReturnsNil(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	mgr := NewManager(server.URL, testMinRefresh)
	config := mgr.RefreshIfNeeded(context.Background())

	assert.Nil(t, config)
}

func TestManager_FetchFailureReturnsCached(t *testing.T) {
	var fetchCount atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetchCount.Add(1)
		if fetchCount.Load() > 1 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		err := json.NewEncoder(w).Encode(rawConfig{
			ServerURL:     "https://ingest.example.com",
			VersionSince:  "1.0.0",
			VersionUntil:  "2.0.0",
			PeriodMinutes: 60,
		})
		require.NoError(t, err)
	}))
	defer server.Close()

	mgr := NewManager(server.URL, testMinRefresh)

	// First call succeeds
	config1 := mgr.RefreshIfNeeded(context.Background())
	require.NotNil(t, config1)

	// Wait for config to become stale
	time.Sleep(testMinRefresh + 10*time.Millisecond)

	// Second call fails but returns cached
	config2 := mgr.RefreshIfNeeded(context.Background())
	require.NotNil(t, config2)
	assert.Equal(t, config1, config2)
}

func TestManager_RejectsInvalidPeriod(t *testing.T) {
	tests := []struct {
		name   string
		period int
	}{
		{"zero", 0},
		{"negative", -5},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := newConfigServer(t, rawConfig{
				ServerURL:     "https://ingest.example.com",
				VersionSince:  "1.0.0",
				VersionUntil:  "2.0.0",
				PeriodMinutes: tt.period,
			})
			defer server.Close()

			mgr := NewManager(server.URL, testMinRefresh)
			config := mgr.RefreshIfNeeded(context.Background())
			assert.Nil(t, config)
		})
	}
}

func TestManager_RejectsEmptyServerURL(t *testing.T) {
	server := newConfigServer(t, rawConfig{
		ServerURL:     "",
		VersionSince:  "1.0.0",
		VersionUntil:  "2.0.0",
		PeriodMinutes: 60,
	})
	defer server.Close()

	mgr := NewManager(server.URL, testMinRefresh)
	config := mgr.RefreshIfNeeded(context.Background())
	assert.Nil(t, config)
}

func TestManager_RejectsInvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := w.Write([]byte("not json"))
		require.NoError(t, err)
	}))
	defer server.Close()

	mgr := NewManager(server.URL, testMinRefresh)
	config := mgr.RefreshIfNeeded(context.Background())
	assert.Nil(t, config)
}

func newConfigServer(t *testing.T, config rawConfig) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		err := json.NewEncoder(w).Encode(config)
		require.NoError(t, err)
	}))
}

func TestGoreeCloudConfigRejectsRedirect(t *testing.T) {
	var forwarded atomic.Int32
	redirected := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		forwarded.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer redirected.Close()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", redirected.URL+"/unapproved")
		w.WriteHeader(http.StatusTemporaryRedirect)
	}))
	defer origin.Close()

	manager := NewManager(origin.URL, time.Minute)
	if result := manager.RefreshIfNeeded(context.Background()); result != nil {
		t.Fatal("configuration redirect was accepted")
	}
	if got := forwarded.Load(); got != 0 {
		t.Fatalf("configuration fetch followed redirect %d times", got)
	}
}

func TestGoreeCloudConfigTransportPolicy(t *testing.T) {
	cases := []struct {
		target string
		allow  bool
	}{
		{"https://config.example.invalid/settings", true},
		{"http://config.example.invalid/settings", false},
		{"http://localhost:9050/settings", true},
		{"http://127.0.0.1:9050/settings", true},
		{"http://[::1]:9050/settings", true},
		{"http://192.0.2.8/settings", false},
		{"http://localhost.evil.invalid/settings", false},
		{"https://user:pass@config.example.invalid/settings", false},
		{"https://config.example.invalid/settings#fragment", false},
		{"https://config.example.invalid/settings?x=1", false},
		{"https://config.example.invalid/settings?", false},
		{"file:///etc/hosts", false},
		{"", false},
	}
	for _, tc := range cases {
		t.Run(tc.target, func(t *testing.T) {
			if got := validConfigEndpoint(tc.target); got != tc.allow {
				t.Errorf("URL policy got %v, want %v", got, tc.allow)
			}
		})
	}
}

func TestGoreeCloudConfigRejectsUnsafeAdvertisedServer(t *testing.T) {
	for _, target := range []string{
		"http://collector.example.invalid/metrics",
		"https://user:secret@collector.example.invalid/metrics",
		"https://collector.example.invalid/metrics#fragment",
		"https://collector.example.invalid/metrics?api_key=private",
		"file:///tmp/metrics",
	} {
		t.Run(target, func(t *testing.T) {
			server := newConfigServer(t, rawConfig{
				ServerURL: target, VersionSince: "1.0.0", VersionUntil: "2.0.0", PeriodMinutes: 10,
			})
			defer server.Close()
			if got := NewManager(server.URL, time.Minute).RefreshIfNeeded(context.Background()); got != nil {
				t.Fatalf("unsafe advertised destination was accepted")
			}
		})
	}
}

func TestGoreeCloudConfigTransportErrorsOmitSecrets(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	target := server.URL + "/settings?token=synthetic-secret-token"
	server.Close()

	m := NewManager(target, time.Minute)
	_, err := m.fetch(context.Background())
	if err == nil {
		t.Fatal("closed endpoint unexpectedly returned a configuration")
	}
	if strings.Contains(err.Error(), "synthetic-secret-token") || strings.Contains(err.Error(), "token=") {
		t.Fatal("transport error disclosed sensitive config URL")
	}
}
