package remoteconfig

import (
	"context"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
)

const validAuthorization = `{"server_url":"https://metrics.example.invalid","version-since":"1.0.0","version-until":"2.0.0","period_minutes":60}`

func TestTelemetryRevocationClearsDestination(t *testing.T) {
	for _, code := range []int{204, 301, 400, 401, 403, 404, 410, 422, 201, 202, 206} {
		t.Run(fmt.Sprint(code), func(t *testing.T) {
			var status atomic.Int32
			status.Store(http.StatusOK)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(int(status.Load()))
				if status.Load() == http.StatusOK {
					_, _ = fmt.Fprint(w, validAuthorization)
				}
			}))
			defer server.Close()
			mgr := NewManager(server.URL, 0)
			require.NotNil(t, mgr.RefreshIfNeeded(context.Background()))
			status.Store(int32(code))
			require.Nil(t, mgr.RefreshIfNeeded(context.Background()), "withdrawn authorization must not reuse a cached destination")
			require.Nil(t, mgr.lastConfig)
		})
	}
}

func TestTelemetryInvalidSuccessClearsDestination(t *testing.T) {
	oversized := validAuthorization + strings.Repeat(" ", 4096-len(validAuthorization)) + "untrusted suffix"
	cases := map[string]string{
		"malformed":         `{"server_url":`,
		"oversized":         oversized,
		"duplicate field":   strings.Replace(validAuthorization, `"period_minutes":60`, `"period_minutes":60,"PERIOD_MINUTES":1`, 1),
		"empty versions":    strings.Replace(validAuthorization, `"version-until":"2.0.0"`, `"version-until":"1.0.0"`, 1),
		"inverted versions": strings.Replace(validAuthorization, `"version-since":"1.0.0"`, `"version-since":"3.0.0"`, 1),
		"insecure upload":   strings.Replace(validAuthorization, "https://metrics.example.invalid", "http://metrics.example.invalid", 1),
		"empty fragment":    strings.Replace(validAuthorization, "https://metrics.example.invalid", "https://metrics.example.invalid/#", 1),
		"interval overflow": strings.Replace(validAuthorization, `"period_minutes":60`, fmt.Sprintf(`"period_minutes":%d`, math.MaxInt64/int64(60000000000)+1), 1),
	}
	for name, invalid := range cases {
		t.Run(name, func(t *testing.T) {
			var reject atomic.Bool
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if reject.Load() {
					_, _ = fmt.Fprint(w, invalid)
				} else {
					_, _ = fmt.Fprint(w, validAuthorization)
				}
			}))
			defer server.Close()
			mgr := NewManager(server.URL, 0)
			require.NotNil(t, mgr.RefreshIfNeeded(context.Background()))
			reject.Store(true)
			require.Nil(t, mgr.RefreshIfNeeded(context.Background()), "invalid replacement cannot preserve or renew consent")
			require.Nil(t, mgr.lastConfig)
		})
	}
}

func TestTelemetryEndpointPolicy(t *testing.T) {
	for _, endpoint := range []string{
		"", "/relative", "http://metrics.example.invalid", "ftp://metrics.example.invalid",
		"https://user:secret@metrics.example.invalid", "https://metrics.example.invalid?token=secret",
		"https://metrics.example.invalid?", "https://metrics.example.invalid#", "https://metrics.example.invalid#secret",
		"https://metrics.example.invalid:", "https://metrics.example.invalid:0", "https://metrics.example.invalid:65536",
		"http://localhost.example.invalid", "http://192.0.2.1", "https:opaque",
	} {
		t.Run(endpoint, func(t *testing.T) {
			require.False(t, ValidEndpoint(endpoint))
			mgr := NewManager(endpoint, 0)
			var requests int
			mgr.client.Transport = configTransport(func(*http.Request) (*http.Response, error) {
				requests++
				t.Error("invalid configuration URL reached the transport")
				return nil, fmt.Errorf("unexpected transport call")
			})
			require.Nil(t, mgr.RefreshIfNeeded(context.Background()))
			require.Zero(t, requests)
		})
	}
	for _, endpoint := range []string{"https://metrics.example.invalid/api", "https://metrics.example.invalid:443", "http://localhost:8080", "http://127.0.0.1:8080", "http://[::1]:8080"} {
		require.True(t, ValidEndpoint(endpoint), endpoint)
	}
}
