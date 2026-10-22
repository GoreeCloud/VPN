package remoteconfig

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestTelemetryLeaseExpiresDespiteRefreshFailures(t *testing.T) {
	for _, code := range []int{408, 429, 500, 503} {
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
			now := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
			mgr := NewManager(server.URL, 0)
			mgr.now = func() time.Time { return now }
			first := mgr.RefreshIfNeeded(context.Background())
			require.NotNil(t, first)
			consentTime := mgr.lastSucceeded
			status.Store(int32(code))
			now = now.Add(maxCachedConfigAge - time.Nanosecond)
			require.Equal(t, first, mgr.RefreshIfNeeded(context.Background()))
			require.Equal(t, consentTime, mgr.lastSucceeded, "failure cannot renew authorization")
			now = now.Add(time.Nanosecond)
			require.Nil(t, mgr.RefreshIfNeeded(context.Background()), "exact lease expiry must deny telemetry")
			require.Nil(t, mgr.lastConfig)
			status.Store(http.StatusOK)
			require.NotNil(t, mgr.RefreshIfNeeded(context.Background()), "a newly validated response may authorize again")
			require.Equal(t, now, mgr.lastSucceeded)
		})
	}
}

func TestTelemetryRefreshIntervalCannotExtendLease(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) > 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_, _ = fmt.Fprint(w, validAuthorization)
	}))
	defer server.Close()
	now := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	mgr := NewManager(server.URL, 24*time.Hour)
	mgr.now = func() time.Time { return now }
	require.NotNil(t, mgr.RefreshIfNeeded(context.Background()))
	now = now.Add(maxCachedConfigAge)
	require.Nil(t, mgr.RefreshIfNeeded(context.Background()))
	require.Equal(t, int32(2), calls.Load())
}

type failingConfigBody struct{}

func (failingConfigBody) Read([]byte) (int, error) { return 0, errors.New("read interrupted") }
func (failingConfigBody) Close() error             { return nil }

type configTransport func(*http.Request) (*http.Response, error)

func (f configTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestTelemetryUnreadableSuccessWithdrawsAuthorization(t *testing.T) {
	mgr := NewManager("https://config.example.invalid", 0)
	broken := false
	mgr.client.Transport = configTransport(func(*http.Request) (*http.Response, error) {
		var body io.ReadCloser = io.NopCloser(strings.NewReader(validAuthorization))
		if broken {
			body = failingConfigBody{}
		}
		return &http.Response{StatusCode: http.StatusOK, Body: body}, nil
	})
	require.NotNil(t, mgr.RefreshIfNeeded(context.Background()))
	broken = true
	require.Nil(t, mgr.RefreshIfNeeded(context.Background()))
	require.True(t, mgr.lastSucceeded.IsZero())
}

func TestTelemetryRedirectDoesNotContactAnotherOrigin(t *testing.T) {
	var leaked atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		leaked.Add(1)
		_, _ = fmt.Fprint(w, validAuthorization)
	}))
	defer target.Close()
	var redirect atomic.Bool
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if redirect.Load() {
			http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
			return
		}
		_, _ = fmt.Fprint(w, validAuthorization)
	}))
	defer source.Close()
	mgr := NewManager(source.URL, 0)
	require.NotNil(t, mgr.RefreshIfNeeded(context.Background()))
	redirect.Store(true)
	require.Nil(t, mgr.RefreshIfNeeded(context.Background()))
	require.Zero(t, leaked.Load())
}
