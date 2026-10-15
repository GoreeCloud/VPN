package remoteconfig

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"testing/iotest"
)

type goreecloudReadFailureTransport func(*http.Request) (*http.Response, error)

func (f goreecloudReadFailureTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

// A 200 response whose body fails during reading must not preserve a
// previously-authorized telemetry destination.
func TestGoreeCloudUnreadableSuccessRevokesCachedTelemetry(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(rawConfig{
			ServerURL:    "https://metrics.example.invalid/ingest",
			VersionSince: "1.0.0", VersionUntil: "2.0.0", PeriodMinutes: 30,
		})
	}))
	defer server.Close()

	manager := NewManager(server.URL, 0)
	if manager.RefreshIfNeeded(context.Background()) == nil {
		t.Fatal("initial authorized config missing")
	}
	manager.client.Transport = goreecloudReadFailureTransport(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(iotest.ErrReader(io.ErrUnexpectedEOF)),
		}, nil
	})
	if result := manager.RefreshIfNeeded(context.Background()); result != nil {
		t.Fatal("unreadable successful response retained cached telemetry authorization")
	}
	if manager.lastConfig != nil || !manager.lastSucceeded.IsZero() {
		t.Fatal("unreadable successful response retained cached destination or lease")
	}
}
