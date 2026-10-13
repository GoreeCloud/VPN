package metrics

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"net/url"
	"testing"
)

func TestMetricsConfigurationRequiresExplicitEndpoints(t *testing.T) {
	t.Setenv(EnvMetricsConfigURL, "")
	t.Setenv(EnvMetricsServerURL, "")
	if got := getMetricsConfigURL(); got != "" {
		t.Fatalf("unexpected default metrics configuration URL %q", got)
	}
	push, err := NewPush(nil, nil, PushConfig{ForceSending: true}, "1.0.0")
	if err == nil || push != nil {
		t.Fatalf("forced metrics push must require a destination: push=%v err=%v", push, err)
	}
	client := &ClientMetrics{}
	client.pushMu.Lock()
	client.startPushLocked(context.Background(), PushConfig{})
	client.pushMu.Unlock()
	if client.push.Load() != nil {
		t.Fatal("metrics push started without remote configuration")
	}
}

func TestForcedMetricsPushAcceptsExplicitDestination(t *testing.T) {
	destination, err := url.Parse("https://metrics.example.invalid/collect")
	if err != nil {
		t.Fatal(err)
	}
	push, err := NewPush(nil, nil, PushConfig{
		ForceSending:  true,
		ServerAddress: destination,
	}, "1.0.0")
	if err != nil || push == nil {
		t.Fatalf("explicit metrics endpoint rejected: %v", err)
	}
	if got := push.cfgAddress.String(); got != destination.String() {
		t.Fatalf("got destination %q, want %q", got, destination)
	}
}

func TestMetricsPushDoesNotFollowRedirects(t *testing.T) {
	var redirected atomic.Int32
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirected.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer destination.Close()

	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", destination.URL+"/collect")
		w.WriteHeader(http.StatusTemporaryRedirect)
	}))
	defer origin.Close()

	push, err := NewPush(nil, nil, PushConfig{ForceSending: true}, "1.0.0")
	if err == nil || push != nil {
		t.Fatal("forced push without configured destination unexpectedly allowed")
	}
	configured, err := url.Parse(origin.URL)
	if err != nil { t.Fatal(err) }
	push, err = NewPush(nil, nil, PushConfig{ForceSending: true, ServerAddress: configured}, "1.0.0")
	if err != nil { t.Fatal(err) }

	req, err := http.NewRequest(http.MethodPost, origin.URL+"/collect", strings.NewReader("sensitive-test-data"))
	if err != nil { t.Fatal(err) }
	req.Header.Set("X-Peer-ID", "sensitive-peer-id")
	resp, err := push.client.Do(req)
	if err != nil { t.Fatal(err) }
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusTemporaryRedirect {
		t.Fatalf("redirect should be surfaced as unsuccessful response, got %d", resp.StatusCode)
	}
	if redirected.Load() != 0 {
		t.Fatal("metrics payload forwarded to an unapproved redirect destination")
	}
}
