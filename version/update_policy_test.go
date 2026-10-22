package version

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type rejectingVersionTransport struct{ calls int }

func (r *rejectingVersionTransport) RoundTrip(*http.Request) (*http.Response, error) {
	r.calls++
	return nil, fmt.Errorf("unexpected version request")
}

func TestGoreeCloudVersionDiscoveryHasNoDefaultEgress(t *testing.T) {
	transport := &rejectingVersionTransport{}
	previous := http.DefaultClient
	http.DefaultClient = &http.Client{Transport: transport}
	t.Cleanup(func() { http.DefaultClient = previous })
	u := NewUpdate("test")
	if u.versionURL != "" {
		t.Fatalf("unqualified default version endpoint: %q", u.versionURL)
	}
	u.StartFetcher()
	if u.fetchVersion(context.Background()) || u.LatestVersion() != nil {
		t.Fatal("disabled discovery reported a version")
	}
	u.StopWatch()
	if transport.calls != 0 {
		t.Fatalf("default discovery attempted %d HTTP requests", transport.calls)
	}
}

func TestVersionFetcherStopBeforeStart(t *testing.T) {
	transport := &rejectingVersionTransport{}
	previous := http.DefaultClient
	http.DefaultClient = &http.Client{Transport: transport}
	t.Cleanup(func() { http.DefaultClient = previous })
	u := NewUpdate("test")
	u.versionURL = "https://updates.example.invalid/version"
	u.StopWatch()
	u.StartFetcher()
	u.StopWatch()
	if transport.calls != 0 {
		t.Fatal("stop before start allowed an HTTP request")
	}
}

func TestVersionFetcherStopCancelsRequestAndDuplicateStart(t *testing.T) {
	started := make(chan struct{})
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			close(started)
		}
		<-r.Context().Done()
	}))
	defer server.Close()
	u := NewUpdate("test")
	u.versionURL = server.URL
	go u.StartFetcher()
	defer u.StopWatch()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("fetch did not start")
	}
	u.StartFetcher() // Must return immediately without another request.
	u.StopWatch()
	u.StopWatch()
	if calls.Load() != 1 {
		t.Fatalf("duplicate start made %d requests", calls.Load())
	}
}

func TestVersionFetcherBoundsUnknownLengthResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.(http.Flusher).Flush() // No Content-Length; enforce the streamed limit.
		fmt.Fprint(w, strings.Repeat("1", maxVersionResponse+1))
	}))
	defer server.Close()
	u := NewUpdate("test")
	u.versionURL = server.URL
	if u.fetchVersion(context.Background()) || u.LatestVersion() != nil {
		t.Fatal("oversized chunked response accepted")
	}
}
