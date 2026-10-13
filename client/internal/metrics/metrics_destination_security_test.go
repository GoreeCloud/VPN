package metrics

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
)

func TestMetricsDeliveryRejectsRedirect(t *testing.T) {
	var redirectedHits atomic.Int32
	redirected := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		redirectedHits.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer redirected.Close()

	var originHits atomic.Int32
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		originHits.Add(1)
		w.Header().Set("Location", redirected.URL+"/new-endpoint")
		w.WriteHeader(http.StatusTemporaryRedirect)
	}))
	defer origin.Close()

	endpoint, err := url.Parse(origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	p, err := NewPush(&mockMetrics{exportData: "synthetic_count 1\n"}, nil,
		PushConfig{ForceSending: true, ServerAddress: endpoint}, "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	p.SetPeerID("synthetic-peer-id")

	if err := p.push(context.Background(), origin.URL); err == nil {
		t.Fatal("redirected delivery unexpectedly succeeded")
	}
	if originHits.Load() != 1 || redirectedHits.Load() != 0 {
		t.Errorf("delivery escaped configured endpoint: origin=%d redirected=%d", originHits.Load(), redirectedHits.Load())
	}
}

func TestMetricsDestinationSecurity(t *testing.T) {
	for _, tc := range []struct {
		endpoint string
		allow    bool
	}{
		{"https://collector.example.invalid/metrics", true},
		{"http://collector.example.invalid/metrics", false},
		{"http://localhost:20000/metrics", true},
		{"http://127.0.0.1:20000/metrics", true},
		{"http://[::1]:20000/metrics", true},
		{"http://192.0.2.1:20000/metrics", false},
		{"http://localhost.evil.invalid/metrics", false},
		{"https://user:secret@collector.example.invalid/metrics", false},
		{"https://collector.example.invalid/metrics#fragment", false},
		{"ftp://collector.example.invalid/metrics", false},
	} {
		t.Run(tc.endpoint, func(t *testing.T) {
			target, err := url.Parse(tc.endpoint)
			if err != nil {
				t.Fatal(err)
			}
			if got := validMetricsDestination(target); got != tc.allow {
				t.Errorf("accepted=%v want=%v", got, tc.allow)
			}
			_, err = NewPush(nil, nil, PushConfig{ForceSending: true, ServerAddress: target}, "1.0.0")
			if (err == nil) != tc.allow {
				t.Errorf("constructor accepted=%v want=%v", err == nil, tc.allow)
			}
		})
	}
}

func TestMetricsOutboundGuardAndMissingProvider(t *testing.T) {
	p, err := NewPush(&mockMetrics{exportData: "synthetic_count 1\n"}, nil, PushConfig{}, "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	target, interval := p.resolve(context.Background())
	if target != "" || interval != defaultPushInterval {
		t.Errorf("unexpected fallback: target=%q interval=%s", target, interval)
	}
	for _, raw := range []string{
		"http://collector.example.invalid/metrics",
		"https://collector.example.invalid/metrics#fragment",
		"https://user:secret@collector.example.invalid/metrics",
	} {
		if err := p.push(context.Background(), raw); err == nil {
			t.Error("unsafe telemetry outbound destination accepted")
		}
	}
}
