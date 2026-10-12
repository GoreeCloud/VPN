package metrics

import (
	"context"
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
