package metrics

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

type policyCountingMetrics struct {
	mockMetrics
	exports int
}

func (m *policyCountingMetrics) Export(w io.Writer) error {
	m.exports++
	return m.mockMetrics.Export(w)
}

type policyTransport func(*http.Request) (*http.Response, error)

func (f policyTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestDestinationPolicyRejectsUnsafeOverrides(t *testing.T) {
	for _, endpoint := range []string{
		"http://metrics.example.invalid", "https://user:synthetic-secret@metrics.example.invalid",
		"https://metrics.example.invalid?token=synthetic-secret", "https://metrics.example.invalid?",
		"https://metrics.example.invalid#synthetic-secret",
		"https://metrics.example.invalid:0", "https://metrics.example.invalid:65536",
	} {
		for _, forced := range []bool{false, true} {
			push, err := NewPush(&mockMetrics{}, &mockConfigProvider{}, PushConfig{ServerAddress: parseURL(endpoint), ForceSending: forced}, "1.0.0")
			require.Error(t, err, "unsafe override must fail for forced=%t endpoint=%s", forced, endpoint)
			require.Nil(t, push)
		}
	}
}

func TestDestinationPolicyRejectsBeforeExportOrTransport(t *testing.T) {
	for _, endpoint := range []string{"http://metrics.example.invalid", "https://metrics.example.invalid?token=synthetic-secret"} {
		metrics := &policyCountingMetrics{mockMetrics: mockMetrics{exportData: "synthetic_metric 1\n"}}
		push, err := NewPush(metrics, &mockConfigProvider{}, PushConfig{}, "1.0.0")
		require.NoError(t, err)
		requests := 0
		push.client.Transport = policyTransport(func(*http.Request) (*http.Response, error) {
			requests++
			return &http.Response{StatusCode: 204, Body: io.NopCloser(strings.NewReader(""))}, nil
		})
		require.Error(t, push.push(context.Background(), endpoint))
		require.Zero(t, metrics.exports, "denied destinations must not export identifying metrics")
		require.Zero(t, requests, "denied destinations must not reach transport")
	}
}

func TestDestinationPolicyInvalidEnvCannotFallBack(t *testing.T) {
	for _, endpoint := range []string{"https://metrics.example.invalid#", "https://metrics.example.invalid?token=synthetic-secret", "://bad"} {
		t.Setenv(EnvMetricsServerURL, endpoint)
		t.Setenv(EnvMetricsForceSending, "false")
		cfg := PushConfigFromEnv()
		push, err := NewPush(&mockMetrics{}, &mockConfigProvider{config: testConfig("https://fallback.example.invalid", "1.0.0", "2.0.0", defaultPushInterval)}, cfg, "1.0.0")
		require.Error(t, err, "invalid explicit configuration must not silently fall back")
		require.Nil(t, push)
	}
}

func TestDestinationPolicyResolutionAndSnapshot(t *testing.T) {
	provider := &mockConfigProvider{config: testConfig("http://metrics.example.invalid", "1.0.0", "2.0.0", defaultPushInterval)}
	push, err := NewPush(&mockMetrics{}, provider, PushConfig{}, "1.0.0")
	require.NoError(t, err)
	endpoint, _ := push.resolve(context.Background())
	require.Empty(t, endpoint, "an untrusted provider destination must fail closed")
	configured := parseURL("https://metrics.example.invalid/path")
	push, err = NewPush(&mockMetrics{}, nil, PushConfig{ServerAddress: configured, ForceSending: true}, "1.0.0")
	require.NoError(t, err)
	configured.Host = "changed.example.invalid"
	endpoint, _ = push.resolve(context.Background())
	require.Equal(t, "https://metrics.example.invalid/path", endpoint, "caller mutation must not change the destination snapshot")
}

func TestDestinationPolicyTransportErrorRedaction(t *testing.T) {
	push, err := NewPush(&mockMetrics{exportData: "synthetic_metric 1\n"}, &mockConfigProvider{}, PushConfig{}, "1.0.0")
	require.NoError(t, err)
	push.client.Transport = policyTransport(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("synthetic-private-transport-detail")
	})
	err = push.push(context.Background(), "https://metrics.example.invalid/private-sink")
	require.Error(t, err)
	require.NotContains(t, err.Error(), "metrics.example.invalid", "transport errors must not expose the destination")
	require.NotContains(t, err.Error(), "private-sink")
	require.NotContains(t, err.Error(), "synthetic-private-transport-detail")
}

func TestDestinationPolicyLogsOmitDestination(t *testing.T) {
	var output bytes.Buffer
	oldOutput := log.StandardLogger().Out
	oldLevel := log.GetLevel()
	log.SetOutput(&output)
	log.SetLevel(log.DebugLevel)
	t.Cleanup(func() { log.SetOutput(oldOutput); log.SetLevel(oldLevel) })
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	t.Cleanup(server.Close)
	endpoint := server.URL + "/synthetic-private-sink"
	push, err := NewPush(&mockMetrics{exportData: "synthetic_metric 1\n"}, nil, PushConfig{ServerAddress: parseURL(endpoint), ForceSending: true}, "1.0.0")
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	push.Start(ctx)
	require.NoError(t, push.push(context.Background(), endpoint))
	require.NotContains(t, output.String(), "synthetic-private-sink", "start and successful upload logs must omit destination paths")
	require.NotContains(t, output.String(), server.URL)
}

func TestDestinationPolicyMissingProviderSkipsOptionalPush(t *testing.T) {
	push, err := NewPush(&mockMetrics{}, nil, PushConfig{}, "1.0.0")
	require.NoError(t, err)
	endpoint, interval := push.resolve(context.Background())
	require.Empty(t, endpoint, "a missing provider cannot authorize an optional upload")
	require.Equal(t, defaultPushInterval, interval)
}
