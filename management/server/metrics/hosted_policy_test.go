package metrics

import (
	"context"
	"errors"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type hostedPolicyTransport struct{ requests atomic.Int32 }

func (t *hostedPolicyTransport) RoundTrip(*http.Request) (*http.Response, error) {
	t.requests.Add(1)
	return nil, errors.New("synthetic transport blocks all external traffic")
}
func installHostedPolicyTransport(t *testing.T) *hostedPolicyTransport {
	t.Helper()
	transport := &hostedPolicyTransport{}
	old := http.DefaultTransport
	http.DefaultTransport = transport
	t.Cleanup(func() { http.DefaultTransport = old })
	return transport
}

func TestHostedMetricsTokenFetchIsDisabled(t *testing.T) {
	transport := installHostedPolicyTransport(t)
	_, err := getAPIKey(context.Background())
	require.Error(t, err)
	require.Zero(t, transport.requests.Load(), "unqualified hosted token requests must never reach transport")
}

func TestHostedMetricsSendIsDisabledBeforeCollection(t *testing.T) {
	transport := installHostedPolicyTransport(t)
	worker := NewWorker(context.Background(), "synthetic-installation", nil, nil, "disabled")
	require.Error(t, worker.sendMetrics(context.Background()))
	require.Zero(t, transport.requests.Load(), "direct sends must fail before fetching tokens or collecting account data")
}

func TestHostedMetricsWorkerDoesNotStartPolling(t *testing.T) {
	transport := installHostedPolicyTransport(t)
	t.Setenv("NETBIRD_METRICS_INTERVAL_IN_SECONDS", "0.02")
	ctx, cancel := context.WithCancel(context.Background())
	worker := NewWorker(ctx, "synthetic-installation", nil, nil, "disabled")
	done := make(chan struct{})
	go func() { worker.Run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	select {
	case <-done:
	case <-time.After(150 * time.Millisecond):
		t.Error("unqualified hosted metrics must not start a polling loop")
	}
	require.Zero(t, transport.requests.Load(), "worker startup must make no hosted request")
}
