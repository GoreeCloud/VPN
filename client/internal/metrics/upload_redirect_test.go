package metrics

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
)

type resetCountingMetrics struct {
	mockMetrics
	resets atomic.Int32
}

func (m *resetCountingMetrics) Reset() { m.resets.Add(1) }

func TestUploadRedirectNeverForwardsMetricsOrPeerIdentity(t *testing.T) {
	for _, code := range []int{301, 302, 303, 307, 308} {
		t.Run(fmt.Sprint(code), func(t *testing.T) {
			var forwarded atomic.Int32
			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				forwarded.Add(1)
				w.WriteHeader(http.StatusNoContent)
			}))
			defer target.Close()
			var redirect atomic.Bool
			redirect.Store(true)
			source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if redirect.Load() {
					http.Redirect(w, r, target.URL, code)
					return
				}
				w.WriteHeader(http.StatusNoContent)
			}))
			defer source.Close()
			metrics := &resetCountingMetrics{mockMetrics: mockMetrics{exportData: "synthetic_metric 1\n"}}
			push, err := NewPush(metrics, &mockConfigProvider{}, PushConfig{}, "1.0.0")
			require.NoError(t, err)
			push.SetPeerID("synthetic-peer")
			require.Error(t, push.push(context.Background(), source.URL))
			require.Zero(t, forwarded.Load(), "an unapproved redirect target must receive no request")
			require.Zero(t, metrics.resets.Load(), "failed delivery must retain the metrics batch")
			redirect.Store(false)
			require.NoError(t, push.push(context.Background(), source.URL))
			require.Equal(t, int32(1), metrics.resets.Load())
			require.Zero(t, forwarded.Load())
		})
	}
}
