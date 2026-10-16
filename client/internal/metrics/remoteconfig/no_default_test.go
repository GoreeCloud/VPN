package remoteconfig

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestNoDefaultMetricsConfigEndpointSkipsNetworkFetch(t *testing.T) {
	manager := NewManager("", time.Minute)
	require.Nil(t, manager.RefreshIfNeeded(context.Background()))
	require.Nil(t, manager.lastConfig)
	require.True(t, manager.lastFetched.IsZero(), "an unset endpoint must not schedule any remote fetch")
}
