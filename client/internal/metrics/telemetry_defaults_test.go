package metrics

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGoreeCloudMetricsHasNoImplicitConfigEndpoint(t *testing.T) {
	t.Setenv(EnvMetricsConfigURL, "")
	require.Empty(t, getMetricsConfigURL())
	t.Setenv(EnvMetricsConfigURL, "https://metrics.example.test/config")
	require.Equal(t, "https://metrics.example.test/config", getMetricsConfigURL())
}

func TestForceMetricsPushRequiresExplicitDestination(t *testing.T) {
	t.Setenv(EnvMetricsForceSending, "true")
	t.Setenv(EnvMetricsServerURL, "")
	config := PushConfigFromEnv()
	require.True(t, config.ForceSending)
	require.Nil(t, config.ServerAddress)
	push, err := NewPush(&mockMetrics{}, &mockConfigProvider{}, config, "1.0.0")
	require.ErrorContains(t, err, "requires explicit server URL")
	require.Nil(t, push)
}

func TestForceMetricsPushRespectsOperatorDestination(t *testing.T) {
	t.Setenv(EnvMetricsForceSending, "true")
	t.Setenv(EnvMetricsServerURL, "https://metrics.example.test")
	config := PushConfigFromEnv()
	push, err := NewPush(&mockMetrics{}, &mockConfigProvider{}, config, "1.0.0")
	require.NoError(t, err)
	require.Equal(t, "https://metrics.example.test", push.cfgAddress.String())
}
