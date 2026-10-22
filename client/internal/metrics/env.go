package metrics

import (
	"fmt"
	"net/url"
	"os"
	"strconv"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/metrics/remoteconfig"
)

const (
	// EnvMetricsPushEnabled controls whether collected metrics are pushed to the backend.
	// Metrics collection itself is always active (for debug bundles).
	// Disabled by default. Set NB_METRICS_PUSH_ENABLED=true to enable push.
	EnvMetricsPushEnabled = "NB_METRICS_PUSH_ENABLED"

	// EnvMetricsForceSending skips remote configuration fetch. It requires
	// NB_METRICS_SERVER_URL to identify an explicit destination.
	EnvMetricsForceSending = "NB_METRICS_FORCE_SENDING"

	// EnvMetricsConfigURL is the environment variable to override the metrics push config ServerAddress
	EnvMetricsConfigURL = "NB_METRICS_CONFIG_URL"

	// EnvMetricsServerURL is the environment variable to override the metrics server address.
	// When set, this takes precedence over the server_url from remote push config.
	EnvMetricsServerURL = "NB_METRICS_SERVER_URL"

	// EnvMetricsInterval overrides the push interval from the remote config.
	// Only affects how often metrics are pushed; remote config availability
	// and version range checks are still respected.
	// Format: duration string like "1h", "30m", "4h"
	EnvMetricsInterval = "NB_METRICS_INTERVAL"

	// GoreeCloud VPN intentionally has no inherited remote metrics endpoint.
	// Operators must explicitly configure NB_METRICS_CONFIG_URL before any
	// remotely configured metrics transmission can be attempted.
	defaultMetricsConfigURL = ""
)

// IsMetricsPushEnabled returns true if metrics push is enabled via NB_METRICS_PUSH_ENABLED env var.
// Disabled by default. Metrics collection is always active for debug bundles.
func IsMetricsPushEnabled() bool {
	enabled, _ := strconv.ParseBool(os.Getenv(EnvMetricsPushEnabled))
	return enabled
}

// getMetricsInterval returns the metrics push interval from NB_METRICS_INTERVAL env var.
// Returns 0 if not set or invalid.
func getMetricsInterval() time.Duration {
	intervalStr := os.Getenv(EnvMetricsInterval)
	if intervalStr == "" {
		return 0
	}
	interval, err := time.ParseDuration(intervalStr)
	if err != nil {
		log.Warnf("invalid metrics interval from env %q: %v", intervalStr, err)
		return 0
	}
	if interval <= 0 {
		log.Warnf("invalid metrics interval from env %q: must be positive", intervalStr)
		return 0
	}
	return interval
}

// isMetricsPushEnvSet returns true if NB_METRICS_PUSH_ENABLED is explicitly set (to any value).
// When set, the env var takes full precedence over management server configuration.
func isMetricsPushEnvSet() bool {
	_, set := os.LookupEnv(EnvMetricsPushEnabled)
	return set
}

func isForceSending() bool {
	force, _ := strconv.ParseBool(os.Getenv(EnvMetricsForceSending))
	return force
}

// getMetricsConfigURL returns the URL to fetch push configuration from
func getMetricsConfigURL() string {
	if envURL := os.Getenv(EnvMetricsConfigURL); envURL != "" {
		return envURL
	}
	return defaultMetricsConfigURL
}

// getMetricsServerURL returns an explicitly configured, safe metrics destination.
// Invalid overrides return an error so callers cannot fall back to another target.
func getMetricsServerURL() (*url.URL, error) {
	raw := os.Getenv(EnvMetricsServerURL)
	if raw == "" {
		return nil, nil
	}
	if !remoteconfig.ValidEndpoint(raw) {
		return nil, fmt.Errorf("metrics server URL rejected by transport policy")
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("cannot parse metrics server URL")
	}
	return parsed, nil
}
