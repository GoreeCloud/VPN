package metrics

import "net/url"

// safeMetricsPushURL validates the destination at the final outbound
// boundary, even when a caller bypasses resolveServerURL.
func safeMetricsPushURL(raw string) bool {
	parsed, err := url.Parse(raw)
	return err == nil && validMetricsDestination(parsed)
}
