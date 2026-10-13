package metrics

import "testing"

func TestMetricsServerURLFromEnvTransportPolicy(t *testing.T) {
	for _, tc := range []struct {
		endpoint string
		allowed  bool
	}{
		{"", false},
		{"https://collector.example.invalid/metrics", true},
		{"http://collector.example.invalid/metrics", false},
		{"https://user:secret@collector.example.invalid/metrics", false},
		{"https://collector.example.invalid/metrics#fragment", false},
		{"http://localhost:8080/metrics", true},
		{"http://127.0.0.1:8080/metrics", true},
		{"http://[::1]:8080/metrics", true},
		{"http://192.0.2.12:8080/metrics", false},
	} {
		t.Run(tc.endpoint, func(t *testing.T) {
			t.Setenv(EnvMetricsServerURL, tc.endpoint)
			if accepted := getMetricsServerURL() != nil; accepted != tc.allowed {
				t.Errorf("configured destination accepted=%v, want=%v", accepted, tc.allowed)
			}
		})
	}
}
