package remoteconfig

import (
	"context"
	"math"
	"testing"
	"time"
)

func TestGoreeCloudConfigRejectsOverflowMinutes(t *testing.T) {
	maxSafe := int(math.MaxInt64 / int64(time.Minute))
	for _, tc := range []struct {
		minutes int
		valid   bool
	}{
		{1, true},
		{maxSafe, true},
		{maxSafe + 1, false},
		{0, false},
		{-1, false},
	} {
		server := newConfigServer(t, rawConfig{
			ServerURL:     "https://ingest.example.invalid/metrics",
			VersionSince:  "1.0.0",
			VersionUntil:  "2.0.0",
			PeriodMinutes: tc.minutes,
		})
		got := NewManager(server.URL, time.Minute).RefreshIfNeeded(context.Background())
		server.Close()
		if (got != nil) != tc.valid {
			t.Fatalf("accepted minutes=%d, want accepted=%v", tc.minutes, tc.valid)
		}
		if got != nil && got.Interval <= 0 {
			t.Fatalf("invalid interval: %s", got.Interval)
		}
	}
}
