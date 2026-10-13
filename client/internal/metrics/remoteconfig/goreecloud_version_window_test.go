package remoteconfig

import (
	"context"
	"testing"
)

func TestGoreeCloudRemoteConfigVersionWindow(t *testing.T) {
	tests := []struct {
		name, since, until string
		valid              bool
	}{
		{"inverted", "3.2.0", "2.9.0", false},
		{"same version", "2.1.0", "2.1.0", true},
		{"ascending", "1.0.0", "2.1.0", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			server := newConfigServer(t, rawConfig{
				ServerURL:     "https://ingest.example.com",
				VersionSince:  tc.since,
				VersionUntil:  tc.until,
				PeriodMinutes: 60,
			})
			defer server.Close()
			manager := NewManager(server.URL, testMinRefresh)
			config := manager.RefreshIfNeeded(context.Background())
			if (config != nil) != tc.valid {
				t.Fatalf("version window %q..%q accepted=%t, want=%t",
					tc.since, tc.until, config != nil, tc.valid)
			}
			if !tc.valid && manager.lastConfig != nil {
				t.Fatal("invalid successful config was incorrectly cached")
			}
		})
	}
}
