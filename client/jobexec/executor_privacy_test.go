package jobexec

import (
	"context"
	"strings"
	"testing"

	"github.com/netbirdio/netbird/client/internal/debug"
)

func TestGoreeCloudExplicitDebugUploadURL(t *testing.T) {
	for _, tc := range []struct {
		name  string
		url   string
		allow bool
	}{
		{"unset", "", false},
		{"whitespace", "   ", false},
		{"inherited debug", "https://upload.debug.netbird.io/upload-url", false},
		{"inherited host case", "https://API.NETBIRD.IO/upload", false},
		{"inherited apex", "https://netbird.io/upload", false},
		{"legacy cloud", "https://api.wiretrustee.com/upload", false},
		{"non HTTPS", "http://support.example.test/upload", false},
		{"relative", "/upload", false},
		{"username", "https://user:secret@support.example.test/upload", false},
		{"fragment", "https://support.example.test/upload#token", false},
		{"empty fragment", "https://support.example.test/upload#", false},
		{"malformed", "not-an-endpoint", false},
		{"explicit HTTPS", "https://support.example.test/upload-url", true},
		{"explicit HTTPS with path", "https://support.example.test/v1/bundle?region=west", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := requireExplicitDebugUploadURL(tc.url)
			if (err == nil) != tc.allow {
				t.Fatalf("URL %q allowed=%v, want allowed=%v (err=%v)", tc.url, err == nil, tc.allow, err)
			}
		})
	}
}

func TestGoreeCloudRemoteJobRejectsUnsetOrUpstreamUploadBeforeBundleGeneration(t *testing.T) {
	executor := NewExecutor()
	for _, endpoint := range []string{"", "https://upload.debug.netbird.io/upload-url", "http://support.example.test/upload"} {
		// No bundle dependencies are supplied: an invalid request must fail
		// before generating a bundle, reading logs, or attempting network I/O.
		key, err := executor.BundleJob(context.Background(), debug.GeneratorDependencies{}, debug.BundleConfig{}, 0, "", endpoint)
		if err == nil || key != "" {
			t.Fatalf("endpoint %q unexpectedly executed: key=%q, err=%v", endpoint, key, err)
		}
		if !strings.Contains(err.Error(), "upload") {
			t.Fatalf("unexpected error for %q: %v", endpoint, err)
		}
	}
}
