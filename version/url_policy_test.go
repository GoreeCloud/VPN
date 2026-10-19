package version

import (
	"net/url"
	"os"
	"strings"
	"testing"
)

func TestGoreeCloudManualInstallerLinkOwnedByProject(t *testing.T) {
	const expected = "https://github.com/GoreeCloud/VPN/releases"
	if actual := DownloadUrl(); actual != expected {
		t.Fatalf("manual installer link = %q, want %q", actual, expected)
	}
	parsed, err := url.Parse(expected)
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() != "github.com" {
		t.Fatalf("manual link lacks valid project-owned HTTPS destination: %v", err)
	}
}

func TestGoreeCloudReleaseLinksNeverReferenceUpstreamPackageService(t *testing.T) {
	for _, filename := range []string{"url.go", "url_linux.go", "url_windows.go", "url_darwin.go", "url_freebsd.go"} {
		raw, err := os.ReadFile(filename)
		if err != nil {
			t.Fatal(err)
		}
		content := strings.ToLower(string(raw))
		for _, legacy := range []string{"app.netbird.io", "pkgs.netbird.io", "github.com/netbirdio/netbird/releases"} {
			if strings.Contains(content, legacy) {
				t.Errorf("%s still contains inherited download origin %q", filename, legacy)
			}
		}
	}
}
