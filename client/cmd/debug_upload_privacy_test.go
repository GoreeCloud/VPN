package cmd

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGoreeCloudDebugCLIRequiresExplicitTrustedUploadService(t *testing.T) {
	oldEnabled, oldURL, oldInsecure := uploadBundleFlag, uploadBundleURLFlag, uploadBundleInsecureFlag
	t.Cleanup(func() {
		uploadBundleFlag, uploadBundleURLFlag, uploadBundleInsecureFlag = oldEnabled, oldURL, oldInsecure
	})

	uploadBundleFlag = false
	uploadBundleURLFlag = ""
	uploadBundleInsecureFlag = false
	require.NoError(t, requireExplicitCLIUploadService(), "local bundles must remain available")

	cases := []struct {
		name, address     string
		insecure, allowed bool
	}{
		{"unset", "", false, false},
		{"whitespace", "  ", false, false},
		{"NetBird hosted", "https://upload.debug.netbird.io/upload-url", false, false},
		{"NetBird root", "https://netbird.io/upload", false, false},
		{"NetBird trailing root dot", "https://upload.debug.netbird.io./upload-url", false, false},
		{"NetBird uppercase host", "https://UPLOAD.DEBUG.NETBIRD.IO/upload-url", false, false},
		{"legacy cloud", "https://admin.wiretrustee.com/upload", false, false},
		{"other upstream", "https://netbird.cloud/upload", false, false},
		{"plain HTTP", "http://support.example.test/upload", false, false},
		{"invalid", "not-a-url", false, false},
		{"credentials", "https://user:secret@support.example.test/upload", false, false},
		{"fragment", "https://support.example.test/upload#token", false, false},
		{"insecure override", "https://support.example.test/upload", true, false},
		{"explicit trusted HTTPS", "https://support.example.test/upload", false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			uploadBundleFlag = true
			uploadBundleURLFlag = tc.address
			uploadBundleInsecureFlag = tc.insecure
			err := requireExplicitCLIUploadService()
			require.Equal(t, tc.allowed, err == nil, "validation result: %v", err)
			if !tc.allowed {
				require.NotNil(t, err)
				// Rejected upload input must fail before any daemon connection.
				require.Error(t, debugBundle(nil, nil))
				require.Error(t, runForDuration(nil, nil))
			}
		})
	}
}

func TestGoreeCloudDebugBundleUploadFlagsHaveNoHostedDefaults(t *testing.T) {
	for _, cmd := range []*struct{ name, defaultURL string }{
		{"bundle", debugBundleCmd.Flags().Lookup("upload-bundle-url").DefValue},
		{"for", forCmd.Flags().Lookup("upload-bundle-url").DefValue},
	} {
		require.True(t, strings.TrimSpace(cmd.defaultURL) == "", "%s should have no inherited hosted default", cmd.name)
	}
}
