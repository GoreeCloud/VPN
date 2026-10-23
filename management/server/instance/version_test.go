package instance

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/version"
)

// The instance API must not infer a latest release from inherited NetBird
// hosting. No HTTP client, remote URL, or cached remote version is needed.
func TestDefaultManager_GetVersionInfo_LocalOnly(t *testing.T) {
	m := &DefaultManager{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	for _, requestContext := range []context.Context{context.Background(), ctx} {
		for range 3 {
			info, err := m.GetVersionInfo(requestContext)
			require.NoError(t, err)
			require.Equal(t, version.NetbirdVersion(), info.CurrentVersion)
			require.Empty(t, info.ManagementVersion)
			require.Empty(t, info.DashboardVersion)
			require.False(t, info.ManagementUpdateAvailable)
		}
	}
}

func TestDefaultManager_NoInheritedReleaseDiscoverySource(t *testing.T) {
	source, err := os.ReadFile("manager.go")
	require.NoError(t, err)

	for _, forbidden := range []string{
		"pkgs.netbird.io",
		"api.github.com/repos/netbirdio/dashboard",
		"managementVersionURL",
		"dashboardReleasesURL",
		"fetchGitHubRelease",
		"fetchPlainTextVersion",
		"http.Client",
	} {
		require.False(t, strings.Contains(string(source), forbidden),
			"management version API must not retain inherited release discovery: %s", forbidden)
	}
}
