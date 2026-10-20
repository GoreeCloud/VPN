package profilemanager

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestGoreeCloudLegacyCloudMigrationRequiresExplicitOptIn(t *testing.T) {
	oldProber := newMgmProber
	calls := 0
	newMgmProber = func(_ context.Context, _ string, _ wgtypes.Key, _ bool) (mgmProber, error) {
		calls++
		return &mockMgmProber{}, nil
	}
	t.Cleanup(func() { newMgmProber = oldProber })

	// A real serialized legacy profile, not a synthetic empty Config:
	// neither its connection endpoint nor existing peer identity may change.
	configPath := filepath.Join(t.TempDir(), "legacy.json")
	stored, err := UpdateOrCreateConfig(ConfigInput{
		ConfigPath:    configPath,
		ManagementURL: "https://api.wiretrustee.com:33073",
	})
	require.NoError(t, err)
	require.NotEmpty(t, stored.PrivateKey)
	require.NotEmpty(t, stored.SSHKey)
	before, err := os.ReadFile(configPath)
	require.NoError(t, err)

	for _, value := range []string{"", "false", "TRUE", "1"} {
		t.Run("flag="+value, func(t *testing.T) {
			t.Setenv("GOREECLOUD_ENABLE_LEGACY_CLOUD_MIGRATION", value)
			actual, err := UpdateOldManagementURL(context.Background(), stored, configPath)
			require.NoError(t, err)
			require.Same(t, stored, actual, "implicit migration must not alter the profile")
			require.Equal(t, "https://api.wiretrustee.com:33073", actual.ManagementURL.String())
			require.Equal(t, stored.PrivateKey, actual.PrivateKey)
			require.Equal(t, stored.SSHKey, actual.SSHKey)
			after, err := os.ReadFile(configPath)
			require.NoError(t, err)
			require.Equal(t, before, after, "implicit migration rewrote the stored profile")
			require.Zero(t, calls, "implicit migration probed hosted NetBird management")
		})
	}
}
