package profilemanager

import (
	"testing"

	"github.com/netbirdio/netbird/client/mdm"
	"github.com/stretchr/testify/require"
)

func TestGoreeCloudInMemoryProvisionRequiresExplicitManagementURL(t *testing.T) {
	for _, missing := range []string{"", " ", "\t", "\n"} {
		t.Run("missing", func(t *testing.T) {
			config, err := CreateInMemoryConfig(ConfigInput{ManagementURL: missing})
			require.Nil(t, config)
			require.ErrorContains(t, err, "requires an explicit management URL")
		})
	}
}

func TestGoreeCloudInMemoryProvisionAcceptsExplicitSelfHostedURL(t *testing.T) {
	config, err := CreateInMemoryConfig(ConfigInput{ManagementURL: "https://control.example.test"})
	require.NoError(t, err)
	require.Equal(t, "https://control.example.test:443", config.ManagementURL.String())
	require.NotEmpty(t, config.PrivateKey)
	require.NotEmpty(t, config.SSHKey)
}

func TestGoreeCloudInMemoryProvisionPreservesIntentionalLegacyURL(t *testing.T) {
	config, err := CreateInMemoryConfig(ConfigInput{ManagementURL: DefaultManagementURL})
	require.NoError(t, err)
	require.Equal(t, DefaultManagementURL, config.ManagementURL.String())
}

func TestGoreeCloudInMemoryProvisionRejectsMalformedExplicitURL(t *testing.T) {
	config, err := CreateInMemoryConfig(ConfigInput{ManagementURL: "not-a-url"})
	require.Nil(t, config)
	require.Error(t, err)
}

func TestGoreeCloudInMemoryManagementURLUsesValidManagedPolicy(t *testing.T) {
	managed := mdm.NewPolicy(map[string]any{mdm.KeyManagementURL: "https://managed.example.test"})
	require.Equal(t, "https://managed.example.test", ResolveInMemoryManagementURL("", managed))
	require.Equal(t, "https://managed.example.test", ResolveInMemoryManagementURL("https://other.example.test", managed))
	resolved := ResolveInMemoryManagementURL("", managed)
	config, err := CreateInMemoryConfig(ConfigInput{ManagementURL: resolved})
	require.NoError(t, err)
	require.Equal(t, "https://managed.example.test:443", config.ManagementURL.String())
}

func TestGoreeCloudInMemoryManagementURLWithoutPolicyRequiresExplicitURL(t *testing.T) {
	require.Empty(t, ResolveInMemoryManagementURL("", nil))
	require.Equal(t, "https://provided.example.test", ResolveInMemoryManagementURL("https://provided.example.test", mdm.NewPolicy(nil)))
	config, err := CreateInMemoryConfig(ConfigInput{ManagementURL: ResolveInMemoryManagementURL("", nil)})
	require.Nil(t, config)
	require.Error(t, err)
}

func TestGoreeCloudInMemoryManagementURLRejectsEmptyManagedOverride(t *testing.T) {
	policy := mdm.NewPolicy(map[string]any{mdm.KeyManagementURL: ""})
	config, err := CreateInMemoryConfig(ConfigInput{ManagementURL: ResolveInMemoryManagementURL("", policy)})
	require.Nil(t, config)
	require.Error(t, err)
}
