package updater

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/netbirdio/netbird/client/internal/peer"
	"github.com/netbirdio/netbird/client/internal/statemanager"
)

func TestGoreeCloudUpdateDirectiveCannotEnableInstaller(t *testing.T) {
	m := NewManager(peer.NewRecorder(""), statemanager.New(filepath.Join(t.TempDir(), "state.json")))
	if m.autoUpdateSupported() {
		t.Fatal("inherited automatic installer is enabled")
	}
	for _, target := range []string{"1.2.3", "latest"} {
		m.SetVersion(target, true)
		if m.mode != modeDownloadOnly || m.forceUpdate || m.pendingVersion != nil || m.expectedVersion != nil {
			t.Fatalf("directive %q staged an inherited install", target)
		}
		if err := m.Install(context.Background()); err == nil {
			t.Fatal("Install accepted an inherited update")
		}
	}
}
