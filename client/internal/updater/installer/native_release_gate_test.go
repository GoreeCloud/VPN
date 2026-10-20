//go:build windows || darwin

package installer

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGoreeCloudNativeUpdaterBlockedBeforeSideEffects(t *testing.T) {
	tempDir := filepath.Join(t.TempDir(), "no-updater-files")
	u := NewWithDir(tempDir)
	for _, tc := range []struct {
		name    string
		attempt func() error
	}{
		{"service-triggered installer", func() error {
			return u.RunInstallation(context.Background(), "1.2.3")
		}},
		{"updater direct setup", func() error {
			return u.Setup(context.Background(), false, filepath.Join(tempDir, "old-netbird-installer"), tempDir)
		}},
		{"updater dry run", func() error {
			return u.Setup(context.Background(), true, "", tempDir)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.attempt()
			if err == nil || !strings.Contains(err.Error(), "signed native update channel is not approved") {
				t.Fatalf("expected signed-channel denial, got %v", err)
			}
			if _, statErr := os.Stat(tempDir); !os.IsNotExist(statErr) {
				t.Fatalf("native updater touched filesystem before denial: %v", statErr)
			}
		})
	}
}
