package installer

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestGoreeCloudInstallerPolicy(t *testing.T) {
	for _, dryRun := range []string{"", "true", "false"} {
		t.Run("dry-run-"+dryRun, func(t *testing.T) {
			t.Setenv("NB_AUTO_UPDATE_DRY_RUN", dryRun)
			root := t.TempDir()
			staging := filepath.Join(root, "must-not-be-created")
			inst := NewWithDir(staging)
			for _, target := range []string{"1.2.3", "latest", "", "../installer"} {
				if err := inst.RunInstallation(context.Background(), target); !errors.Is(err, ErrUpdatesDisabled) {
					t.Fatalf("RunInstallation(%q): got %v, want update-policy rejection", target, err)
				}
			}
			for _, dry := range []bool{false, true} {
				if err := inst.Setup(context.Background(), dry, "untrusted-installer", "untrusted-service"); !errors.Is(err, ErrUpdatesDisabled) {
					t.Fatalf("Setup(dryRun=%t): got %v, want update-policy rejection", dry, err)
				}
			}
			entries, err := os.ReadDir(root)
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 0 {
				t.Fatalf("rejected update created files: %v", entries)
			}
		})
	}
}

func TestGoreeCloudInstallerPreservesExistingResult(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "result.json")
	want := []byte(`{"Success":false,"Error":"preserved evidence"}`)
	if err := os.WriteFile(file, want, 0o600); err != nil {
		t.Fatal(err)
	}
	inst := NewWithDir(root)
	if err := inst.RunInstallation(context.Background(), "1.2.3"); !errors.Is(err, ErrUpdatesDisabled) {
		t.Fatal(err)
	}
	if err := inst.Setup(context.Background(), false, "untrusted-installer", "untrusted-service"); !errors.Is(err, ErrUpdatesDisabled) {
		t.Fatal(err)
	}
	got, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatalf("rejected update changed existing result: %s", got)
	}
}
