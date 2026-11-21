package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/GoreeCloud/VPN/internal/control"
	"github.com/GoreeCloud/VPN/internal/credentials"
)

func TestStagedEncryptedRegistryBackupRestore(t *testing.T) {
	private := t.TempDir()
	if err := os.Chmod(private, 0700); err != nil {
		t.Fatal(err)
	}
	original := filepath.Join(private, "source")
	s, err := control.Open(original)
	if err != nil {
		t.Fatal(err)
	}
	p, err := s.Add("approved-laptop", syntheticPublicKey(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Approve(p.ID); err != nil {
		t.Fatal(err)
	}
	pending, err := s.Add("pending-phone", syntheticPublicKey(t))
	if err != nil {
		t.Fatal(err)
	}
	if pending.ApprovedAt != nil {
		t.Fatal("pending peer automatically approved")
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(original, "state.json"))
	if err != nil {
		t.Fatal(err)
	}

	key := filepath.Join(private, "independent.key")
	if err = credentials.Create(key); err != nil {
		t.Fatal(err)
	}
	encrypted := filepath.Join(private, "backup.gcvpnbak")
	if err = backupRegistry(original, key, encrypted); err != nil {
		t.Fatal(err)
	}
	ciphertext, err := os.ReadFile(encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(ciphertext, []byte("approved-laptop")) || bytes.Contains(ciphertext, before) {
		t.Fatal("backup artifact leaked registry metadata")
	}
	if err = backupRegistry(original, key, encrypted); err == nil {
		t.Fatal("overwrote encrypted backup")
	}
	staging := filepath.Join(private, "staged-recovery")
	if err = restoreRegistry(encrypted, key, staging); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(filepath.Join(staging, "state.json"))
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("staged bytes differ: %v", err)
	}
	restored, err := control.Open(staging)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	peers := restored.List()
	if len(peers) != 2 || peers[0].ID != p.ID || peers[0].ApprovedAt == nil ||
		peers[1].ID != pending.ID || peers[1].ApprovedAt != nil {
		t.Fatalf("restored admission decisions changed: %+v", peers)
	}
	if err = restoreRegistry(encrypted, key, staging); err == nil {
		t.Fatal("allowed overwriting existing restored state")
	}

	wrong := filepath.Join(private, "wrong.key")
	if err = credentials.Create(wrong); err != nil {
		t.Fatal(err)
	}
	wrongTarget := filepath.Join(private, "wrong-recovery")
	if err = restoreRegistry(encrypted, wrong, wrongTarget); err == nil {
		t.Fatal("accepted wrong backup key")
	}
	if _, err = os.Lstat(wrongTarget); !os.IsNotExist(err) {
		t.Fatal("created target after failed decrypt")
	}

	altered := append([]byte(nil), ciphertext...)
	altered[len(altered)-1] ^= 0x02
	corrupt := filepath.Join(private, "corrupt.gcvpnbak")
	if err = os.WriteFile(corrupt, altered, 0600); err != nil {
		t.Fatal(err)
	}
	corruptTarget := filepath.Join(private, "corrupt-recovery")
	if err = restoreRegistry(corrupt, key, corruptTarget); err == nil {
		t.Fatal("accepted tampered metadata")
	}
	if _, err = os.Lstat(corruptTarget); !os.IsNotExist(err) {
		t.Fatal("created target after authentication failure")
	}
}
