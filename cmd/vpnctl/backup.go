package main

// Offline owner-private AES-256-GCM backup and staging-only restore of registry
// metadata. No WireGuard tunnel secret is included, no host network is changed.
import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/GoreeCloud/VPN/internal/backup"
	"github.com/GoreeCloud/VPN/internal/control"
	"github.com/GoreeCloud/VPN/internal/credentials"
)

func readBackupKey(path string) ([32]byte, error) {
	var key [32]byte
	if !filepath.IsAbs(path) {
		return key, errors.New("backup key must be an absolute path")
	}
	value, err := credentials.Read(path)
	if err != nil {
		return key, err
	}
	if len(value) != 64 {
		return key, errors.New("backup key must be generated as 32 random bytes")
	}
	raw, err := hex.DecodeString(value)
	if err != nil || len(raw) != 32 {
		return key, errors.New("invalid backup key encoding")
	}
	copy(key[:], raw)
	return key, nil
}
func privateRegistryFile(path string, max int64) ([]byte, error) {
	if !filepath.IsAbs(path) {
		return nil, errors.New("registry file path must be absolute")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() < 1 || info.Size() > max {
		return nil, errors.New("registry file must be private mode-0600, regular and within size limits")
	}
	return os.ReadFile(path)
}
func backupRegistry(stateDir, keyPath, dest string) error {
	if !filepath.IsAbs(stateDir) {
		return errors.New("state directory must be an absolute path")
	}
	dir, err := os.Lstat(stateDir)
	if err != nil {
		return err
	}
	if !dir.IsDir() || dir.Mode()&os.ModeSymlink != 0 || dir.Mode().Perm()&0077 != 0 {
		return errors.New("state directory must be owner-private and non-symlink")
	}
	raw, err := privateRegistryFile(filepath.Join(stateDir, "state.json"), backup.MaxPlaintext)
	if err != nil {
		return err
	}
	if err = control.ValidateSnapshotJSON(raw); err != nil {
		return err
	}
	key, err := readBackupKey(keyPath)
	if err != nil {
		return err
	}
	encrypted, err := backup.Seal(raw, key)
	if err != nil {
		return err
	}
	if err = writePeerSnapshot(dest, encrypted); err != nil {
		return err
	}
	stored, err := os.ReadFile(dest)
	if err != nil {
		return err
	}
	if !bytes.Equal(stored, encrypted) {
		return errors.New("encrypted backup readback mismatch")
	}
	checksum := sha256.Sum256(stored)
	fmt.Printf("Encrypted registry metadata backup created (0600; SHA-256 %x). Backup key stored separately. No tunnel keys included.\n", checksum)
	return nil
}
func restoreRegistry(backupPath, keyPath, destination string) error {
	if !filepath.IsAbs(destination) {
		return errors.New("restore target must be an absolute path")
	}
	// A destination must be newly created, never a live/possibly active registry.
	parent, err := os.Lstat(filepath.Dir(destination))
	if err != nil {
		return err
	}
	if !parent.IsDir() || parent.Mode()&os.ModeSymlink != 0 || parent.Mode().Perm()&0077 != 0 {
		return errors.New("restore parent must be a real private 0700 directory")
	}
	if _, err = os.Lstat(destination); err == nil {
		return errors.New("restore target already exists: refusing overwrite")
	}
	if !os.IsNotExist(err) {
		return err
	}
	key, err := readBackupKey(keyPath)
	if err != nil {
		return err
	}
	stored, err := privateRegistryFile(backupPath, backup.MaxPlaintext+128)
	if err != nil {
		return err
	}
	raw, err := backup.Open(stored, key)
	if err != nil {
		return err
	}
	if err = control.ValidateSnapshotJSON(raw); err != nil {
		return err
	}
	if err = os.Mkdir(destination, 0700); err != nil {
		return err
	}
	store, err := control.Open(destination)
	if err != nil {
		return err
	}
	defer store.Close()
	state := filepath.Join(destination, "state.json")
	f, err := os.OpenFile(state, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	if _, err = f.Write(raw); err != nil {
		_ = f.Close()
		_ = os.Remove(state)
		return err
	}
	if err = f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(state)
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	check, err := os.ReadFile(state)
	if err != nil || !bytes.Equal(check, raw) {
		return errors.New("restored registry readback did not match authenticated backup")
	}
	fmt.Println("Encrypted metadata restored into NEW private staging directory (0600). No daemon, tunnel or network configuration activated.")
	return nil
}
