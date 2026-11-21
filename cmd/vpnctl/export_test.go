package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func syntheticPublicKey(t *testing.T) string {
	t.Helper()
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(key.PublicKey().Bytes())
}

func TestActivePeerSnapshotFiltersRevoked(t *testing.T) {
	now := time.Now().UTC()
	p1 := registeredPeer{ID: strings.Repeat("a", 32), Name: "Laptop", PublicKey: syntheticPublicKey(t), Address: "10.77.0.2/32", CreatedAt: now, ApprovedAt: &now}
	p2 := registeredPeer{ID: strings.Repeat("b", 32), Name: "Phone", PublicKey: syntheticPublicKey(t), Address: "10.77.0.3/32", CreatedAt: now, RevokedAt: &now}
	pending := registeredPeer{ID: strings.Repeat("c", 32), Name: "Pending", PublicKey: syntheticPublicKey(t), Address: "10.77.0.4/32", CreatedAt: now}
	source, _ := json.Marshal(map[string]any{"peers": []registeredPeer{p2, pending, p1}})
	output, err := activePeerSnapshot(source)
	if err != nil {
		t.Fatal(err)
	}
	var records []map[string]string
	if err = json.Unmarshal(output, &records); err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0]["address"] != p1.Address || records[0]["public_key"] != p1.PublicKey {
		t.Fatalf("revoked or pending peer not filtered from gateway: %s", output)
	}
	private := t.TempDir()
	if err = os.Chmod(private, 0700); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(private, "peers.json")
	if err = writePeerSnapshot(file, output); err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(file)
	if info.Mode().Perm() != 0600 {
		t.Fatal("not mode 0600")
	}
	if err = writePeerSnapshot(file, output); err == nil {
		t.Fatal("existing snapshot must not be overwritten")
	}
}

func TestActivePeerSnapshotFailsClosed(t *testing.T) {
	now := time.Now().UTC()
	valid := registeredPeer{ID: strings.Repeat("c", 32), Name: "Phone", PublicKey: syntheticPublicKey(t), Address: "10.77.0.2/32", CreatedAt: now}
	tests := []struct {
		name  string
		input string
	}{
		{"empty", ""},
		{"wrong schema", "{\"devices\":[]}"},
		{"bad json", "{\"peers\":"},
		{"trailing", "{\"peers\":[]} true"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := activePeerSnapshot([]byte(tc.input)); err == nil {
				t.Fatal("accepted invalid snapshot")
			}
		})
	}
	corrupt := valid
	corrupt.Address = "10.77.0.1/32"
	raw, _ := json.Marshal(map[string]any{"peers": []registeredPeer{corrupt}})
	if _, err := activePeerSnapshot(raw); err == nil {
		t.Fatal("accepted reserved gateway address")
	}
	malformed, _ := json.Marshal(map[string]any{"peers": []registeredPeer{valid, valid}})
	if _, err := activePeerSnapshot(malformed); err == nil {
		t.Fatal("accepted duplicate peer")
	}
	tmp := t.TempDir()
	if err := os.Chmod(tmp, 0755); err != nil {
		t.Fatal(err)
	}
	if err := writePeerSnapshot(filepath.Join(tmp, "world-readable.json"), []byte("[]")); err == nil {
		t.Fatal("accepted public output parent")
	}
}
