package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/GoreeCloud/VPN/internal/policy"
	"github.com/GoreeCloud/VPN/internal/wireguard"
)

func TestOfflineACLRequiresReviewedMemberAndOwnerPrivateFiles(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	key := syntheticPublicKey(t)
	peers, _ := json.Marshal([]wireguard.GatewayPeer{{PublicKey: key, Address: "10.77.0.2/32"}})
	rules, _ := json.Marshal([]policy.Rule{{PublicKey: key, Protocol: "tcp", Port: 443}})
	source := filepath.Join(dir, "approved.json")
	permissions := filepath.Join(dir, "rules.json")
	output := filepath.Join(dir, "gateway.nft")
	if err := os.WriteFile(source, peers, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(permissions, rules, 0600); err != nil {
		t.Fatal(err)
	}
	if err := writeGatewayAccessPolicy(source, permissions, output); err != nil {
		t.Fatal(err)
	}
	out, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "tcp dport 443 accept") || !strings.Contains(string(out), "iifname \"gateway\" drop") {
		t.Fatal("gateway ACL omitted service restriction")
	}
	fi, _ := os.Stat(output)
	if fi.Mode().Perm() != 0600 {
		t.Fatal("ACL not mode 0600")
	}
	if err := writeGatewayAccessPolicy(source, permissions, output); err == nil {
		t.Fatal("overwrote existing policy")
	}
	if err := os.WriteFile(permissions, []byte("[{}]"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := writeGatewayAccessPolicy(source, permissions, filepath.Join(dir, "bad.nft")); err == nil {
		t.Fatal("policy allowed an identity-free wildcard")
	}
	if err := os.Chmod(permissions, 0644); err != nil {
		t.Fatal(err)
	}
	if err := writeGatewayAccessPolicy(source, permissions, filepath.Join(dir, "unsafe.nft")); err == nil {
		t.Fatal("policy accepted world-readable metadata")
	}
}
