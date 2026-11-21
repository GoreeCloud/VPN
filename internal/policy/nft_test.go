package policy

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/GoreeCloud/VPN/internal/wireguard"
)

func public(t *testing.T) string {
	t.Helper()
	x, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(x.PublicKey().Bytes())
}
func TestDefaultDenyAndExplicitGatewayAllow(t *testing.T) {
	key := public(t)
	peers := []wireguard.GatewayPeer{{PublicKey: key, Address: "10.77.0.2/32"}}
	empty, err := RenderGatewayFirewall(peers, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(empty), "iifname \"gateway\" drop") ||
		!strings.Contains(string(empty), "chain forward") ||
		strings.Contains(string(empty), " dport ") {
		t.Fatal("not default deny")
	}
	allow, err := RenderGatewayFirewall(peers, []Rule{
		{PublicKey: key, Protocol: "tcp", Port: 443},
		{PublicKey: key, Protocol: "icmp"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(allow), "ip saddr 10.77.0.2 ip daddr 10.77.0.1 tcp dport 443 accept") ||
		!strings.Contains(string(allow), "icmp type echo-request accept") ||
		!strings.Contains(string(allow), "chain forward") {
		t.Fatal("missing scoped gateway-local rules")
	}
	again, err := RenderGatewayFirewall(peers, []Rule{
		{PublicKey: key, Protocol: "icmp"},
		{PublicKey: key, Protocol: "tcp", Port: 443},
	})
	if err != nil || string(allow) != string(again) {
		t.Fatal("nondeterministic firewall output")
	}
}
func TestFirewallRefusesOverbroadOrNonmemberRules(t *testing.T) {
	key := public(t)
	other := public(t)
	base := []wireguard.GatewayPeer{{PublicKey: key, Address: "10.77.0.2/32"}}
	tests := []struct {
		name  string
		peers []wireguard.GatewayPeer
		rules []Rule
	}{
		{"unapproved", base, []Rule{{PublicKey: other, Protocol: "tcp", Port: 443}}},
		{"wildcard", base, []Rule{{PublicKey: key, Protocol: "any", Port: 443}}},
		{"wrong-port", base, []Rule{{PublicKey: key, Protocol: "tcp", Port: 0}}},
		{"overflow", base, []Rule{{PublicKey: key, Protocol: "udp", Port: 65536}}},
		{"icmp-port", base, []Rule{{PublicKey: key, Protocol: "icmp", Port: 53}}},
		{"duplicate", base, []Rule{{PublicKey: key, Protocol: "tcp", Port: 443}, {PublicKey: key, Protocol: "tcp", Port: 443}}},
		{"subnet", []wireguard.GatewayPeer{{PublicKey: key, Address: "0.0.0.0/0"}}, nil},
		{"gateway-address", []wireguard.GatewayPeer{{PublicKey: key, Address: "10.77.0.1/32"}}, nil},
		{"duplicate-peers", append(base, base[0]), nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := RenderGatewayFirewall(tc.peers, tc.rules); err == nil {
				t.Fatal("unsafe rule accepted")
			}
		})
	}
}
