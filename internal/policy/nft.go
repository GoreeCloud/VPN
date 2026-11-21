// Package policy renders reviewed, default-deny gateway firewall rules.
// This is an offline nftables ruleset; it never executes nft or touches a host.
package policy

import (
	"bytes"
	"errors"
	"fmt"
	"net/netip"
	"sort"

	"github.com/GoreeCloud/VPN/internal/control"
	"github.com/GoreeCloud/VPN/internal/wireguard"
)

// Rule grants one approved peer access to a gateway-local service.
// It NEVER grants forwarding to other peer/private LANs.
type Rule struct {
	PublicKey string `json:"public_key"`
	Protocol  string `json:"protocol"`
	Port      int    `json:"port,omitempty"`
}

// RenderGatewayFirewall creates an offline nftables ruleset for a dedicated
// development gateway interface named "gateway". No system action is taken.
func RenderGatewayFirewall(peers []wireguard.GatewayPeer, rules []Rule) ([]byte, error) {
	if len(peers) > 253 || len(rules) > 1024 {
		return nil, errors.New("gateway firewall limit exceeded")
	}
	addresses := map[string]string{}
	usedAddress := map[string]bool{}
	subnet := netip.MustParsePrefix("10.77.0.0/24")
	for _, p := range peers {
		if !control.ValidPublicKey(p.PublicKey) {
			return nil, errors.New("invalid approved public key")
		}
		prefix, err := netip.ParsePrefix(p.Address)
		if err != nil || !prefix.Addr().Is4() || prefix.Bits() != 32 || !subnet.Contains(prefix.Addr()) {
			return nil, errors.New("invalid approved private address")
		}
		tail := prefix.Addr().As4()[3]
		if tail < 2 || tail > 254 || addresses[p.PublicKey] != "" || usedAddress[p.Address] {
			return nil, errors.New("duplicate or reserved approved peer address")
		}
		addresses[p.PublicKey] = prefix.Addr().String()
		usedAddress[p.Address] = true
	}
	type entry struct {
		source, proto string
		port          int
	}
	entries := make([]entry, 0, len(rules))
	duplicate := map[string]bool{}
	for _, r := range rules {
		ip, exists := addresses[r.PublicKey]
		if !exists {
			return nil, errors.New("firewall grant references a non-approved peer")
		}
		switch r.Protocol {
		case "tcp", "udp":
			if r.Port < 1 || r.Port > 65535 {
				return nil, errors.New("invalid service port")
			}
		case "icmp":
			if r.Port != 0 {
				return nil, errors.New("ICMP cannot have a service port")
			}
		default:
			return nil, errors.New("unsupported service protocol")
		}
		key := fmt.Sprintf("%s|%s|%d", ip, r.Protocol, r.Port)
		if duplicate[key] {
			return nil, errors.New("duplicate service permission")
		}
		duplicate[key] = true
		entries = append(entries, entry{ip, r.Protocol, r.Port})
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].source != entries[j].source {
			return entries[i].source < entries[j].source
		}
		if entries[i].proto != entries[j].proto {
			return entries[i].proto < entries[j].proto
		}
		return entries[i].port < entries[j].port
	})
	var b bytes.Buffer
	b.WriteString("# Offline GoreeCloud VPN gateway service ACL; review before application.\n")
	b.WriteString("# Peer approval and gateway apply are distinct administrator decisions.\n")
	b.WriteString("table inet goreecloud_vpn {\n")
	b.WriteString("  chain input {\n")
	b.WriteString("    type filter hook input priority -10; policy accept;\n")
	for _, e := range entries {
		if e.proto == "icmp" {
			fmt.Fprintf(&b, "    iifname \"gateway\" ip saddr %s ip daddr 10.77.0.1 icmp type echo-request accept\n", e.source)
		} else {
			fmt.Fprintf(&b, "    iifname \"gateway\" ip saddr %s ip daddr 10.77.0.1 %s dport %d accept\n", e.source, e.proto, e.port)
		}
	}
	b.WriteString("    iifname \"gateway\" drop\n")
	b.WriteString("  }\n")
	b.WriteString("  chain forward {\n")
	b.WriteString("    type filter hook forward priority -10; policy accept;\n")
	b.WriteString("    iifname \"gateway\" drop\n")
	b.WriteString("  }\n")
	b.WriteString("}\n")
	return b.Bytes(), nil
}
