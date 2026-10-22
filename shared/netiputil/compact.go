// Package netiputil provides compact binary encoding for IP prefixes used in
// the management proto wire format.
//
// Format: [IP bytes][1 byte prefix_len]
//   - IPv4: 5 bytes total (4 IP + 1 prefix_len, 0-32)
//   - IPv6: 17 bytes total (16 IP + 1 prefix_len, 0-128)
//
// Address family is determined by length: 5 = v4, 17 = v6.
package netiputil

import (
	"fmt"
	"net/netip"
)

// EncodePrefix encodes a netip.Prefix into compact bytes.
// The address is always unmapped before encoding.
func EncodePrefix(p netip.Prefix) ([]byte, error) {
	if !p.IsValid() {
		return nil, fmt.Errorf("invalid IP prefix")
	}

	addr := p.Addr().Unmap()
	bits := p.Bits()
	if addr.Is4() && bits > 32 {
		return nil, fmt.Errorf("invalid prefix length %d for IPv4 address %s (max 32)", bits, addr)
	}
	return append(addr.AsSlice(), byte(bits)), nil
}

// DecodePrefix decodes compact bytes into a netip.Prefix.
func DecodePrefix(b []byte) (netip.Prefix, error) {
	switch len(b) {
	case 5:
		var ip4 [4]byte
		copy(ip4[:], b)
		bits := int(b[len(b)-1])
		if bits > 32 {
			return netip.Prefix{}, fmt.Errorf("invalid IPv4 prefix length %d (max 32)", bits)
		}
		return netip.PrefixFrom(netip.AddrFrom4(ip4), bits), nil
	case 17:
		var ip6 [16]byte
		copy(ip6[:], b)
		addr := netip.AddrFrom16(ip6).Unmap()
		bits := int(b[len(b)-1])
		if addr.Is4() {
			if bits > 32 {
				return netip.Prefix{}, fmt.Errorf("invalid prefix length %d for v4-mapped address (max 32)", bits)
			}
		} else if bits > 128 {
			return netip.Prefix{}, fmt.Errorf("invalid IPv6 prefix length %d (max 128)", bits)
		}
		return netip.PrefixFrom(addr, bits), nil
	default:
		return netip.Prefix{}, fmt.Errorf("invalid compact prefix length %d (expected 5 or 17)", len(b))
	}
}

// EncodeAddrChecked encodes a valid, zone-free address as a compact host
// prefix. The wire format cannot retain an IPv6 interface zone.
func EncodeAddrChecked(a netip.Addr) ([]byte, error) {
	if !a.IsValid() {
		return nil, fmt.Errorf("invalid IP address")
	}
	// Check before Unmap: unmapping a scoped IPv4-mapped address loses its zone.
	if a.Zone() != "" {
		return nil, fmt.Errorf("scoped IP address cannot be encoded as a peer host")
	}
	a = a.Unmap()
	return EncodePrefix(netip.PrefixFrom(a, a.BitLen()))
}

// EncodeAddr retains the legacy errorless API. Unsupported addresses return
// nil; callers that need an explicit failure should use EncodeAddrChecked.
func EncodeAddr(a netip.Addr) []byte {
	encoded, _ := EncodeAddrChecked(a)
	return encoded
}

// DecodeAddr decodes only compact host prefixes (/32 or /128). Network
// policies must use DecodePrefix so their CIDR masks are preserved.
func DecodeAddr(b []byte) (netip.Addr, error) {
	p, err := DecodePrefix(b)
	if err != nil {
		return netip.Addr{}, err
	}
	if p.Bits() != p.Addr().BitLen() {
		return netip.Addr{}, fmt.Errorf("expected host prefix, got /%d", p.Bits())
	}
	return p.Addr(), nil
}
