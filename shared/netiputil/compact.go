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

// EncodeAddrChecked encodes a valid address into a compact host-prefix value.
// Callers handling untrusted network configuration should prefer this function
// to the legacy EncodeAddr API so invalid addresses return an explicit error.
func EncodeAddrChecked(a netip.Addr) ([]byte, error) {
	if !a.IsValid() {
		return nil, fmt.Errorf("invalid IP address")
	}
	a = a.Unmap()
	if a.Zone() != "" {
		return nil, fmt.Errorf("zoned IPv6 addresses are not supported in prefix encoding")
	}
	bits := 128
	if a.Is4() {
		bits = 32
	}
	return EncodePrefix(netip.PrefixFrom(a, bits))
}

// EncodeAddr preserves the existing errorless API for legacy callers.
// Invalid or unsupported addresses yield nil; new callers should use
// EncodeAddrChecked and handle its explicit error.
func EncodeAddr(a netip.Addr) []byte {
	b, _ := EncodeAddrChecked(a)
	return b
}

// DecodeAddr decodes compact prefix bytes and returns only the address,
// discarding the prefix length. Useful when the prefix length is implied
// (e.g. peer overlay IPs are always /32 or /128).
func DecodeAddr(b []byte) (netip.Addr, error) {
	p, err := DecodePrefix(b)
	if err != nil {
		return netip.Addr{}, err
	}
	return p.Addr(), nil
}
