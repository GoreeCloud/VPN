package netiputil

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestHostDecoderRejectsNetworks(t *testing.T) {
	for _, value := range []string{"192.0.2.9/24", "0.0.0.0/0", "2001:db8::1/64", "::/0", "::ffff:192.0.2.9/24"} {
		t.Run(value, func(t *testing.T) {
			prefix := netip.MustParsePrefix(value)
			wire, err := EncodePrefix(prefix)
			require.NoError(t, err)
			decoded, err := DecodeAddr(wire)
			require.Error(t, err, "network prefix must not become a peer host")
			require.False(t, decoded.IsValid())
			// The ACL prefix API must retain its separate network semantics.
			got, err := DecodePrefix(wire)
			require.NoError(t, err)
			require.Equal(t, prefix.Bits(), got.Bits())
		})
	}
}

func TestHostEncoderRejectsScopedAddresses(t *testing.T) {
	for _, value := range []string{"fe80::1%eth0", "::ffff:192.0.2.1%eth0"} {
		t.Run(value, func(t *testing.T) {
			address := netip.MustParseAddr(value)
			require.Nil(t, EncodeAddr(address), "wire format cannot retain an interface zone")
			encoded, err := EncodeAddrChecked(address)
			require.Error(t, err)
			require.Nil(t, encoded)
		})
	}
}

func TestCheckedHostEncoderRoundTrips(t *testing.T) {
	encoded, err := EncodeAddrChecked(netip.Addr{})
	require.Error(t, err)
	require.Nil(t, encoded)
	for _, text := range []string{"192.0.2.1", "2001:db8::1", "::ffff:192.0.2.1", "0.0.0.0", "::"} {
		address := netip.MustParseAddr(text)
		wire, err := EncodeAddrChecked(address)
		require.NoError(t, err)
		require.Equal(t, wire, EncodeAddr(address))
		decoded, err := DecodeAddr(wire)
		require.NoError(t, err)
		require.Equal(t, address.Unmap(), decoded)
	}
	// Preserve compatibility with the existing mapped /32 wire representation.
	mapped := netip.MustParseAddr("::ffff:192.0.2.1").As16()
	wire := append(mapped[:], byte(32))
	decoded, err := DecodeAddr(wire)
	require.NoError(t, err)
	require.Equal(t, netip.MustParseAddr("192.0.2.1"), decoded)
}

func FuzzHostDecoderBoundary(f *testing.F) {
	for _, seed := range [][]byte{nil, {192, 0, 2, 1, 32}, {192, 0, 2, 1, 24}, make([]byte, 17)} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, wire []byte) {
		host, err := DecodeAddr(wire)
		if err != nil {
			require.False(t, host.IsValid())
			return
		}
		require.True(t, host.IsValid())
		prefix, err := DecodePrefix(wire)
		require.NoError(t, err)
		require.Equal(t, host.BitLen(), prefix.Bits())
		canonical, err := EncodeAddrChecked(host)
		require.NoError(t, err)
		again, err := DecodeAddr(canonical)
		require.NoError(t, err)
		require.Equal(t, host, again)
	})
}
