package netiputil

import (
	"bytes"
	"net/netip"
	"testing"
)

func TestEncodeAddrCheckedRoundTrip(t *testing.T) {
	for _, input := range []struct {
		address string
		want    string
		size    int
	}{
		{"100.64.0.9", "100.64.0.9", 5},
		{"fd00::abcd", "fd00::abcd", 17},
		{"::ffff:10.0.0.8", "10.0.0.8", 5},
	} {
		t.Run(input.address, func(t *testing.T) {
			encoded, err := EncodeAddrChecked(netip.MustParseAddr(input.address))
			if err != nil {
				t.Fatal(err)
			}
			if len(encoded) != input.size {
				t.Fatalf("encoded length = %d, want %d", len(encoded), input.size)
			}
			decoded, err := DecodeAddr(encoded)
			if err != nil {
				t.Fatal(err)
			}
			if got := decoded.String(); got != input.want {
				t.Fatalf("decoded address = %q, want %q", got, input.want)
			}
			if !bytes.Equal(EncodeAddr(netip.MustParseAddr(input.address)), encoded) {
				t.Fatal("legacy encoder must remain wire compatible")
			}
		})
	}
}

func TestEncodeAddrCheckedRejectsUnsupportedInputs(t *testing.T) {
	for _, address := range []netip.Addr{
		{},
		netip.MustParseAddr("fe80::1%eth0"),
	} {
		value, err := EncodeAddrChecked(address)
		if err == nil || value != nil {
			t.Fatalf("invalid address %q must fail without emitting data: %v, %v", address, value, err)
		}
		if got := EncodeAddr(address); got != nil {
			t.Fatalf("legacy invalid input must return nil, got %x", got)
		}
	}
}
