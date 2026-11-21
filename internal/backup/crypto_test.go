package backup

import (
	"bytes"
	"crypto/rand"
	"strings"
	"testing"
)

func randomKey(t *testing.T) [32]byte {
	t.Helper()
	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		t.Fatal(err)
	}
	return key
}
func TestEncryptedBackupRoundTripAndTamperDenial(t *testing.T) {
	first := randomKey(t)
	second := randomKey(t)
	plain := []byte("{\"version\":1,\"peers\":[]}")
	sealed, err := Seal(plain, first)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, plain) || bytes.Equal(sealed, plain) {
		t.Fatal("plaintext leaked")
	}
	opened, err := Open(sealed, first)
	if err != nil || !bytes.Equal(opened, plain) {
		t.Fatalf("restore failed: %v", err)
	}
	other, err := Seal(plain, first)
	if err != nil || bytes.Equal(other, sealed) {
		t.Fatal("nonce was not randomized")
	}
	if _, err := Open(sealed, second); err == nil {
		t.Fatal("wrong key accepted")
	}
	altered := append([]byte(nil), sealed...)
	altered[len(altered)-1] ^= 0x01
	if _, err := Open(altered, first); err == nil {
		t.Fatal("ciphertext tampering accepted")
	}
	altered = append([]byte(nil), sealed...)
	altered[len(Magic)] ^= 0x10
	if _, err := Open(altered, first); err == nil {
		t.Fatal("nonce tampering accepted")
	}
	altered = append([]byte(nil), sealed...)
	altered[0] ^= 0x01
	if _, err := Open(altered, first); err == nil {
		t.Fatal("format tampering accepted")
	}
	if _, err := Seal(nil, first); err == nil {
		t.Fatal("empty backup encrypted")
	}
	if _, err := Seal([]byte(strings.Repeat("z", MaxPlaintext+1)), first); err == nil {
		t.Fatal("oversized backup encrypted")
	}
}
