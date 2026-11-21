// Package backup protects owner-private peer registry snapshots with
// authenticated encryption. It is separate from WireGuard tunnel key handling.
package backup

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
)

const Magic = "GCVPNBK1"
const MaxPlaintext = 2 << 20
const maxCiphertext = len(Magic) + 12 + MaxPlaintext + 16

// Seal encrypts validated metadata with a separate random 256-bit backup key.
func Seal(plain []byte, key [32]byte) ([]byte, error) {
	if len(plain) == 0 || len(plain) > MaxPlaintext {
		return nil, errors.New("invalid registry backup plaintext size")
	}
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return nil, err
	}
	sealed := make([]byte, 0, len(Magic)+len(nonce)+len(plain)+gcm.Overhead())
	sealed = append(sealed, []byte(Magic)...)
	sealed = append(sealed, nonce...)
	sealed = gcm.Seal(sealed, nonce, plain, []byte(Magic))
	return sealed, nil
}

// Open rejects wrong keys, tampering, format-version mismatches and oversized
// artifacts without emitting decrypted metadata or secrets in errors.
func Open(sealed []byte, key [32]byte) ([]byte, error) {
	if len(sealed) < len(Magic)+12+16 || len(sealed) > maxCiphertext ||
		!bytes.Equal(sealed[:len(Magic)], []byte(Magic)) {
		return nil, errors.New("invalid registry backup format or size")
	}
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := sealed[len(Magic) : len(Magic)+gcm.NonceSize()]
	ciphertext := sealed[len(Magic)+gcm.NonceSize():]
	plain, err := gcm.Open(nil, nonce, ciphertext, []byte(Magic))
	if err != nil {
		return nil, errors.New("backup authentication failed")
	}
	if len(plain) == 0 || len(plain) > MaxPlaintext {
		return nil, errors.New("invalid decrypted registry size")
	}
	return plain, nil
}
