package jwek_test

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"testing"
)

// mustDecodeBase64 decodes a base64url segment of a test vector.
func mustDecodeBase64(t *testing.T, segment string) []byte {
	t.Helper()

	decoded, err := base64.RawURLEncoding.DecodeString(segment)
	if err != nil {
		panic(err)
	}

	return decoded
}

// mustGenerateECDH returns a fresh private key on curve.
func mustGenerateECDH(t *testing.T, curve ecdh.Curve) *ecdh.PrivateKey {
	t.Helper()

	key, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}

	return key
}

// randomKey returns size random bytes, for a symmetric key.
func randomKey(size int) []byte {
	key := make([]byte, size)
	_, _ = rand.Read(key) // never fails: it crashes the program instead

	return key
}
