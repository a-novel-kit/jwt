package jws_test

import (
	"crypto/rsa"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/a-novel-kit/jwt"
	"github.com/a-novel-kit/jwt/jwa"
	"github.com/a-novel-kit/jwt/jws"
)

// smallRSAKey is a bogus RSA key with a sub-2048-bit modulus. It is enough to exercise the key-size
// floor — which only reads the modulus bit length before any crypto — without a slow weak-key
// generation.
func smallRSAKey() *rsa.PrivateKey {
	return &rsa.PrivateKey{PublicKey: rsa.PublicKey{N: big.NewInt(12345), E: 65537}}
}

func TestHMACWeakKey(t *testing.T) {
	t.Parallel()

	shortKey := []byte("too-short") // 9 bytes, under the 32-byte HS256 floor.

	t.Run("Signer", func(t *testing.T) {
		t.Parallel()

		_, err := jws.NewHMACSigner(shortKey, jws.HS256).Header(t.Context(), &jwa.JWH{})
		require.ErrorIs(t, err, jwt.ErrInvalidSecretKey)
	})

	t.Run("Verifier", func(t *testing.T) {
		t.Parallel()

		header := &jwa.JWH{JWHCommon: jwa.JWHCommon{Alg: jwa.HS256}}

		_, err := jws.NewHMACVerifier(shortKey, jws.HS256).Transform(t.Context(), header, "a.b.c")
		require.ErrorIs(t, err, jwt.ErrInvalidSecretKey)
	})
}

func TestRSAWeakKey(t *testing.T) {
	t.Parallel()

	key := smallRSAKey()

	t.Run("Signer", func(t *testing.T) {
		t.Parallel()

		_, err := jws.NewRSASigner(key, jws.RS256).Header(t.Context(), &jwa.JWH{})
		require.ErrorIs(t, err, jwt.ErrInvalidSecretKey)
	})

	t.Run("Verifier", func(t *testing.T) {
		t.Parallel()

		header := &jwa.JWH{JWHCommon: jwa.JWHCommon{Alg: jwa.RS256}}

		_, err := jws.NewRSAVerifier(&key.PublicKey, jws.RS256).Transform(t.Context(), header, "a.b.c")
		require.ErrorIs(t, err, jwt.ErrInvalidSecretKey)
	})
}

func TestRSAPSSWeakKey(t *testing.T) {
	t.Parallel()

	key := smallRSAKey()

	t.Run("Signer", func(t *testing.T) {
		t.Parallel()

		_, err := jws.NewRSAPSSSigner(key, jws.PS256).Header(t.Context(), &jwa.JWH{})
		require.ErrorIs(t, err, jwt.ErrInvalidSecretKey)
	})

	t.Run("Verifier", func(t *testing.T) {
		t.Parallel()

		header := &jwa.JWH{JWHCommon: jwa.JWHCommon{Alg: jwa.PS256}}

		_, err := jws.NewRSAPSSVerifier(&key.PublicKey, jws.PS256).Transform(t.Context(), header, "a.b.c")
		require.ErrorIs(t, err, jwt.ErrInvalidSecretKey)
	})
}

func TestRSANilKey(t *testing.T) {
	t.Parallel()

	// The size floor must fail closed on a nil key or nil modulus, not panic.
	t.Run("SignerNil", func(t *testing.T) {
		t.Parallel()

		_, err := jws.NewRSASigner(nil, jws.RS256).Header(t.Context(), &jwa.JWH{})
		require.ErrorIs(t, err, jwt.ErrInvalidSecretKey)
	})

	t.Run("VerifierNilModulus", func(t *testing.T) {
		t.Parallel()

		header := &jwa.JWH{JWHCommon: jwa.JWHCommon{Alg: jwa.RS256}}

		_, err := jws.NewRSAVerifier(&rsa.PublicKey{}, jws.RS256).Transform(t.Context(), header, "a.b.c")
		require.ErrorIs(t, err, jwt.ErrInvalidSecretKey)
	})
}
