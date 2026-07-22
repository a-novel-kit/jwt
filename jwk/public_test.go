package jwk_test

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/a-novel-kit/jwt/v2/jwa"
	"github.com/a-novel-kit/jwt/v2/jwk"
)

// Covers every key type the package generates, since the private members differ
// by type and a type reading as public when it is not is the whole risk.

func members(t *testing.T, key *jwa.JWK) map[string]json.RawMessage {
	t.Helper()

	out := map[string]json.RawMessage{}
	if len(key.Payload) > 0 {
		require.NoError(t, json.Unmarshal(key.Payload, &out))
	}

	return out
}

func TestHasPrivateMaterial(t *testing.T) {
	t.Parallel()

	rsaPrivate, rsaPublic, err := jwk.GenerateRSA(jwk.RS256)
	require.NoError(t, err)

	ecPrivate, ecPublic, err := jwk.GenerateECDSA(jwk.ES256)
	require.NoError(t, err)

	edPrivate, edPublic, err := jwk.GenerateED25519()
	require.NoError(t, err)

	ecdhPrivate, ecdhPublic, err := jwk.GenerateECDH()
	require.NoError(t, err)

	hmacKey, err := jwk.GenerateHMAC(jwk.HS256)
	require.NoError(t, err)

	aesKey, err := jwk.GenerateAES(jwk.A256GCM)
	require.NoError(t, err)

	testCases := []struct {
		name string

		key *jwa.JWK

		expect bool
	}{
		{name: "RSA/Private", key: rsaPrivate.JWK, expect: true},
		{name: "RSA/Public", key: rsaPublic.JWK, expect: false},
		{name: "ECDSA/Private", key: ecPrivate.JWK, expect: true},
		{name: "ECDSA/Public", key: ecPublic.JWK, expect: false},
		{name: "ED25519/Private", key: edPrivate.JWK, expect: true},
		{name: "ED25519/Public", key: edPublic.JWK, expect: false},
		{name: "ECDH/Private", key: ecdhPrivate.JWK, expect: true},
		{name: "ECDH/Public", key: ecdhPublic.JWK, expect: false},
		// A symmetric key is its secret whatever its payload says.
		{name: "HMAC", key: hmacKey.JWK, expect: true},
		{name: "AES", key: aesKey.JWK, expect: true},
		{name: "Nil", key: nil, expect: false},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			got, err := jwk.HasPrivateMaterial(testCase.key)
			require.NoError(t, err)
			require.Equal(t, testCase.expect, got)
		})
	}
}

func TestPublicStripsPrivateMembers(t *testing.T) {
	t.Parallel()

	rsaPrivate, _, err := jwk.GenerateRSA(jwk.RS256)
	require.NoError(t, err)

	// RSA carries the widest private set, so it is the one that proves every
	// name is removed rather than just "d".
	private := members(t, rsaPrivate.JWK)
	for _, name := range []string{"d", "p", "q", "dp", "dq", "qi"} {
		require.Contains(t, private, name, "the generated key should carry %s to begin with", name)
	}

	public, err := jwk.Public(rsaPrivate.JWK)
	require.NoError(t, err)

	got := members(t, public)
	for _, name := range []string{"d", "p", "q", "dp", "dq", "qi", "oth"} {
		require.NotContains(t, got, name)
	}

	// The public half has to remain usable.
	require.Contains(t, got, "n")
	require.Contains(t, got, "e")

	require.Equal(t, rsaPrivate.KID, public.KID)
	require.Equal(t, rsaPrivate.KTY, public.KTY)

	hasPrivate, err := jwk.HasPrivateMaterial(public)
	require.NoError(t, err)
	require.False(t, hasPrivate)

	// The input is left alone, so a caller projecting a key it still signs with
	// does not disarm its own signer.
	require.Contains(t, members(t, rsaPrivate.JWK), "d")
}

func TestPublicRefusesASymmetricKey(t *testing.T) {
	t.Parallel()

	// There is no public half to return. Emptying the payload would produce a
	// key that looks publishable and verifies nothing.
	hmacKey, err := jwk.GenerateHMAC(jwk.HS256)
	require.NoError(t, err)

	_, err = jwk.Public(hmacKey.JWK)
	require.ErrorIs(t, err, jwk.ErrPrivateKeyMaterial)
}

func TestPublicOnAnAlreadyPublicKey(t *testing.T) {
	t.Parallel()

	// Idempotent, so a caller need not track whether it has already projected.
	_, ecPublic, err := jwk.GenerateECDSA(jwk.ES256)
	require.NoError(t, err)

	public, err := jwk.Public(ecPublic.JWK)
	require.NoError(t, err)
	require.JSONEq(t, string(ecPublic.Payload), string(public.Payload))
}
