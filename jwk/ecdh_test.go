package jwk_test

import (
	"crypto/ecdh"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/a-novel-kit/jwt/v2/jwa"
	"github.com/a-novel-kit/jwt/v2/jwk"
	"github.com/a-novel-kit/jwt/v2/jwk/serializers"
)

func TestGenerateECDHKey(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name string

		preset jwk.ECDHPreset
		kty    jwa.KTY
	}{
		{name: "X25519", preset: jwk.ECDHESX25519, kty: jwa.KTYOKP},
		{name: "P256", preset: jwk.ECDHESP256, kty: jwa.KTYEC},
		{name: "P384", preset: jwk.ECDHESP384, kty: jwa.KTYEC},
		{name: "P521", preset: jwk.ECDHESP521, kty: jwa.KTYEC},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			privateKey, publicKey, err := jwk.GenerateECDHKey(testCase.preset)
			require.NoError(t, err)

			expectHeader := jwa.JWKCommon{
				KTY:    testCase.kty,
				Use:    jwa.UseEnc,
				KeyOps: jwa.KeyOps{jwa.KeyOpDeriveKey},
				Alg:    jwa.ECDHES,
			}

			require.True(t, privateKey.MatchPreset(expectHeader))
			require.True(t, publicKey.MatchPreset(expectHeader))
			require.NotEmpty(t, privateKey.KID)
			require.Equal(t, privateKey.KID, publicKey.KID)
			require.Equal(t, testCase.preset.Curve, publicKey.Key().Curve())

			var privatePayload, publicPayload serializers.ECDHPayload

			require.NoError(t, json.Unmarshal(privateKey.Payload, &privatePayload))
			require.NoError(t, json.Unmarshal(publicKey.Payload, &publicPayload))
			require.NotEmpty(t, privatePayload.D)
			require.Empty(t, publicPayload.D)
		})
	}
}

func TestConsumeECDHKey(t *testing.T) {
	t.Parallel()

	private, public, err := jwk.GenerateECDHKey(jwk.ECDHESP256)
	require.NoError(t, err)

	testCases := []struct {
		name string

		key    *jwa.JWK
		preset jwk.ECDHPreset

		expectPrivate bool
		expectErr     error
	}{
		{name: "Success/Private", key: private.JWK, preset: jwk.ECDHESP256, expectPrivate: true},
		{name: "Success/Public", key: public.JWK, preset: jwk.ECDHESP256},
		// The preset's curve is checked against the payload, which MatchPreset cannot see.
		{name: "Error/OtherCurve", key: public.JWK, preset: jwk.ECDHESP384, expectErr: jwk.ErrJWKMismatch},
		{name: "Error/OtherKeyType", key: public.JWK, preset: jwk.ECDHESX25519, expectErr: jwk.ErrJWKMismatch},
		{
			name:      "Error/Mismatch",
			key:       newBullshitKey[*ecdh.PublicKey](t, "kid").JWK,
			preset:    jwk.ECDHESP256,
			expectErr: jwk.ErrJWKMismatch,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			privateKey, publicKey, err := jwk.ConsumeECDHKey(testCase.key, testCase.preset)
			require.ErrorIs(t, err, testCase.expectErr)

			if err == nil {
				require.True(t, publicKey.Key().Equal(public.Key()))
				require.Equal(t, testCase.expectPrivate, privateKey != nil)
			}
		})
	}
}

func TestConsumeECDH(t *testing.T) {
	t.Parallel()

	// The deprecated pair keeps its X25519 ECDH-ES behavior.
	private, public, err := jwk.GenerateECDH()
	require.NoError(t, err)
	require.Equal(t, ecdh.X25519(), public.Key().Curve())

	privateKey, publicKey, err := jwk.ConsumeECDH(private.JWK)
	require.NoError(t, err)
	require.True(t, privateKey.Key().Equal(private.Key()))
	require.True(t, publicKey.Key().Equal(public.Key()))
}
