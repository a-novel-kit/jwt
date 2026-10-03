package jwk_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/a-novel-kit/jwt/v2/jwa"
	"github.com/a-novel-kit/jwt/v2/jwk"
	"github.com/a-novel-kit/jwt/v2/jwk/serializers"
)

func TestGenerateMLDSA(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name string

		preset jwk.MLDSAPreset
	}{
		{name: "MLDSA44", preset: jwk.MLDSA44},
		{name: "MLDSA65", preset: jwk.MLDSA65},
		{name: "MLDSA87", preset: jwk.MLDSA87},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			privateKey, publicKey, err := jwk.GenerateMLDSA(testCase.preset)
			require.NoError(t, err)

			require.True(t, privateKey.MatchPreset(jwa.JWKCommon{
				KTY:    jwa.KTYAKP,
				Use:    jwa.UseSig,
				KeyOps: jwa.KeyOps{jwa.KeyOpSign},
				Alg:    testCase.preset.Alg,
			}))
			require.True(t, publicKey.MatchPreset(jwa.JWKCommon{
				KTY:    jwa.KTYAKP,
				Use:    jwa.UseSig,
				KeyOps: jwa.KeyOps{jwa.KeyOpVerify},
				Alg:    testCase.preset.Alg,
			}))
			require.NotEmpty(t, privateKey.KID)
			require.Equal(t, privateKey.KID, publicKey.KID)
			require.Equal(t, testCase.preset.Params, publicKey.Key().Parameters())
		})
	}
}

func TestConsumeMLDSA(t *testing.T) {
	t.Parallel()

	private, public, err := jwk.GenerateMLDSA(jwk.MLDSA65)
	require.NoError(t, err)

	_, edPublic := mustED25519(t)

	// A key relabeled with another parameter set's algorithm cannot decode under it.
	relabeled := *public.JWK
	relabeled.Alg = jwa.MLDSA44

	testCases := []struct {
		name string

		key *jwa.JWK

		expectPrivate bool
		expectErr     error
	}{
		{name: "Success/Private", key: private.JWK, expectPrivate: true},
		{name: "Success/Public", key: public.JWK},
		{name: "Error/Mismatch", key: newBullshitKey[any](t, "kid").JWK, expectErr: jwk.ErrJWKMismatch},
		{name: "Error/OtherFamily", key: edPublic.JWK, expectErr: jwk.ErrJWKMismatch},
		{name: "Error/WrongParameterSet", key: &relabeled, expectErr: serializers.ErrInvalidMLDSAKey},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			privateKey, publicKey, err := jwk.ConsumeMLDSA(testCase.key)
			require.ErrorIs(t, err, testCase.expectErr)

			if err == nil {
				require.True(t, publicKey.Key().Equal(public.Key()))
				require.Equal(t, testCase.expectPrivate, privateKey != nil)
			}
		})
	}
}
