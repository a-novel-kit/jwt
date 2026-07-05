package jwk_test

import (
	"crypto/ecdsa"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/a-novel-kit/jwt/v2/jwa"
	"github.com/a-novel-kit/jwt/v2/jwk"
	"github.com/a-novel-kit/jwt/v2/jwk/serializers"
)

func mustECDSA(t *testing.T, preset jwk.ECDSAPreset) (*jwk.Key[*ecdsa.PrivateKey], *jwk.Key[*ecdsa.PublicKey]) {
	t.Helper()

	private, public, err := jwk.GenerateECDSA(preset)
	require.NoError(t, err)

	return private, public
}

func TestGenerateECDSA(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name   string
		preset jwk.ECDSAPreset
	}{
		{
			name:   "ES256",
			preset: jwk.ES256,
		},
		{
			name:   "ES384",
			preset: jwk.ES384,
		},
		{
			name:   "ES512",
			preset: jwk.ES512,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			privateKey, publicKey, err := jwk.GenerateECDSA(testCase.preset)
			require.NoError(t, err)

			require.True(t, privateKey.MatchPreset(jwa.JWKCommon{
				KTY:    jwa.KTYEC,
				Use:    jwa.UseSig,
				KeyOps: jwa.KeyOps{jwa.KeyOpSign},
				Alg:    testCase.preset.Alg,
			}))
			require.NotEmpty(t, privateKey.KID)

			require.True(t, publicKey.MatchPreset(jwa.JWKCommon{
				KTY:    jwa.KTYEC,
				Use:    jwa.UseSig,
				KeyOps: jwa.KeyOps{jwa.KeyOpVerify},
				Alg:    testCase.preset.Alg,
			}))
			require.Equal(t, privateKey.KID, publicKey.KID)

			t.Run("ParsePrivate", func(t *testing.T) {
				t.Parallel()

				var ecPayload serializers.ECPayload

				require.NoError(t, json.Unmarshal(privateKey.Payload, &ecPayload))

				decodedPrivate, decodedPublic, err := serializers.DecodeEC(&ecPayload)
				require.NoError(t, err)

				require.NotNil(t, decodedPrivate)
				require.NotNil(t, decodedPublic)

				require.True(t, privateKey.Key().Equal(decodedPrivate))
				require.True(t, publicKey.Key().Equal(decodedPublic))
			})

			t.Run("ParsePublic", func(t *testing.T) {
				t.Parallel()

				var ecPayload serializers.ECPayload

				require.NoError(t, json.Unmarshal(publicKey.Payload, &ecPayload))

				decodedPrivate, decodedPublic, err := serializers.DecodeEC(&ecPayload)
				require.NoError(t, err)

				require.Nil(t, decodedPrivate)
				require.NotNil(t, decodedPublic)

				require.True(t, publicKey.Key().Equal(decodedPublic))
			})
		})
	}
}

func TestConsumeECDSA(t *testing.T) {
	t.Parallel()

	es256Private, es256Public := mustECDSA(t, jwk.ES256)
	es384Private, es384Public := mustECDSA(t, jwk.ES384)
	es512Private, es512Public := mustECDSA(t, jwk.ES512)

	testCases := []struct {
		name      string
		preset    jwk.ECDSAPreset
		private   *jwk.Key[*ecdsa.PrivateKey]
		public    *jwk.Key[*ecdsa.PublicKey]
		expectErr error
	}{
		{
			name:    "ES256",
			preset:  jwk.ES256,
			private: es256Private,
			public:  es256Public,
		},
		{
			name:    "ES384",
			preset:  jwk.ES384,
			private: es384Private,
			public:  es384Public,
		},
		{
			name:    "ES512",
			preset:  jwk.ES512,
			private: es512Private,
			public:  es512Public,
		},

		{
			name:      "Mismatch",
			preset:    jwk.ES256,
			private:   newBullshitKey[*ecdsa.PrivateKey](t, "kid-1"),
			public:    newBullshitKey[*ecdsa.PublicKey](t, "kid-2"),
			expectErr: jwk.ErrJWKMismatch,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			t.Run("Private", func(t *testing.T) {
				t.Parallel()

				privateKey, publicKey, err := jwk.ConsumeECDSA(testCase.private.JWK, testCase.preset)
				require.ErrorIs(t, err, testCase.expectErr)

				if err == nil {
					require.True(t, publicKey.Key().Equal(testCase.public.Key()))
					require.True(t, privateKey.Key().Equal(testCase.private.Key()))
				}
			})

			t.Run("Public", func(t *testing.T) {
				t.Parallel()

				privateKey, publicKey, err := jwk.ConsumeECDSA(testCase.public.JWK, testCase.preset)
				require.ErrorIs(t, err, testCase.expectErr)

				if err == nil {
					require.True(t, publicKey.Key().Equal(testCase.public.Key()))
					require.Nil(t, privateKey)
				}
			})
		})
	}
}
