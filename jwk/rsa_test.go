package jwk_test

import (
	"crypto/rsa"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/a-novel-kit/jwt/v2/jwa"
	"github.com/a-novel-kit/jwt/v2/jwk"
	"github.com/a-novel-kit/jwt/v2/jwk/serializers"
)

func mustRSA(t *testing.T, preset jwk.RSAPreset) (*jwk.Key[*rsa.PrivateKey], *jwk.Key[*rsa.PublicKey]) {
	t.Helper()

	private, public, err := jwk.GenerateRSA(preset)
	require.NoError(t, err)

	return private, public
}

func TestGenerateRSA(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name   string
		preset jwk.RSAPreset
	}{
		{
			name:   "RS256",
			preset: jwk.RS256,
		},
		{
			name:   "RS384",
			preset: jwk.RS384,
		},
		{
			name:   "RS512",
			preset: jwk.RS512,
		},

		{
			name:   "PS256",
			preset: jwk.PS256,
		},
		{
			name:   "PS384",
			preset: jwk.PS384,
		},
		{
			name:   "PS512",
			preset: jwk.PS512,
		},

		{
			name:   "RSAOAEP",
			preset: jwk.RSAOAEP,
		},
		{
			name:   "RSAOAEP256",
			preset: jwk.RSAOAEP256,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			privateKey, publicKey, err := jwk.GenerateRSA(testCase.preset)
			require.NoError(t, err)

			require.True(t, privateKey.MatchPreset(jwa.JWKCommon{
				KTY:    jwa.KTYRSA,
				Use:    testCase.preset.Use,
				KeyOps: testCase.preset.PrivateKeyOps,
				Alg:    testCase.preset.Alg,
			}))
			require.NotEmpty(t, privateKey.KID)

			require.True(t, publicKey.MatchPreset(jwa.JWKCommon{
				KTY:    jwa.KTYRSA,
				Use:    testCase.preset.Use,
				KeyOps: testCase.preset.PublicKeyOps,
				Alg:    testCase.preset.Alg,
			}))
			require.Equal(t, privateKey.KID, publicKey.KID)

			t.Run("ParsePrivate", func(t *testing.T) {
				t.Parallel()

				var rsaPayload serializers.RSAPayload

				require.NoError(t, json.Unmarshal(privateKey.Payload, &rsaPayload))

				decodedPrivate, decodedPublic, err := serializers.DecodeRSA(&rsaPayload)
				require.NoError(t, err)

				require.NotNil(t, decodedPrivate)
				require.NotNil(t, decodedPublic)

				require.True(t, privateKey.Key().Equal(decodedPrivate))
				require.True(t, publicKey.Key().Equal(decodedPublic))
			})

			t.Run("ParsePublic", func(t *testing.T) {
				t.Parallel()

				var rsaPayload serializers.RSAPayload

				require.NoError(t, json.Unmarshal(publicKey.Payload, &rsaPayload))

				decodedPrivate, decodedPublic, err := serializers.DecodeRSA(&rsaPayload)
				require.NoError(t, err)

				require.Nil(t, decodedPrivate)
				require.NotNil(t, decodedPublic)

				require.True(t, publicKey.Key().Equal(decodedPublic))
			})
		})
	}
}

func TestConsumeRSA(t *testing.T) {
	t.Parallel()

	rs256Private, rs256Public := mustRSA(t, jwk.RS256)
	rs384Private, rs384Public := mustRSA(t, jwk.RS384)
	rs512Private, rs512Public := mustRSA(t, jwk.RS512)
	ps256Private, ps256Public := mustRSA(t, jwk.PS256)
	ps384Private, ps384Public := mustRSA(t, jwk.PS384)
	ps512Private, ps512Public := mustRSA(t, jwk.PS512)

	rsaOAEPPrivate, rsaOAEPPublic := mustRSA(t, jwk.RSAOAEP)
	rsaOAEP256Private, rsaOAEP256Public := mustRSA(t, jwk.RSAOAEP256)

	testCases := []struct {
		name      string
		preset    jwk.RSAPreset
		private   *jwk.Key[*rsa.PrivateKey]
		public    *jwk.Key[*rsa.PublicKey]
		expectErr error
	}{
		{
			name:    "RS256",
			preset:  jwk.RS256,
			private: rs256Private,
			public:  rs256Public,
		},
		{
			name:    "RS384",
			preset:  jwk.RS384,
			private: rs384Private,
			public:  rs384Public,
		},
		{
			name:    "RS512",
			preset:  jwk.RS512,
			private: rs512Private,
			public:  rs512Public,
		},
		{
			name:    "PS256",
			preset:  jwk.PS256,
			private: ps256Private,
			public:  ps256Public,
		},
		{
			name:    "PS384",
			preset:  jwk.PS384,
			private: ps384Private,
			public:  ps384Public,
		},
		{
			name:    "PS512",
			preset:  jwk.PS512,
			private: ps512Private,
			public:  ps512Public,
		},
		{
			name:    "RSAOAEP",
			preset:  jwk.RSAOAEP,
			private: rsaOAEPPrivate,
			public:  rsaOAEPPublic,
		},
		{
			name:    "RSAOAEP256",
			preset:  jwk.RSAOAEP256,
			private: rsaOAEP256Private,
			public:  rsaOAEP256Public,
		},

		{
			name:      "Mismatch",
			preset:    jwk.RS256,
			private:   newBullshitKey[*rsa.PrivateKey](t, "kid-1"),
			public:    newBullshitKey[*rsa.PublicKey](t, "kid-2"),
			expectErr: jwk.ErrJWKMismatch,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			t.Run("Private", func(t *testing.T) {
				t.Parallel()

				privateKey, publicKey, err := jwk.ConsumeRSA(testCase.private.JWK, testCase.preset)
				require.ErrorIs(t, err, testCase.expectErr)

				if err == nil {
					require.True(t, publicKey.Key().Equal(testCase.public.Key()))
					require.True(t, privateKey.Key().Equal(testCase.private.Key()))
				}
			})

			t.Run("Public", func(t *testing.T) {
				t.Parallel()

				privateKey, publicKey, err := jwk.ConsumeRSA(testCase.public.JWK, testCase.preset)
				require.ErrorIs(t, err, testCase.expectErr)

				if err == nil {
					require.True(t, publicKey.Key().Equal(testCase.public.Key()))
					require.Nil(t, privateKey)
				}
			})
		})
	}
}
