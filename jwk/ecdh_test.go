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

func mustECDH(t *testing.T) (*jwk.Key[*ecdh.PrivateKey], *jwk.Key[*ecdh.PublicKey]) {
	t.Helper()

	private, public, err := jwk.GenerateECDH()
	require.NoError(t, err)

	return private, public
}

func TestGenerateECDH(t *testing.T) {
	t.Parallel()

	privateKey, publicKey, err := jwk.GenerateECDH()
	require.NoError(t, err)

	require.True(t, privateKey.MatchPreset(jwa.JWKCommon{
		KTY:    jwa.KTYOKP,
		Use:    jwa.UseEnc,
		KeyOps: jwa.KeyOps{jwa.KeyOpDeriveKey},
		Alg:    jwa.ECDHES,
	}))
	require.NotEmpty(t, privateKey.KID)

	require.True(t, publicKey.MatchPreset(jwa.JWKCommon{
		KTY:    jwa.KTYOKP,
		Use:    jwa.UseEnc,
		KeyOps: jwa.KeyOps{jwa.KeyOpDeriveKey},
		Alg:    jwa.ECDHES,
	}))
	require.Equal(t, privateKey.KID, publicKey.KID)

	t.Run("ParsePrivate", func(t *testing.T) {
		t.Parallel()

		var ecdhPayload serializers.ECDHPayload

		require.NoError(t, json.Unmarshal(privateKey.Payload, &ecdhPayload))

		decodedPrivate, decodedPublic, err := serializers.DecodeECDH(&ecdhPayload)
		require.NoError(t, err)

		require.NotNil(t, decodedPrivate)
		require.NotNil(t, decodedPublic)

		require.True(t, privateKey.Key().Equal(decodedPrivate))
		require.True(t, publicKey.Key().Equal(decodedPublic))
	})

	t.Run("ParsePublic", func(t *testing.T) {
		t.Parallel()

		var ecdhPayload serializers.ECDHPayload

		require.NoError(t, json.Unmarshal(publicKey.Payload, &ecdhPayload))

		decodedPrivate, decodedPublic, err := serializers.DecodeECDH(&ecdhPayload)
		require.NoError(t, err)

		require.Nil(t, decodedPrivate)
		require.NotNil(t, decodedPublic)

		require.True(t, publicKey.Key().Equal(decodedPublic))
	})
}

func TestConsumeECDH(t *testing.T) {
	t.Parallel()

	private, public := mustECDH(t)

	testCases := []struct {
		name      string
		private   *jwk.Key[*ecdh.PrivateKey]
		public    *jwk.Key[*ecdh.PublicKey]
		expectErr error
	}{
		{
			name:    "Success",
			private: private,
			public:  public,
		},
		{
			name:      "Mismatch",
			private:   newBullshitKey[*ecdh.PrivateKey](t, "kid-1"),
			public:    newBullshitKey[*ecdh.PublicKey](t, "kid-2"),
			expectErr: jwk.ErrJWKMismatch,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			t.Run("Private", func(t *testing.T) {
				t.Parallel()

				privateKey, publicKey, err := jwk.ConsumeECDH(testCase.private.JWK)
				require.ErrorIs(t, err, testCase.expectErr)

				if err == nil {
					require.True(t, publicKey.Key().Equal(public.Key()))
					require.True(t, privateKey.Key().Equal(private.Key()))
				}
			})

			t.Run("Public", func(t *testing.T) {
				t.Parallel()

				privateKey, publicKey, err := jwk.ConsumeECDH(testCase.public.JWK)
				require.ErrorIs(t, err, testCase.expectErr)

				if err == nil {
					require.True(t, publicKey.Key().Equal(public.Key()))
					require.Nil(t, privateKey)
				}
			})
		})
	}
}
