package jwk_test

import (
	"crypto/ed25519"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/a-novel-kit/jwt/v2/jwa"
	"github.com/a-novel-kit/jwt/v2/jwk"
	"github.com/a-novel-kit/jwt/v2/jwk/serializers"
)

func mustED25519(t *testing.T) (*jwk.Key[ed25519.PrivateKey], *jwk.Key[ed25519.PublicKey]) {
	t.Helper()

	private, public, err := jwk.GenerateED25519()
	require.NoError(t, err)

	return private, public
}

func TestGenerateED25519(t *testing.T) {
	t.Parallel()

	privateKey, publicKey, err := jwk.GenerateED25519()
	require.NoError(t, err)

	require.True(t, privateKey.MatchPreset(jwa.JWKCommon{
		KTY:    jwa.KTYOKP,
		Use:    jwa.UseSig,
		KeyOps: jwa.KeyOps{jwa.KeyOpSign},
		Alg:    jwa.EdDSA,
	}))
	require.NotEmpty(t, privateKey.KID)

	require.True(t, publicKey.MatchPreset(jwa.JWKCommon{
		KTY:    jwa.KTYOKP,
		Use:    jwa.UseSig,
		KeyOps: jwa.KeyOps{jwa.KeyOpVerify},
		Alg:    jwa.EdDSA,
	}))
	require.Equal(t, privateKey.KID, publicKey.KID)

	t.Run("ParsePrivate", func(t *testing.T) {
		t.Parallel()

		var edPayload serializers.EDPayload

		require.NoError(t, json.Unmarshal(privateKey.Payload, &edPayload))

		decodedPrivate, decodedPublic, err := serializers.DecodeED(&edPayload)
		require.NoError(t, err)

		require.NotNil(t, decodedPrivate)
		require.NotNil(t, decodedPublic)

		require.True(t, privateKey.Key().Equal(decodedPrivate))
		require.True(t, publicKey.Key().Equal(decodedPublic))
	})

	t.Run("ParsePublic", func(t *testing.T) {
		t.Parallel()

		var edPayload serializers.EDPayload

		require.NoError(t, json.Unmarshal(publicKey.Payload, &edPayload))

		decodedPrivate, decodedPublic, err := serializers.DecodeED(&edPayload)
		require.NoError(t, err)

		require.Nil(t, decodedPrivate)
		require.NotNil(t, decodedPublic)

		require.True(t, publicKey.Key().Equal(decodedPublic))
	})
}

func TestConsumeED25519(t *testing.T) {
	t.Parallel()

	private, public := mustED25519(t)

	testCases := []struct {
		name      string
		private   *jwk.Key[ed25519.PrivateKey]
		public    *jwk.Key[ed25519.PublicKey]
		expectErr error
	}{
		{
			name:    "Success",
			private: private,
			public:  public,
		},
		{
			name:      "Mismatch",
			private:   newBullshitKey[ed25519.PrivateKey](t, "kid-1"),
			public:    newBullshitKey[ed25519.PublicKey](t, "kid-2"),
			expectErr: jwk.ErrJWKMismatch,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			t.Run("Private", func(t *testing.T) {
				t.Parallel()

				privateKey, publicKey, err := jwk.ConsumeED25519(testCase.private.JWK)
				require.ErrorIs(t, err, testCase.expectErr)

				if err == nil {
					require.True(t, publicKey.Key().Equal(public.Key()))
					require.True(t, privateKey.Key().Equal(private.Key()))
				}
			})

			t.Run("Public", func(t *testing.T) {
				t.Parallel()

				privateKey, publicKey, err := jwk.ConsumeED25519(testCase.public.JWK)
				require.ErrorIs(t, err, testCase.expectErr)

				if err == nil {
					require.True(t, publicKey.Key().Equal(public.Key()))
					require.Nil(t, privateKey)
				}
			})
		})
	}
}
