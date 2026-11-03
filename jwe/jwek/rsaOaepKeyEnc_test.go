package jwek_test

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/a-novel-kit/jwt/v2"
	"github.com/a-novel-kit/jwt/v2/jwa"
	"github.com/a-novel-kit/jwt/v2/jwe/jwek"
	"github.com/a-novel-kit/jwt/v2/jwk"
)

func TestRSAOAEPKeyEnc(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name string

		keyPreset jwk.RSAPreset
		preset    jwek.RSAOAEPKeyEncPreset
	}{
		{
			name:      "RSAOAEPKeyEnc",
			keyPreset: jwk.RSAOAEP,
			preset:    jwek.RSAOAEP,
		},
		{
			name:      "RSAOAEP256KeyEnc",
			keyPreset: jwk.RSAOAEP256,
			preset:    jwek.RSAOAEP256,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			recipientPrivateKey, recipientPublicKey, err := jwk.GenerateRSA(testCase.keyPreset)
			require.NoError(t, err)

			manager := jwek.NewRSAOAEPKeyEncManager(&jwek.RSAOAEPKeyEncManagerConfig{
				EncKey: recipientPublicKey.Key(),
			}, testCase.preset)

			header, err := manager.SetHeader(t.Context(), &jwa.JWH{JWHCommon: jwa.JWHCommon{Enc: jwa.A256GCM}})
			require.NoError(t, err)

			computedCEK, err := manager.ComputeCEK(t.Context(), header)
			require.NoError(t, err)
			require.Len(t, computedCEK, 32)

			encryptedCEK, err := manager.EncryptCEK(t.Context(), header, computedCEK)
			require.NoError(t, err)
			require.NotNil(t, encryptedCEK)
			require.NotEqual(t, computedCEK, encryptedCEK)

			t.Run("OK", func(t *testing.T) {
				t.Parallel()

				decoder := jwek.NewRSAOAEPKeyEncDecoder(
					&jwek.RSAOAEPKeyEncDecoderConfig{EncKey: recipientPrivateKey.Key()},
					testCase.preset,
				)

				decryptedCEK, err := decoder.ComputeCEK(t.Context(), header, encryptedCEK)
				require.NoError(t, err)
				require.Equal(t, computedCEK, decryptedCEK)
			})

			t.Run("WrongRecipientKey", func(t *testing.T) {
				t.Parallel()

				fakeRecipientPrivateKey, _, err := jwk.GenerateRSA(testCase.keyPreset)
				require.NoError(t, err)

				decoder := jwek.NewRSAOAEPKeyEncDecoder(
					&jwek.RSAOAEPKeyEncDecoderConfig{EncKey: fakeRecipientPrivateKey.Key()},
					testCase.preset,
				)

				_, err = decoder.ComputeCEK(t.Context(), header, encryptedCEK)
				require.ErrorIs(t, err, jwt.ErrTokenRejected)
			})
		})
	}
}

func TestRSAOAEPKeyEncShortKey(t *testing.T) {
	t.Parallel()

	// RFC 7518 §4.3: RSA-OAEP needs a key of 2048 bits or more, at both ends.
	shortKey, err := rsa.GenerateKey(rand.Reader, 1024)
	require.NoError(t, err)

	header := &jwa.JWH{JWHCommon: jwa.JWHCommon{Alg: jwa.RSAOAEP256, Enc: jwa.A256GCM}}

	manager := jwek.NewRSAOAEPKeyEncManager(&jwek.RSAOAEPKeyEncManagerConfig{EncKey: &shortKey.PublicKey}, jwek.RSAOAEP256)

	_, err = manager.EncryptCEK(t.Context(), header, make([]byte, 32))
	require.ErrorIs(t, err, jwt.ErrInvalidSecretKey)

	decoder := jwek.NewRSAOAEPKeyEncDecoder(&jwek.RSAOAEPKeyEncDecoderConfig{EncKey: shortKey}, jwek.RSAOAEP256)

	_, err = decoder.ComputeCEK(t.Context(), header, []byte("encrypted"))
	require.ErrorIs(t, err, jwt.ErrInvalidSecretKey)
}
