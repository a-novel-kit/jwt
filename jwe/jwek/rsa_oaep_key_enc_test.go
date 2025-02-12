package jwek_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/a-novel-kit/jwt/jwa"
	"github.com/a-novel-kit/jwt/jwe/jwek"
	"github.com/a-novel-kit/jwt/jwk"
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

			cek, err := jwk.GenerateAES(jwk.A256GCM)
			require.NoError(t, err)

			recipientPrivateKey, recipientPublicKey, err := jwk.GenerateRSA(testCase.keyPreset)
			require.NoError(t, err)

			manager := jwek.NewRSAOAEPKeyEncManager(&jwek.RSAOAEPKeyEncManagerConfig{
				CEK:    cek.Key(),
				EncKey: recipientPublicKey.Key(),
			}, testCase.preset)

			header, err := manager.SetHeader(t.Context(), &jwa.JWH{})
			require.NoError(t, err)

			computedCEK, err := manager.ComputeCEK(t.Context(), header)
			require.NoError(t, err)
			require.Equal(t, cek.Key(), computedCEK)

			encryptedCEK, err := manager.EncryptCEK(t.Context(), header, computedCEK)
			require.NoError(t, err)
			require.NotNil(t, encryptedCEK)
			require.NotEqual(t, cek.Key(), encryptedCEK)

			t.Run("OK", func(t *testing.T) {
				t.Parallel()

				decoder := jwek.NewRSAOAEPKeyEncDecoder(
					&jwek.RSAOAEPKeyEncDecoderConfig{EncKey: recipientPrivateKey.Key()},
					testCase.preset,
				)

				decryptedCEK, err := decoder.ComputeCEK(t.Context(), header, encryptedCEK)
				require.NoError(t, err)
				require.Equal(t, cek.Key(), decryptedCEK)
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
				require.Error(t, err)
			})
		})
	}
}
