package jwek_test

import (
	"bytes"
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/a-novel-kit/jwt/jwa"
	"github.com/a-novel-kit/jwt/jwe/jwek"
	"github.com/a-novel-kit/jwt/jwk"
)

func TestAESGCMKW(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name string

		keyPreset jwk.AESPreset
		preset    jwek.AESGCMKWPreset
	}{
		{
			name:      "A128GCMKW",
			keyPreset: jwk.A128GCMKW,
			preset:    jwek.A128GCMKW,
		},
		{
			name:      "A192GCMKW",
			keyPreset: jwk.A192GCMKW,
			preset:    jwek.A192GCMKW,
		},
		{
			name:      "A256GCMKW",
			keyPreset: jwk.A256GCMKW,
			preset:    jwek.A256GCMKW,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			wrapKey, err := jwk.GenerateAES(testCase.keyPreset)
			require.NoError(t, err)

			cek, err := jwk.GenerateAES(jwk.A128GCM)
			require.NoError(t, err)

			manager := jwek.NewAESGCMKWManager(&jwek.AESGCMKWManagerConfig{
				CEK:     cek.Key(),
				WrapKey: wrapKey.Key(),
			}, testCase.preset)

			header, err := manager.SetHeader(context.Background(), &jwa.JWH{})
			require.NoError(t, err)

			computedCEK, err := manager.ComputeCEK(context.Background(), header)
			require.NoError(t, err)
			require.Equal(t, cek.Key(), computedCEK)

			encryptedCEK, err := manager.EncryptCEK(context.Background(), header, cek.Key())
			require.NoError(t, err)
			require.NotEmpty(t, encryptedCEK)
			require.NotEqual(t, cek.Key(), encryptedCEK)

			t.Run("OK", func(t *testing.T) {
				t.Parallel()

				decoder := jwek.NewAESGCMKWDecoder(
					&jwek.AESGCMKWDecoderConfig{WrapKey: wrapKey.Key()},
					testCase.preset,
				)

				decodedCEK, err := decoder.ComputeCEK(context.Background(), header, encryptedCEK)
				require.NoError(t, err)
				require.Equal(t, cek.Key(), decodedCEK)
			})

			t.Run("WrongKEK", func(t *testing.T) {
				t.Parallel()

				decoder := jwek.NewAESGCMKWDecoder(
					&jwek.AESGCMKWDecoderConfig{WrapKey: bytes.Repeat([]byte{0}, testCase.preset.KeyLen)},
					testCase.preset,
				)

				_, err := decoder.ComputeCEK(context.Background(), header, encryptedCEK)
				require.Error(t, err)
			})
		})
	}
}
