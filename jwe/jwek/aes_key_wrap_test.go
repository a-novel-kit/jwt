package jwek_test

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/a-novel-kit/jwt/jwa"
	"github.com/a-novel-kit/jwt/jwe/jwek"
	"github.com/a-novel-kit/jwt/jwk"
)

func TestAESKW(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name string

		keyPreset jwk.AESPreset
		preset    jwek.AESKWPreset
	}{
		{
			name:      "A128KW",
			keyPreset: jwk.A128KW,
			preset:    jwek.A128KW,
		},
		{
			name:      "A192KW",
			keyPreset: jwk.A192KW,
			preset:    jwek.A192KW,
		},
		{
			name:      "A256KW",
			keyPreset: jwk.A256KW,
			preset:    jwek.A256KW,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			wrapKey, err := jwk.GenerateAES(testCase.keyPreset)
			require.NoError(t, err)

			cek, err := jwk.GenerateAES(jwk.A128GCM)
			require.NoError(t, err)

			manager := jwek.NewAESKWManager(&jwek.AESKWManagerConfig{
				CEK:     cek.Key(),
				WrapKey: wrapKey.Key(),
			}, testCase.preset)

			header, err := manager.SetHeader(t.Context(), &jwa.JWH{})
			require.NoError(t, err)

			computedCEK, err := manager.ComputeCEK(t.Context(), header)
			require.NoError(t, err)
			require.Equal(t, cek.Key(), computedCEK)

			encryptedCEK, err := manager.EncryptCEK(t.Context(), header, cek.Key())
			require.NoError(t, err)
			require.NotEmpty(t, encryptedCEK)
			require.NotEqual(t, cek.Key(), encryptedCEK)

			t.Run("OK", func(t *testing.T) {
				t.Parallel()

				decoder := jwek.NewAESKWDecoder(
					&jwek.AESKWDecoderConfig{WrapKey: wrapKey.Key()},
					testCase.preset,
				)

				decodedCEK, err := decoder.ComputeCEK(t.Context(), header, encryptedCEK)
				require.NoError(t, err)
				require.Equal(t, cek.Key(), decodedCEK)
			})

			t.Run("WrongKEK", func(t *testing.T) {
				t.Parallel()

				decoder := jwek.NewAESKWDecoder(
					&jwek.AESKWDecoderConfig{WrapKey: bytes.Repeat([]byte{0}, testCase.preset.KeyLen)},
					testCase.preset,
				)

				_, err := decoder.ComputeCEK(t.Context(), header, encryptedCEK)
				require.Error(t, err)
			})
		})
	}
}
