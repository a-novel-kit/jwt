package jwek_test

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/a-novel-kit/jwt/v2/jwa"
	"github.com/a-novel-kit/jwt/v2/jwe/jwek"
	"github.com/a-novel-kit/jwt/v2/jwk"
)

func TestAESKW(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name string

		keyPreset jwk.AESPreset
		preset    jwek.KeyWrapPreset
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

			manager := jwek.NewAESKWManager(&jwek.AESKWManagerConfig{
				WrapKey: wrapKey.Key(),
			}, testCase.preset)

			header, err := manager.SetHeader(t.Context(), &jwa.JWH{JWHCommon: jwa.JWHCommon{Enc: jwa.A256GCM}})
			require.NoError(t, err)

			computedCEK, err := manager.ComputeCEK(t.Context(), header)
			require.NoError(t, err)
			require.Len(t, computedCEK, 32)

			encryptedCEK, err := manager.EncryptCEK(t.Context(), header, computedCEK)
			require.NoError(t, err)
			require.NotEmpty(t, encryptedCEK)
			require.NotEqual(t, computedCEK, encryptedCEK)

			t.Run("OK", func(t *testing.T) {
				t.Parallel()

				decoder := jwek.NewAESKWDecoder(
					&jwek.AESKWDecoderConfig{WrapKey: wrapKey.Key()},
					testCase.preset,
				)

				decodedCEK, err := decoder.ComputeCEK(t.Context(), header, encryptedCEK)
				require.NoError(t, err)
				require.Equal(t, computedCEK, decodedCEK)
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
