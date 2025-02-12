package jwek_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/a-novel-kit/jwt/jwa"
	"github.com/a-novel-kit/jwt/jwe/jwek"
	"github.com/a-novel-kit/jwt/jwk"
)

func TestPBES2KeyEncKW(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name string

		preset jwek.PBES2KeyEncKWPreset
	}{
		{
			name:   "PBES2A128KW",
			preset: jwek.PBES2A128KW,
		},
		{
			name:   "PBES2A192KW",
			preset: jwek.PBES2A192KW,
		},
		{
			name:   "PBES2A256KW",
			preset: jwek.PBES2A256KW,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			cek, err := jwk.GenerateAES(jwk.A256GCM)
			require.NoError(t, err)

			secret := "my-strong-password"

			manager := jwek.NewPBES2KeyEncKWManager(&jwek.PBES2KeyEncKWManagerConfig{
				CEK:        cek.Key(),
				Secret:     secret,
				Iterations: 1000,
				SaltSize:   16,
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

				decoder := jwek.NewPBES2KeyEncKWDecoder(
					&jwek.PBES2KeyEncKWDecoderConfig{Secret: secret},
					testCase.preset,
				)

				decodedCEK, err := decoder.ComputeCEK(t.Context(), header, encryptedCEK)
				require.NoError(t, err)
				require.Equal(t, computedCEK, decodedCEK)
			})

			t.Run("WrongSecret", func(t *testing.T) {
				t.Parallel()

				decoder := jwek.NewPBES2KeyEncKWDecoder(
					&jwek.PBES2KeyEncKWDecoderConfig{Secret: "fake-secret"},
					testCase.preset,
				)

				_, err = decoder.ComputeCEK(t.Context(), header, encryptedCEK)
				require.Error(t, err)
			})

			t.Run("MissingEncKey", func(t *testing.T) {
				t.Parallel()

				decoder := jwek.NewPBES2KeyEncKWDecoder(
					&jwek.PBES2KeyEncKWDecoderConfig{Secret: secret},
					testCase.preset,
				)

				_, err := decoder.ComputeCEK(t.Context(), header, nil)
				require.Error(t, err)
			})
		})
	}
}
