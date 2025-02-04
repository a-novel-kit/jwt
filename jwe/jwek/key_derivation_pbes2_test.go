package jwek_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/a-novel-kit/jwt/jwa"
	"github.com/a-novel-kit/jwt/jwe/jwek"
	"github.com/a-novel-kit/jwt/jwk"
)

func TestPBES2KeyAgrKW(t *testing.T) {
	testCases := []struct {
		name string

		preset jwek.PBES2KeyAgrKWPreset
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
			cek, err := jwk.GenerateAES(jwk.A256GCM)

			secret := "my-strong-password"

			manager := jwek.NewPBES2KeyAgrKWManager(&jwek.PBES2KeyAgrKWManagerConfig{
				CEK:        cek.Key(),
				Secret:     secret,
				Iterations: 1000,
				SaltSize:   16,
			}, testCase.preset)

			header, err := manager.SetHeader(context.Background(), &jwa.JWH{})
			require.NoError(t, err)

			computedCEK, err := manager.ComputeCEK(context.Background(), header)
			require.NoError(t, err)
			require.Equal(t, cek.Key(), computedCEK)

			encryptedCEK, err := manager.EncryptCEK(context.Background(), header, computedCEK)
			require.NoError(t, err)
			require.NotNil(t, encryptedCEK)
			require.NotEqual(t, cek.Key(), encryptedCEK)

			t.Run("OK", func(t *testing.T) {
				decoder := jwek.NewPBES2KeyAgrKWDecoder(
					&jwek.PBES2KeyAgrKWDecoderConfig{Secret: secret},
					testCase.preset,
				)

				decodedCEK, err := decoder.ComputeCEK(context.Background(), header, encryptedCEK)
				require.NoError(t, err)
				require.Equal(t, computedCEK, decodedCEK)
			})

			t.Run("WrongSecret", func(t *testing.T) {
				decoder := jwek.NewPBES2KeyAgrKWDecoder(
					&jwek.PBES2KeyAgrKWDecoderConfig{Secret: "fake-secret"},
					testCase.preset,
				)

				_, err = decoder.ComputeCEK(context.Background(), header, encryptedCEK)
				require.Error(t, err)
			})

			t.Run("MissingEncKey", func(t *testing.T) {
				decoder := jwek.NewPBES2KeyAgrKWDecoder(
					&jwek.PBES2KeyAgrKWDecoderConfig{Secret: secret},
					testCase.preset,
				)

				_, err := decoder.ComputeCEK(context.Background(), header, nil)
				require.Error(t, err)
			})
		})
	}
}
