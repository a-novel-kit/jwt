package jwek_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/a-novel-kit/jwt"
	"github.com/a-novel-kit/jwt/jwa"
	"github.com/a-novel-kit/jwt/jwe/jwek"
	"github.com/a-novel-kit/jwt/jwk"
)

func TestECDHKeyAgrKW(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name string

		preset jwek.ECDHKeyAgrKWPreset
	}{
		{
			name:   "ECDHESA128KW",
			preset: jwek.ECDHESA128KW,
		},
		{
			name:   "ECDHESA192KW",
			preset: jwek.ECDHESA192KW,
		},
		{
			name:   "ECDHESA256KW",
			preset: jwek.ECDHESA256KW,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			cek, err := jwk.GenerateAES(jwk.A256GCM)
			require.NoError(t, err)

			producerPrivateKey, _, err := jwk.GenerateECDH()
			require.NoError(t, err)

			recipientPrivateKey, recipientPublicKey, err := jwk.GenerateECDH()
			require.NoError(t, err)

			manager := jwek.NewECDHKeyAgrKWManager(&jwek.ECDHKeyAgrKWManagerConfig{
				CEK:           cek.Key(),
				ProducerKey:   producerPrivateKey.Key(),
				RecipientKey:  recipientPublicKey.Key(),
				ProducerInfo:  "producer",
				RecipientInfo: "recipient",
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

				decoder := jwek.NewECDHKeyAgrKWDecoder(&jwek.ECDHKeyAgrKWDecoderConfig{
					RecipientKey: recipientPrivateKey.Key(),
				}, testCase.preset)

				decodedCEK, err := decoder.ComputeCEK(t.Context(), header, encryptedCEK)
				require.NoError(t, err)
				require.Equal(t, computedCEK, decodedCEK)
			})

			t.Run("WrongRecipientKey", func(t *testing.T) {
				t.Parallel()

				fakeRecipientPrivateKey, _, err := jwk.GenerateECDH()
				require.NoError(t, err)

				decoder := jwek.NewECDHKeyAgrKWDecoder(&jwek.ECDHKeyAgrKWDecoderConfig{
					RecipientKey: fakeRecipientPrivateKey.Key(),
				}, testCase.preset)

				_, err = decoder.ComputeCEK(t.Context(), header, encryptedCEK)
				require.Error(t, err)
			})

			t.Run("WrongProducerInfo", func(t *testing.T) {
				t.Parallel()

				decoder := jwek.NewECDHKeyAgrKWDecoder(&jwek.ECDHKeyAgrKWDecoderConfig{
					RecipientKey: recipientPrivateKey.Key(),
				}, testCase.preset)

				common := header.JWHCommon
				common.APU = "fake-producer"

				_, err := decoder.ComputeCEK(t.Context(), &jwa.JWH{JWHCommon: common}, encryptedCEK)
				require.Error(t, err)
			})

			t.Run("WrongRecipientInfo", func(t *testing.T) {
				t.Parallel()

				decoder := jwek.NewECDHKeyAgrKWDecoder(&jwek.ECDHKeyAgrKWDecoderConfig{
					RecipientKey: recipientPrivateKey.Key(),
				}, testCase.preset)

				common := header.JWHCommon
				common.APV = "fake-recipient"

				_, err := decoder.ComputeCEK(t.Context(), &jwa.JWH{JWHCommon: common}, encryptedCEK)
				require.Error(t, err)
			})

			t.Run("MissingEPK", func(t *testing.T) {
				t.Parallel()

				decoder := jwek.NewECDHKeyAgrKWDecoder(&jwek.ECDHKeyAgrKWDecoderConfig{
					RecipientKey: recipientPrivateKey.Key(),
				}, testCase.preset)

				common := header.JWHCommon
				common.EPK = nil

				_, err := decoder.ComputeCEK(t.Context(), &jwa.JWH{JWHCommon: common}, encryptedCEK)
				require.ErrorIs(t, err, jwt.ErrUnsupportedTokenFormat)
			})

			t.Run("MissingEncKey", func(t *testing.T) {
				t.Parallel()

				decoder := jwek.NewECDHKeyAgrKWDecoder(&jwek.ECDHKeyAgrKWDecoderConfig{
					RecipientKey: recipientPrivateKey.Key(),
				}, testCase.preset)

				_, err := decoder.ComputeCEK(t.Context(), header, nil)
				require.Error(t, err)
			})
		})
	}
}
