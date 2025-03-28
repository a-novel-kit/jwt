package jwek_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/a-novel-kit/jwt"
	"github.com/a-novel-kit/jwt/jwa"
	"github.com/a-novel-kit/jwt/jwe/jwek"
	"github.com/a-novel-kit/jwt/jwk"
)

func TestECDHKeyAgr(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name string

		preset jwek.ECDHKeyAgrPreset
	}{
		{
			name:   "ECDHESA128CBC",
			preset: jwek.ECDHESA128CBC,
		},
		{
			name:   "ECDHESA192CBC",
			preset: jwek.ECDHESA192CBC,
		},
		{
			name:   "ECDHESA256CBC",
			preset: jwek.ECDHESA256CBC,
		},
		{
			name:   "ECDHESA128GCM",
			preset: jwek.ECDHESA128GCM,
		},
		{
			name:   "ECDHESA192GCM",
			preset: jwek.ECDHESA192GCM,
		},
		{
			name:   "ECDHESA256GCM",
			preset: jwek.ECDHESA256GCM,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			producerPrivateKey, _, err := jwk.GenerateECDH()
			require.NoError(t, err)

			recipientPrivateKey, recipientPublicKey, err := jwk.GenerateECDH()
			require.NoError(t, err)

			manager := jwek.NewECDHKeyAgrManager(&jwek.ECDHKeyAgrManagerConfig{
				ProducerKey:   producerPrivateKey.Key(),
				RecipientKey:  recipientPublicKey.Key(),
				ProducerInfo:  "producer",
				RecipientInfo: "recipient",
			}, testCase.preset)

			header, err := manager.SetHeader(t.Context(), &jwa.JWH{})
			require.NoError(t, err)

			computedCEK, err := manager.ComputeCEK(t.Context(), header)
			require.NoError(t, err)

			encryptedCEK, err := manager.EncryptCEK(t.Context(), header, computedCEK)
			require.NoError(t, err)
			require.Nil(t, encryptedCEK)

			t.Run("OK", func(t *testing.T) {
				t.Parallel()

				decoder := jwek.NewECDHKeyAgrDecoder(&jwek.ECDHKeyAgrDecoderConfig{
					RecipientKey: recipientPrivateKey.Key(),
				}, testCase.preset)

				decodedCEK, err := decoder.ComputeCEK(t.Context(), header, nil)
				require.NoError(t, err)
				require.Equal(t, computedCEK, decodedCEK)
			})

			t.Run("WrongRecipientKey", func(t *testing.T) {
				t.Parallel()

				fakeRecipientPrivateKey, _, err := jwk.GenerateECDH()
				require.NoError(t, err)

				decoder := jwek.NewECDHKeyAgrDecoder(&jwek.ECDHKeyAgrDecoderConfig{
					RecipientKey: fakeRecipientPrivateKey.Key(),
				}, testCase.preset)

				decodedCEK, err := decoder.ComputeCEK(t.Context(), header, nil)
				require.NoError(t, err)
				require.NotEqual(t, computedCEK, decodedCEK)
			})

			t.Run("WrongProducerInfo", func(t *testing.T) {
				t.Parallel()

				decoder := jwek.NewECDHKeyAgrDecoder(&jwek.ECDHKeyAgrDecoderConfig{
					RecipientKey: recipientPrivateKey.Key(),
				}, testCase.preset)

				common := header.JWHCommon
				common.APU = "fake-producer"

				decodedCEK, err := decoder.ComputeCEK(t.Context(), &jwa.JWH{JWHCommon: common}, nil)
				require.NoError(t, err)
				require.NotEqual(t, computedCEK, decodedCEK)
			})

			t.Run("WrongRecipientInfo", func(t *testing.T) {
				t.Parallel()

				decoder := jwek.NewECDHKeyAgrDecoder(&jwek.ECDHKeyAgrDecoderConfig{
					RecipientKey: recipientPrivateKey.Key(),
				}, testCase.preset)

				common := header.JWHCommon
				common.APV = "fake-recipient"

				decodedCEK, err := decoder.ComputeCEK(t.Context(), &jwa.JWH{JWHCommon: common}, nil)
				require.NoError(t, err)
				require.NotEqual(t, computedCEK, decodedCEK)
			})

			t.Run("MissingEPK", func(t *testing.T) {
				t.Parallel()

				decoder := jwek.NewECDHKeyAgrDecoder(&jwek.ECDHKeyAgrDecoderConfig{
					RecipientKey: recipientPrivateKey.Key(),
				}, testCase.preset)

				common := header.JWHCommon
				common.EPK = nil

				_, err = decoder.ComputeCEK(t.Context(), &jwa.JWH{JWHCommon: common}, nil)
				require.ErrorIs(t, err, jwt.ErrUnsupportedTokenFormat)
			})

			t.Run("UnexpectedEncKey", func(t *testing.T) {
				t.Parallel()

				decoder := jwek.NewECDHKeyAgrDecoder(&jwek.ECDHKeyAgrDecoderConfig{
					RecipientKey: recipientPrivateKey.Key(),
				}, testCase.preset)

				_, err = decoder.ComputeCEK(t.Context(), header, []byte("fake-enc-key"))
				require.Error(t, err)
			})
		})
	}
}
