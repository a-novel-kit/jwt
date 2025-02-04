package jwe_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/a-novel-kit/jwt"
	"github.com/a-novel-kit/jwt/jwe"
	"github.com/a-novel-kit/jwt/jwk"
)

func TestAESCBC(t *testing.T) {
	testCases := []struct {
		name string

		keyPreset jwk.AESPreset
		preset    jwe.AESCBCPreset
	}{
		{
			name:      "A128CBC-HS256",
			keyPreset: jwk.A128CBC,
			preset:    jwe.A128CBCHS256,
		},
		{
			name:      "A192CBC-HS384",
			keyPreset: jwk.A192CBC,
			preset:    jwe.A192CBCHS384,
		},
		{
			name:      "A256CBC-HS512",
			keyPreset: jwk.A256CBC,
			preset:    jwe.A256CBCHS512,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			key, err := jwk.GenerateAES(testCase.keyPreset)
			require.NoError(t, err)

			t.Run("WithEncKey", func(t *testing.T) {
				cekManager := &fakeCEKManager{
					cek:       key.Key(),
					encrypted: []byte("encrypted"),
				}

				encrypter := jwe.NewAESCBCEncryption(&jwe.AESCBCEncryptionConfig{
					CEKManager:     cekManager,
					AdditionalData: []byte("additional-data"),
				}, testCase.preset)

				producer := jwt.NewProducer(jwt.ProducerConfig{
					Plugins: []jwt.ProducerPlugin{encrypter},
				})

				producerClaims := map[string]any{"foo": "bar"}

				token, err := producer.Issue(context.Background(), producerClaims, nil)
				require.NoError(t, err)

				t.Run("Success", func(t *testing.T) {
					cekDecoder := &fakeCEKDecoder{
						cek:       key.Key(),
						encrypted: []byte("encrypted"),
					}

					decrypter := jwe.NewAESCBCDecryption(&jwe.AESCBCDecryptionConfig{
						CEKDecoder:     cekDecoder,
						AdditionalData: []byte("additional-data"),
					}, testCase.preset)

					recipient := jwt.NewRecipient(jwt.RecipientConfig{
						Plugins: []jwt.RecipientPlugin{decrypter},
					})

					var recipientClaims map[string]any
					require.NoError(t, recipient.Consume(context.Background(), token, &recipientClaims))
					require.Equal(t, producerClaims, recipientClaims)
				})

				t.Run("WrongCEK", func(t *testing.T) {
					fakeKey, err := jwk.GenerateAES(testCase.keyPreset)
					require.NoError(t, err)

					cekDecoder := &fakeCEKDecoder{
						cek:       fakeKey.Key(),
						encrypted: []byte("encrypted"),
					}

					decrypter := jwe.NewAESCBCDecryption(&jwe.AESCBCDecryptionConfig{
						CEKDecoder:     cekDecoder,
						AdditionalData: []byte("additional-data"),
					}, testCase.preset)

					recipient := jwt.NewRecipient(jwt.RecipientConfig{
						Plugins: []jwt.RecipientPlugin{decrypter},
					})

					var recipientClaims map[string]any
					require.Error(t, recipient.Consume(context.Background(), token, &recipientClaims))
				})
			})

			t.Run("WithoutEncKey", func(t *testing.T) {
				cekManager := &fakeCEKManager{
					cek: key.Key(),
				}

				encrypter := jwe.NewAESCBCEncryption(&jwe.AESCBCEncryptionConfig{
					CEKManager:     cekManager,
					AdditionalData: []byte("additional-data"),
				}, testCase.preset)

				producer := jwt.NewProducer(jwt.ProducerConfig{
					Plugins: []jwt.ProducerPlugin{encrypter},
				})

				producerClaims := map[string]any{"foo": "bar"}

				token, err := producer.Issue(context.Background(), producerClaims, nil)
				require.NoError(t, err)

				t.Run("Success", func(t *testing.T) {
					cekDecoder := &fakeCEKDecoder{
						cek: key.Key(),
					}

					decrypter := jwe.NewAESCBCDecryption(&jwe.AESCBCDecryptionConfig{
						CEKDecoder:     cekDecoder,
						AdditionalData: []byte("additional-data"),
					}, testCase.preset)

					recipient := jwt.NewRecipient(jwt.RecipientConfig{
						Plugins: []jwt.RecipientPlugin{decrypter},
					})

					var recipientClaims map[string]any
					require.NoError(t, recipient.Consume(context.Background(), token, &recipientClaims))
					require.Equal(t, producerClaims, recipientClaims)
				})

				t.Run("WrongCEK", func(t *testing.T) {
					fakeKey, err := jwk.GenerateAES(testCase.keyPreset)
					require.NoError(t, err)

					cekDecoder := &fakeCEKDecoder{
						cek: fakeKey.Key(),
					}

					decrypter := jwe.NewAESCBCDecryption(&jwe.AESCBCDecryptionConfig{
						CEKDecoder:     cekDecoder,
						AdditionalData: []byte("additional-data"),
					}, testCase.preset)

					recipient := jwt.NewRecipient(jwt.RecipientConfig{
						Plugins: []jwt.RecipientPlugin{decrypter},
					})

					var recipientClaims map[string]any
					require.Error(t, recipient.Consume(context.Background(), token, &recipientClaims))
				})
			})
		})
	}
}
