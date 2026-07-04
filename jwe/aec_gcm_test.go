package jwe_test

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/a-novel-kit/jwt"
	"github.com/a-novel-kit/jwt/jwe"
	"github.com/a-novel-kit/jwt/jwk"
)

func TestAESGCM(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name string

		keyPreset jwk.AESPreset
		preset    jwe.AESGCMPreset
	}{
		{
			name:      "A128GCM",
			keyPreset: jwk.A128GCM,
			preset:    jwe.A128GCM,
		},
		{
			name:      "A192GCM",
			keyPreset: jwk.A192GCM,
			preset:    jwe.A192GCM,
		},
		{
			name:      "A256GCM",
			keyPreset: jwk.A256GCM,
			preset:    jwe.A256GCM,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			key, err := jwk.GenerateAES(testCase.keyPreset)
			require.NoError(t, err)

			t.Run("WithEncKey", func(t *testing.T) {
				t.Parallel()

				cekManager := &fakeCEKManager{
					cek:       key.Key(),
					encrypted: []byte("encrypted"),
				}

				encrypter := jwe.NewAESGCMEncryption(&jwe.AESGCMEncryptionConfig{
					CEKManager:     cekManager,
					AdditionalData: []byte("additional-data"),
				}, testCase.preset)

				producer := jwt.NewProducer(jwt.ProducerConfig{
					Plugins: []jwt.ProducerPlugin{encrypter},
				})

				producerClaims := map[string]any{"foo": "bar"}

				token, err := producer.Issue(t.Context(), producerClaims, nil)
				require.NoError(t, err)

				t.Run("Success", func(t *testing.T) {
					t.Parallel()

					cekDecoder := &fakeCEKDecoder{
						cek:       key.Key(),
						encrypted: []byte("encrypted"),
					}

					decrypter := jwe.NewAESGCMDecryption(&jwe.AESGCMDecryptionConfig{
						CEKDecoder:     cekDecoder,
						AdditionalData: []byte("additional-data"),
					}, testCase.preset)

					recipient := jwt.NewRecipient(jwt.RecipientConfig{
						Plugins: []jwt.RecipientPlugin{decrypter},
					})

					var recipientClaims map[string]any

					require.NoError(t, recipient.Consume(t.Context(), token, &recipientClaims))
					require.Equal(t, producerClaims, recipientClaims)
				})

				t.Run("WrongCEK", func(t *testing.T) {
					t.Parallel()

					fakeKey, err := jwk.GenerateAES(testCase.keyPreset)
					require.NoError(t, err)

					cekDecoder := &fakeCEKDecoder{
						cek:       fakeKey.Key(),
						encrypted: []byte("encrypted"),
					}

					decrypter := jwe.NewAESGCMDecryption(&jwe.AESGCMDecryptionConfig{
						CEKDecoder:     cekDecoder,
						AdditionalData: []byte("additional-data"),
					}, testCase.preset)

					recipient := jwt.NewRecipient(jwt.RecipientConfig{
						Plugins: []jwt.RecipientPlugin{decrypter},
					})

					var recipientClaims map[string]any

					require.Error(t, recipient.Consume(t.Context(), token, &recipientClaims))
				})
			})

			t.Run("WithoutEncKey", func(t *testing.T) {
				t.Parallel()

				cekManager := &fakeCEKManager{
					cek: key.Key(),
				}

				encrypter := jwe.NewAESGCMEncryption(&jwe.AESGCMEncryptionConfig{
					CEKManager:     cekManager,
					AdditionalData: []byte("additional-data"),
				}, testCase.preset)

				producer := jwt.NewProducer(jwt.ProducerConfig{
					Plugins: []jwt.ProducerPlugin{encrypter},
				})

				producerClaims := map[string]any{"foo": "bar"}

				token, err := producer.Issue(t.Context(), producerClaims, nil)
				require.NoError(t, err)

				t.Run("Success", func(t *testing.T) {
					t.Parallel()

					cekDecoder := &fakeCEKDecoder{
						cek: key.Key(),
					}

					decrypter := jwe.NewAESGCMDecryption(&jwe.AESGCMDecryptionConfig{
						CEKDecoder:     cekDecoder,
						AdditionalData: []byte("additional-data"),
					}, testCase.preset)

					recipient := jwt.NewRecipient(jwt.RecipientConfig{
						Plugins: []jwt.RecipientPlugin{decrypter},
					})

					var recipientClaims map[string]any

					require.NoError(t, recipient.Consume(t.Context(), token, &recipientClaims))
					require.Equal(t, producerClaims, recipientClaims)
				})

				t.Run("WrongCEK", func(t *testing.T) {
					t.Parallel()

					fakeKey, err := jwk.GenerateAES(testCase.keyPreset)
					require.NoError(t, err)

					cekDecoder := &fakeCEKDecoder{
						cek: fakeKey.Key(),
					}

					decrypter := jwe.NewAESGCMDecryption(&jwe.AESGCMDecryptionConfig{
						CEKDecoder:     cekDecoder,
						AdditionalData: []byte("additional-data"),
					}, testCase.preset)

					recipient := jwt.NewRecipient(jwt.RecipientConfig{
						Plugins: []jwt.RecipientPlugin{decrypter},
					})

					var recipientClaims map[string]any

					require.Error(t, recipient.Consume(t.Context(), token, &recipientClaims))
				})
			})

			t.Run("NoAdditionalData", func(t *testing.T) {
				t.Parallel()

				cekManager := &fakeCEKManager{
					cek:       key.Key(),
					encrypted: []byte("encrypted"),
				}

				encrypter := jwe.NewAESGCMEncryption(&jwe.AESGCMEncryptionConfig{
					CEKManager: cekManager,
				}, testCase.preset)

				producer := jwt.NewProducer(jwt.ProducerConfig{
					Plugins: []jwt.ProducerPlugin{encrypter},
				})

				producerClaims := map[string]any{"foo": "bar"}

				token, err := producer.Issue(t.Context(), producerClaims, nil)
				require.NoError(t, err)

				cekDecoder := &fakeCEKDecoder{
					cek:       key.Key(),
					encrypted: []byte("encrypted"),
				}

				decrypter := jwe.NewAESGCMDecryption(&jwe.AESGCMDecryptionConfig{
					CEKDecoder: cekDecoder,
				}, testCase.preset)

				recipient := jwt.NewRecipient(jwt.RecipientConfig{
					Plugins: []jwt.RecipientPlugin{decrypter},
				})

				var recipientClaims map[string]any

				require.NoError(t, recipient.Consume(t.Context(), token, &recipientClaims))
				require.Equal(t, producerClaims, recipientClaims)
			})

			t.Run("WrongAdditionalData", func(t *testing.T) {
				t.Parallel()

				cekManager := &fakeCEKManager{
					cek:       key.Key(),
					encrypted: []byte("encrypted"),
				}

				encrypter := jwe.NewAESGCMEncryption(&jwe.AESGCMEncryptionConfig{
					CEKManager:     cekManager,
					AdditionalData: []byte("additional-data"),
				}, testCase.preset)

				producer := jwt.NewProducer(jwt.ProducerConfig{
					Plugins: []jwt.ProducerPlugin{encrypter},
				})

				producerClaims := map[string]any{"foo": "bar"}

				token, err := producer.Issue(t.Context(), producerClaims, nil)
				require.NoError(t, err)

				cekDecoder := &fakeCEKDecoder{
					cek:       key.Key(),
					encrypted: []byte("encrypted"),
				}

				decrypter := jwe.NewAESGCMDecryption(&jwe.AESGCMDecryptionConfig{
					CEKDecoder:     cekDecoder,
					AdditionalData: []byte("fake-additional-data"),
				}, testCase.preset)

				recipient := jwt.NewRecipient(jwt.RecipientConfig{
					Plugins: []jwt.RecipientPlugin{decrypter},
				})

				var recipientClaims map[string]any

				require.Error(t, recipient.Consume(t.Context(), token, &recipientClaims))
			})
		})
	}
}

func TestAESGCMBadIV(t *testing.T) {
	t.Parallel()

	key, err := jwk.GenerateAES(jwk.A256GCM)
	require.NoError(t, err)

	encrypter := jwe.NewAESGCMEncryption(&jwe.AESGCMEncryptionConfig{
		CEKManager: &fakeCEKManager{cek: key.Key(), encrypted: []byte("encrypted")},
	}, jwe.A256GCM)
	producer := jwt.NewProducer(jwt.ProducerConfig{Plugins: []jwt.ProducerPlugin{encrypter}})

	token, err := producer.Issue(t.Context(), map[string]any{"foo": "bar"}, nil)
	require.NoError(t, err)

	// gcm.Open panics on a wrong-length nonce; a tampered IV must instead yield an error.
	parts, err := jwt.DecodeToken(token, &jwt.EncryptedTokenDecoder{})
	require.NoError(t, err)

	parts.IV = base64.RawURLEncoding.EncodeToString([]byte("short"))

	decrypter := jwe.NewAESGCMDecryption(&jwe.AESGCMDecryptionConfig{
		CEKDecoder: &fakeCEKDecoder{cek: key.Key(), encrypted: []byte("encrypted")},
	}, jwe.A256GCM)
	recipient := jwt.NewRecipient(jwt.RecipientConfig{Plugins: []jwt.RecipientPlugin{decrypter}})

	var claims map[string]any
	require.ErrorIs(t, recipient.Consume(t.Context(), parts.String(), &claims), jwe.ErrInvalidToken)
}
