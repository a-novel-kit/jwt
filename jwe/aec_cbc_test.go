package jwe_test

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/a-novel-kit/jwt/v2"
	"github.com/a-novel-kit/jwt/v2/jwa"
	"github.com/a-novel-kit/jwt/v2/jwe"
	"github.com/a-novel-kit/jwt/v2/jwk"
	"github.com/a-novel-kit/jwt/v2/testutils"
)

func TestAESCBC(t *testing.T) {
	t.Parallel()

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
			t.Parallel()

			key, err := jwk.GenerateAES(testCase.keyPreset)
			require.NoError(t, err)

			t.Run("WithEncKey", func(t *testing.T) {
				t.Parallel()

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

				token, err := producer.Issue(t.Context(), producerClaims, nil)
				require.NoError(t, err)

				t.Run("Success", func(t *testing.T) {
					t.Parallel()

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

					decrypter := jwe.NewAESCBCDecryption(&jwe.AESCBCDecryptionConfig{
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

				encrypter := jwe.NewAESCBCEncryption(&jwe.AESCBCEncryptionConfig{
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

					decrypter := jwe.NewAESCBCDecryption(&jwe.AESCBCDecryptionConfig{
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

					decrypter := jwe.NewAESCBCDecryption(&jwe.AESCBCDecryptionConfig{
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

				encrypter := jwe.NewAESCBCEncryption(&jwe.AESCBCEncryptionConfig{
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

				decrypter := jwe.NewAESCBCDecryption(&jwe.AESCBCDecryptionConfig{
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

				encrypter := jwe.NewAESCBCEncryption(&jwe.AESCBCEncryptionConfig{
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

				decrypter := jwe.NewAESCBCDecryption(&jwe.AESCBCDecryptionConfig{
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

func TestAESCBCRejectsCompression(t *testing.T) {
	t.Parallel()

	decrypter := jwe.NewAESCBCDecryption(&jwe.AESCBCDecryptionConfig{CEKDecoder: &fakeCEKDecoder{}}, jwe.A256CBCHS512)

	header := &jwa.JWH{JWHCommon: jwa.JWHCommon{Enc: jwe.A256CBCHS512.Enc, Zip: jwa.ZipDeflate}}

	_, err := decrypter.Transform(t.Context(), header, "a.b.c.d.e")
	require.ErrorIs(t, err, jwt.ErrUnsupportedTokenFormat)
}

func TestAESCBCMalformedSegment(t *testing.T) {
	t.Parallel()

	key, err := jwk.GenerateAES(jwk.A256CBC)
	require.NoError(t, err)

	encrypter := jwe.NewAESCBCEncryption(&jwe.AESCBCEncryptionConfig{
		CEKManager: &fakeCEKManager{cek: key.Key(), encrypted: []byte("encrypted")},
	}, jwe.A256CBCHS512)
	producer := jwt.NewProducer(jwt.ProducerConfig{Plugins: []jwt.ProducerPlugin{encrypter}})

	token, err := producer.Issue(t.Context(), map[string]any{"foo": "bar"}, nil)
	require.NoError(t, err)

	decrypter := jwe.NewAESCBCDecryption(&jwe.AESCBCDecryptionConfig{
		CEKDecoder: &fakeCEKDecoder{cek: key.Key(), encrypted: []byte("encrypted")},
	}, jwe.A256CBCHS512)
	recipient := jwt.NewRecipient(jwt.RecipientConfig{Plugins: []jwt.RecipientPlugin{decrypter}})

	testCases := []struct {
		name    string
		malform func(token *jwt.EncryptedToken)
	}{
		{name: "EncKey", malform: func(token *jwt.EncryptedToken) { token.EncKey = testutils.UndecodableSegment }},
		{name: "IV", malform: func(token *jwt.EncryptedToken) { token.IV = testutils.UndecodableSegment }},
		{name: "Tag", malform: func(token *jwt.EncryptedToken) { token.Tag = testutils.UndecodableSegment }},
		{name: "CipherText", malform: func(token *jwt.EncryptedToken) { token.CipherText = testutils.UndecodableSegment }},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			parts, err := jwt.DecodeToken(token, &jwt.EncryptedTokenDecoder{})
			require.NoError(t, err)

			testCase.malform(parts)

			var claims map[string]any
			require.ErrorIs(t, recipient.Consume(t.Context(), parts.String(), &claims), jwt.ErrUnsupportedTokenFormat)
		})
	}
}

// RFC 7518 §5.2.2.1 takes MAC_KEY from the leading MAC_KEY_LEN octets of the content encryption key
// and ENC_KEY from the octets after it. The package presets split the key in equal halves, which hides
// the offset, and a round trip agrees with itself on any split. This preset's keys differ in length,
// and the test decrypts the ciphertext with ENC_KEY on its own.
func TestAESCBCKeySplit(t *testing.T) {
	t.Parallel()

	preset := jwe.AESCBCPreset{
		Enc:       jwa.A256CBC,
		Hash:      crypto.SHA256,
		KeyLen:    48,
		EncKeyLen: 32,
		MACKeyLen: 16,
		TagLength: 16,
	}

	cek := make([]byte, preset.KeyLen)
	_, err := rand.Read(cek)
	require.NoError(t, err)

	encrypter := jwe.NewAESCBCEncryption(&jwe.AESCBCEncryptionConfig{
		CEKManager: &fakeCEKManager{cek: cek, encrypted: []byte("encrypted")},
	}, preset)

	header, err := encrypter.Header(t.Context(), &jwa.JWH{})
	require.NoError(t, err)

	plainText := []byte(`{"foo":"bar"}`)
	rawToken := jwt.RawToken{Header: "e30", Payload: base64.RawURLEncoding.EncodeToString(plainText)}

	token, err := encrypter.Transform(t.Context(), header, rawToken.String())
	require.NoError(t, err)

	parts, err := jwt.DecodeToken(token, &jwt.EncryptedTokenDecoder{})
	require.NoError(t, err)

	block, err := aes.NewCipher(cek[preset.MACKeyLen:])
	require.NoError(t, err)

	cipherText := mustDecodeBase64(t, parts.CipherText)
	decrypted := make([]byte, len(cipherText))
	cipher.NewCBCDecrypter(block, mustDecodeBase64(t, parts.IV)).CryptBlocks(decrypted, cipherText)
	require.Equal(t, plainText, decrypted[:len(plainText)])

	decrypter := jwe.NewAESCBCDecryption(&jwe.AESCBCDecryptionConfig{
		CEKDecoder: &fakeCEKDecoder{cek: cek, encrypted: []byte("encrypted")},
	}, preset)

	decoded, err := decrypter.Transform(t.Context(), header, token)
	require.NoError(t, err)
	require.Equal(t, plainText, decoded)
}
