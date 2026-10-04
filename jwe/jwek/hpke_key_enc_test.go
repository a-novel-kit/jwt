package jwek_test

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/a-novel-kit/jwt/v2"
	"github.com/a-novel-kit/jwt/v2/jwa"
	"github.com/a-novel-kit/jwt/v2/jwe"
	"github.com/a-novel-kit/jwt/v2/jwe/jwek"
	"github.com/a-novel-kit/jwt/v2/jwk"
	"github.com/a-novel-kit/jwt/v2/jwk/serializers"
)

func TestHPKEKeyEnc(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name string

		keyPreset jwk.ECDHPreset
		preset    jwek.HPKEKeyEncPreset
	}{
		{name: "HPKE0KE", keyPreset: jwk.HPKE0KE, preset: jwek.HPKE0KE},
		{name: "HPKE1KE", keyPreset: jwk.HPKE1KE, preset: jwek.HPKE1KE},
		{name: "HPKE2KE", keyPreset: jwk.HPKE2KE, preset: jwek.HPKE2KE},
		{name: "HPKE3KE", keyPreset: jwk.HPKE3KE, preset: jwek.HPKE3KE},
		{name: "HPKE7KE", keyPreset: jwk.HPKE7KE, preset: jwek.HPKE7KE},
	}

	producerClaims := map[string]any{"foo": "bar"}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			privateKey, publicKey, err := jwk.GenerateECDHKey(testCase.keyPreset)
			require.NoError(t, err)

			manager := jwek.NewHPKEKeyEncManager(&jwek.HPKEKeyEncManagerConfig{RecipientKey: publicKey.Key()}, testCase.preset)
			decoder := jwek.NewHPKEKeyEncDecoder(&jwek.HPKEKeyEncDecoderConfig{RecipientKey: privateKey.Key()}, testCase.preset)

			producer := jwt.NewProducer(jwt.ProducerConfig{
				Plugins: []jwt.ProducerPlugin{
					jwe.NewAESGCMEncryption(&jwe.AESGCMEncryptionConfig{CEKManager: manager}, jwe.A256GCM),
				},
			})
			recipient := jwt.NewRecipient(jwt.RecipientConfig{
				Plugins: []jwt.RecipientPlugin{
					jwe.NewAESGCMDecryption(&jwe.AESGCMDecryptionConfig{CEKDecoder: decoder}, jwe.A256GCM),
				},
			})

			first, err := producer.Issue(t.Context(), producerClaims, nil)
			require.NoError(t, err)

			second, err := producer.Issue(t.Context(), producerClaims, nil)
			require.NoError(t, err)

			var recipientClaims map[string]any

			require.NoError(t, recipient.Consume(t.Context(), first, &recipientClaims))
			require.Equal(t, producerClaims, recipientClaims)

			// Each token encapsulates afresh, so "ek" travels in the header and differs per token.
			require.NotEqual(t, first, second)
		})
	}

	t.Run("DraftVectors", func(t *testing.T) {
		t.Parallel()

		raw, err := os.ReadFile("testdata/hpke-key-encryption.json")
		require.NoError(t, err)

		var fixture struct {
			Plaintext string `json:"plaintext"`
			Vectors   []struct {
				Alg     jwa.Alg                 `json:"alg"`
				JWK     serializers.ECDHPayload `json:"jwk"`
				Compact string                  `json:"compact"`
			} `json:"vectors"`
		}

		require.NoError(t, json.Unmarshal(raw, &fixture))

		presets := map[jwa.Alg]jwek.HPKEKeyEncPreset{
			jwa.HPKE0KE: jwek.HPKE0KE, jwa.HPKE1KE: jwek.HPKE1KE, jwa.HPKE2KE: jwek.HPKE2KE,
			jwa.HPKE3KE: jwek.HPKE3KE, jwa.HPKE7KE: jwek.HPKE7KE,
		}
		require.Len(t, fixture.Vectors, len(presets))

		for _, vector := range fixture.Vectors {
			privateKey, _, err := serializers.DecodeECDH(&vector.JWK)
			require.NoError(t, err)

			decoder := jwek.NewHPKEKeyEncDecoder(&jwek.HPKEKeyEncDecoderConfig{RecipientKey: privateKey}, presets[vector.Alg])

			var header jwa.JWH

			parts, err := jwt.DecodeToken(vector.Compact, &jwt.EncryptedTokenDecoder{})
			require.NoError(t, err)
			require.NoError(t, json.Unmarshal(mustDecode(t, parts.Header), &header))

			preset := map[jwa.Enc]jwe.AESGCMPreset{jwa.A128GCM: jwe.A128GCM, jwa.A256GCM: jwe.A256GCM}[header.Enc]
			recipient := jwt.NewRecipient(jwt.RecipientConfig{
				Plugins: []jwt.RecipientPlugin{
					jwe.NewAESGCMDecryption(&jwe.AESGCMDecryptionConfig{CEKDecoder: decoder}, preset),
				},
				Deserializer: func(raw []byte, dst any) error {
					*dst.(*string) = string(raw)

					return nil
				},
			})

			var plaintext string

			require.NoError(t, recipient.Consume(t.Context(), vector.Compact, &plaintext), vector.Alg)
			require.Equal(t, fixture.Plaintext, plaintext, vector.Alg)
		}
	})
}

func TestHPKEKeyEncDecoderRejects(t *testing.T) {
	t.Parallel()

	privateKey, _, err := jwk.GenerateECDHKey(jwk.HPKE0KE)
	require.NoError(t, err)

	x25519Private, _, err := jwk.GenerateECDHKey(jwk.HPKE3KE)
	require.NoError(t, err)

	decoder := jwek.NewHPKEKeyEncDecoder(&jwek.HPKEKeyEncDecoderConfig{RecipientKey: privateKey.Key()}, jwek.HPKE0KE)

	testCases := []struct {
		name string

		decoder *jwek.HPKEKeyEncDecoder
		header  jwa.JWHCommon

		expectErr error
	}{
		{
			name:      "OtherAlgorithm",
			decoder:   decoder,
			header:    jwa.JWHCommon{Alg: jwa.HPKE7KE, JWHHPKE: jwa.JWHHPKE{EK: "AAAA"}},
			expectErr: jwt.ErrMismatchRecipientPlugin,
		},
		{
			name:      "MissingEK",
			decoder:   decoder,
			header:    jwa.JWHCommon{Alg: jwa.HPKE0KE},
			expectErr: jwt.ErrUnsupportedTokenFormat,
		},
		{
			name:      "KeyOffCurve",
			decoder:   jwek.NewHPKEKeyEncDecoder(&jwek.HPKEKeyEncDecoderConfig{RecipientKey: x25519Private.Key()}, jwek.HPKE0KE),
			header:    jwa.JWHCommon{Alg: jwa.HPKE0KE, JWHHPKE: jwa.JWHHPKE{EK: "AAAA"}},
			expectErr: jwt.ErrInvalidSecretKey,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			_, err := testCase.decoder.ComputeCEK(t.Context(), &jwa.JWH{JWHCommon: testCase.header}, []byte("cek"))
			require.ErrorIs(t, err, testCase.expectErr)
		})
	}

}

// "psk_id" selects HPKE's PSK mode by its presence, so an empty or null value still counts. The
// producer authenticates the header carrying it, so only the decoder's check can reject the token:
// the control proves the same pipeline decrypts.
func TestHPKEKeyEncDecoderRefusesPSKID(t *testing.T) {
	t.Parallel()

	privateKey, publicKey, err := jwk.GenerateECDHKey(jwk.HPKE0KE)
	require.NoError(t, err)

	producer := jwt.NewProducer(jwt.ProducerConfig{
		Plugins: []jwt.ProducerPlugin{
			jwe.NewAESGCMEncryption(&jwe.AESGCMEncryptionConfig{
				CEKManager: jwek.NewHPKEKeyEncManager(&jwek.HPKEKeyEncManagerConfig{RecipientKey: publicKey.Key()}, jwek.HPKE0KE),
			}, jwe.A128GCM),
		},
	})
	recipient := jwt.NewRecipient(jwt.RecipientConfig{
		Plugins: []jwt.RecipientPlugin{
			jwe.NewAESGCMDecryption(&jwe.AESGCMDecryptionConfig{
				CEKDecoder: jwek.NewHPKEKeyEncDecoder(&jwek.HPKEKeyEncDecoderConfig{RecipientKey: privateKey.Key()}, jwek.HPKE0KE),
			}, jwe.A128GCM),
		},
	})

	testCases := []struct {
		name   string
		header any

		expectErr error
	}{
		{name: "Control", header: nil},
		{name: "EmptyPSKID", header: map[string]any{"psk_id": ""}, expectErr: jwt.ErrUnsupportedTokenFormat},
		{name: "NullPSKID", header: map[string]any{"psk_id": nil}, expectErr: jwt.ErrUnsupportedTokenFormat},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			token, err := producer.Issue(t.Context(), map[string]any{"foo": "bar"}, testCase.header)
			require.NoError(t, err)

			var claims map[string]any

			err = recipient.Consume(t.Context(), token, &claims)
			require.ErrorIs(t, err, testCase.expectErr)
		})
	}
}
