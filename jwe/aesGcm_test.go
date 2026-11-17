package jwe_test

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/a-novel-kit/jwt/v2"
	"github.com/a-novel-kit/jwt/v2/jwa"
	"github.com/a-novel-kit/jwt/v2/jwe"
	"github.com/a-novel-kit/jwt/v2/jwe/jwek"
	"github.com/a-novel-kit/jwt/v2/jwk"
	"github.com/a-novel-kit/jwt/v2/jwk/serializers"
	"github.com/a-novel-kit/jwt/v2/testutils"
)

func TestAESGCM(t *testing.T) {
	t.Parallel()

	presets := []struct {
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

	additionalData := []byte("additional-data")

	testCases := []struct {
		name string

		// encrypted is the key material that travels with the token. Nil sends none.
		encrypted []byte
		// producerData and recipientData are the additional data each side authenticates.
		producerData  []byte
		recipientData []byte
		// wrongCEK makes the recipient decrypt under a key other than the producer's.
		wrongCEK bool

		expectErr error
	}{
		{
			name:          "Success/WithEncKey",
			encrypted:     []byte("encrypted"),
			producerData:  additionalData,
			recipientData: additionalData,
		},
		{
			name:          "Success/WithoutEncKey",
			producerData:  additionalData,
			recipientData: additionalData,
		},
		{
			name:      "Success/NoAdditionalData",
			encrypted: []byte("encrypted"),
		},
		{
			name:          "Error/WrongCEK/WithEncKey",
			encrypted:     []byte("encrypted"),
			producerData:  additionalData,
			recipientData: additionalData,
			wrongCEK:      true,
			expectErr:     jwe.ErrInvalidSecret,
		},
		{
			name:          "Error/WrongCEK/WithoutEncKey",
			producerData:  additionalData,
			recipientData: additionalData,
			wrongCEK:      true,
			expectErr:     jwe.ErrInvalidSecret,
		},
		{
			name:          "Error/WrongAdditionalData",
			encrypted:     []byte("encrypted"),
			producerData:  additionalData,
			recipientData: []byte("fake-additional-data"),
			expectErr:     jwe.ErrInvalidSecret,
		},
	}

	for _, preset := range presets {
		key, err := jwk.GenerateAES(preset.keyPreset)
		require.NoError(t, err)

		for _, testCase := range testCases {
			t.Run(preset.name+"/"+testCase.name, func(t *testing.T) {
				t.Parallel()

				encrypter := jwe.NewAESGCMEncryption(&jwe.AESGCMEncryptionConfig{
					CEKManager:     &fakeCEKManager{cek: key.Key(), encrypted: testCase.encrypted},
					AdditionalData: testCase.producerData,
				}, preset.preset)

				producer := jwt.NewProducer(jwt.ProducerConfig{Plugins: []jwt.ProducerPlugin{encrypter}})

				producerClaims := map[string]any{"foo": "bar"}

				token, err := producer.Issue(t.Context(), producerClaims, nil)
				require.NoError(t, err)

				recipientKey := key
				if testCase.wrongCEK {
					recipientKey, err = jwk.GenerateAES(preset.keyPreset)
					require.NoError(t, err)
				}

				decrypter := jwe.NewAESGCMDecryption(&jwe.AESGCMDecryptionConfig{
					CEKDecoder:     &fakeCEKDecoder{cek: recipientKey.Key(), encrypted: testCase.encrypted},
					AdditionalData: testCase.recipientData,
				}, preset.preset)

				recipient := jwt.NewRecipient(jwt.RecipientConfig{Plugins: []jwt.RecipientPlugin{decrypter}})

				var recipientClaims map[string]any

				err = recipient.Consume(t.Context(), token, &recipientClaims)
				require.ErrorIs(t, err, testCase.expectErr)

				if testCase.expectErr == nil {
					require.Equal(t, producerClaims, recipientClaims)

					return
				}

				// A tag that fails to verify rejects the token.
				require.ErrorIs(t, err, jwt.ErrTokenRejected)
			})
		}
	}
}

func TestAESGCMDecryption(t *testing.T) {
	t.Parallel()

	// https://datatracker.ietf.org/doc/html/rfc7516#appendix-A.1
	t.Run("Success/RFC7516A1", func(t *testing.T) {
		t.Parallel()

		example := mustLoadRFCExample(t, "RFC7516A1")

		var keyPayload serializers.RSAPayload

		require.NoError(t, json.Unmarshal(example.JWK, &keyPayload))

		privateKey, _, err := serializers.DecodeRSA(&keyPayload)
		require.NoError(t, err)

		decoder := jwek.NewRSAOAEPKeyEncDecoder(
			&jwek.RSAOAEPKeyEncDecoderConfig{EncKey: privateKey},
			jwek.RSAOAEP, //nolint:staticcheck // The example encrypts the key with RSA-OAEP over SHA-1.
		)
		recipient := jwt.NewRecipient(jwt.RecipientConfig{
			Plugins: []jwt.RecipientPlugin{
				jwe.NewAESGCMDecryption(&jwe.AESGCMDecryptionConfig{CEKDecoder: decoder}, jwe.A256GCM),
			},
			Deserializer: rawDeserializer,
		})

		var plaintext []byte

		require.NoError(t, recipient.Consume(t.Context(), example.Compact(), &plaintext))
		require.Equal(t, example.Plaintext, string(plaintext))
	})

	key, err := jwk.GenerateAES(jwk.A256GCM)
	require.NoError(t, err)

	encrypter := jwe.NewAESGCMEncryption(&jwe.AESGCMEncryptionConfig{
		CEKManager: &fakeCEKManager{cek: key.Key(), encrypted: []byte("encrypted")},
	}, jwe.A256GCM)

	token, err := jwt.NewProducer(jwt.ProducerConfig{Plugins: []jwt.ProducerPlugin{encrypter}}).
		Issue(t.Context(), map[string]any{"foo": "bar"}, nil)
	require.NoError(t, err)

	parts, err := (&jwt.EncryptedTokenDecoder{}).Decode(token)
	require.NoError(t, err)

	decrypter := jwe.NewAESGCMDecryption(&jwe.AESGCMDecryptionConfig{
		CEKDecoder: &fakeCEKDecoder{cek: key.Key(), encrypted: []byte("encrypted")},
	}, jwe.A256GCM)
	recipient := jwt.NewRecipient(jwt.RecipientConfig{Plugins: []jwt.RecipientPlugin{decrypter}})

	t.Run("Error/Compression", func(t *testing.T) {
		t.Parallel()

		header := &jwa.JWH{JWHCommon: jwa.JWHCommon{Enc: jwe.A256GCM.Enc, Zip: jwa.ZipDeflate}}

		_, err := decrypter.Transform(t.Context(), header, token)
		require.ErrorIs(t, err, jwt.ErrUnsupportedTokenFormat)
	})

	testCases := []struct {
		name    string
		malform func(token *jwt.EncryptedToken)

		expectErr error
	}{
		{
			name:      "Error/MalformedSegment/EncKey",
			malform:   func(token *jwt.EncryptedToken) { token.EncKey = testutils.UndecodableSegment },
			expectErr: jwt.ErrUnsupportedTokenFormat,
		},
		{
			name:      "Error/MalformedSegment/IV",
			malform:   func(token *jwt.EncryptedToken) { token.IV = testutils.UndecodableSegment },
			expectErr: jwt.ErrUnsupportedTokenFormat,
		},
		{
			name:      "Error/MalformedSegment/Tag",
			malform:   func(token *jwt.EncryptedToken) { token.Tag = testutils.UndecodableSegment },
			expectErr: jwt.ErrUnsupportedTokenFormat,
		},
		{
			name:      "Error/MalformedSegment/CipherText",
			malform:   func(token *jwt.EncryptedToken) { token.CipherText = testutils.UndecodableSegment },
			expectErr: jwt.ErrUnsupportedTokenFormat,
		},
		{
			// gcm.Open panics on a nonce of the wrong length, so a tampered IV must yield an error instead.
			name:      "Error/ShortIV",
			malform:   func(token *jwt.EncryptedToken) { token.IV = base64.RawURLEncoding.EncodeToString([]byte("short")) },
			expectErr: jwe.ErrInvalidToken,
		},
		{
			// A tag of the wrong length makes a malformed token, apart from an authentication failure.
			name:      "Error/ShortTag",
			malform:   func(token *jwt.EncryptedToken) { token.Tag = base64.RawURLEncoding.EncodeToString([]byte("shorttag")) },
			expectErr: jwe.ErrInvalidToken,
		},
		{
			// The protected header is bound as AAD, so another header that still names the enc fails
			// authenticated decryption.
			name: "Error/TamperedHeader",
			malform: func(token *jwt.EncryptedToken) {
				token.Header = base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"dir","enc":"A256GCM","x":1}`))
			},
			expectErr: jwe.ErrInvalidSecret,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			malformed := *parts
			testCase.malform(&malformed)

			var claims map[string]any
			require.ErrorIs(t, recipient.Consume(t.Context(), malformed.String(), &claims), testCase.expectErr)
		})
	}
}
