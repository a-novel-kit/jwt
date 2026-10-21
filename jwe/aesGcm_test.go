package jwe_test

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/a-novel-kit/jwt/v2"
	"github.com/a-novel-kit/jwt/v2/jwa"
	"github.com/a-novel-kit/jwt/v2/jwe"
	"github.com/a-novel-kit/jwt/v2/jwk"
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
				}
			})
		}
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

func TestAESGCMBadTag(t *testing.T) {
	t.Parallel()

	key, err := jwk.GenerateAES(jwk.A256GCM)
	require.NoError(t, err)

	encrypter := jwe.NewAESGCMEncryption(&jwe.AESGCMEncryptionConfig{
		CEKManager: &fakeCEKManager{cek: key.Key(), encrypted: []byte("encrypted")},
	}, jwe.A256GCM)
	producer := jwt.NewProducer(jwt.ProducerConfig{Plugins: []jwt.ProducerPlugin{encrypter}})

	token, err := producer.Issue(t.Context(), map[string]any{"foo": "bar"}, nil)
	require.NoError(t, err)

	// A wrong-length tag is a malformed token, distinct from an authentication failure.
	parts, err := jwt.DecodeToken(token, &jwt.EncryptedTokenDecoder{})
	require.NoError(t, err)

	parts.Tag = base64.RawURLEncoding.EncodeToString([]byte("shorttag"))

	decrypter := jwe.NewAESGCMDecryption(&jwe.AESGCMDecryptionConfig{
		CEKDecoder: &fakeCEKDecoder{cek: key.Key(), encrypted: []byte("encrypted")},
	}, jwe.A256GCM)
	recipient := jwt.NewRecipient(jwt.RecipientConfig{Plugins: []jwt.RecipientPlugin{decrypter}})

	var claims map[string]any
	require.ErrorIs(t, recipient.Consume(t.Context(), parts.String(), &claims), jwe.ErrInvalidToken)
}

func TestAESGCMHeaderBound(t *testing.T) {
	t.Parallel()

	key, err := jwk.GenerateAES(jwk.A256GCM)
	require.NoError(t, err)

	encrypter := jwe.NewAESGCMEncryption(&jwe.AESGCMEncryptionConfig{
		CEKManager: &fakeCEKManager{cek: key.Key(), encrypted: []byte("encrypted")},
	}, jwe.A256GCM)
	producer := jwt.NewProducer(jwt.ProducerConfig{Plugins: []jwt.ProducerPlugin{encrypter}})

	token, err := producer.Issue(t.Context(), map[string]any{"foo": "bar"}, nil)
	require.NoError(t, err)

	// The protected header is bound as AAD, so swapping it for a different but still enc-valid header
	// fails decryption.
	parts, err := jwt.DecodeToken(token, &jwt.EncryptedTokenDecoder{})
	require.NoError(t, err)

	parts.Header = base64.RawURLEncoding.EncodeToString([]byte(`{"enc":"A256GCM","x":1}`))

	decrypter := jwe.NewAESGCMDecryption(&jwe.AESGCMDecryptionConfig{
		CEKDecoder: &fakeCEKDecoder{cek: key.Key(), encrypted: []byte("encrypted")},
	}, jwe.A256GCM)
	recipient := jwt.NewRecipient(jwt.RecipientConfig{Plugins: []jwt.RecipientPlugin{decrypter}})

	var claims map[string]any

	// The tamper surfaces as an authenticated-decryption error.
	require.ErrorIs(t, recipient.Consume(t.Context(), parts.String(), &claims), jwe.ErrInvalidSecret)
}

func TestAESGCMRejectsCompression(t *testing.T) {
	t.Parallel()

	decrypter := jwe.NewAESGCMDecryption(&jwe.AESGCMDecryptionConfig{CEKDecoder: &fakeCEKDecoder{}}, jwe.A256GCM)

	header := &jwa.JWH{JWHCommon: jwa.JWHCommon{Enc: jwe.A256GCM.Enc, Zip: jwa.ZipDeflate}}

	_, err := decrypter.Transform(t.Context(), header, "a.b.c.d.e")
	require.ErrorIs(t, err, jwt.ErrUnsupportedTokenFormat)
}

func TestAESGCMMalformedSegment(t *testing.T) {
	t.Parallel()

	key, err := jwk.GenerateAES(jwk.A256GCM)
	require.NoError(t, err)

	encrypter := jwe.NewAESGCMEncryption(&jwe.AESGCMEncryptionConfig{
		CEKManager: &fakeCEKManager{cek: key.Key(), encrypted: []byte("encrypted")},
	}, jwe.A256GCM)
	producer := jwt.NewProducer(jwt.ProducerConfig{Plugins: []jwt.ProducerPlugin{encrypter}})

	token, err := producer.Issue(t.Context(), map[string]any{"foo": "bar"}, nil)
	require.NoError(t, err)

	decrypter := jwe.NewAESGCMDecryption(&jwe.AESGCMDecryptionConfig{
		CEKDecoder: &fakeCEKDecoder{cek: key.Key(), encrypted: []byte("encrypted")},
	}, jwe.A256GCM)
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
