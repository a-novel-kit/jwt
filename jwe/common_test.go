package jwe_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/a-novel-kit/jwt/v2"
	"github.com/a-novel-kit/jwt/v2/jwa"
	"github.com/a-novel-kit/jwt/v2/jwe"
	"github.com/a-novel-kit/jwt/v2/testutils"
)

// contentEncryptions lists the content encryption plugins, which share the steps under test, with
// the "enc" and content encryption key length of each.
var contentEncryptions = []struct {
	enc    jwa.Enc
	keyLen int

	newEncryption func(manager jwe.CEKManager) jwt.ProducerPlugin
	newDecryption func(decoder jwe.CEKDecoder) jwt.RecipientPlugin
}{
	{
		enc:    jwe.A256GCM.Enc,
		keyLen: jwe.A256GCM.KeyLen,
		newEncryption: func(manager jwe.CEKManager) jwt.ProducerPlugin {
			return jwe.NewAESGCMEncryption(&jwe.AESGCMEncryptionConfig{CEKManager: manager}, jwe.A256GCM)
		},
		newDecryption: func(decoder jwe.CEKDecoder) jwt.RecipientPlugin {
			return jwe.NewAESGCMDecryption(&jwe.AESGCMDecryptionConfig{CEKDecoder: decoder}, jwe.A256GCM)
		},
	},
	{
		enc:    jwe.A128CBCHS256.Enc,
		keyLen: jwe.A128CBCHS256.KeyLen,
		newEncryption: func(manager jwe.CEKManager) jwt.ProducerPlugin {
			return jwe.NewAESCBCEncryption(&jwe.AESCBCEncryptionConfig{CEKManager: manager}, jwe.A128CBCHS256)
		},
		newDecryption: func(decoder jwe.CEKDecoder) jwt.RecipientPlugin {
			return jwe.NewAESCBCDecryption(&jwe.AESCBCDecryptionConfig{CEKDecoder: decoder}, jwe.A128CBCHS256)
		},
	},
}

// TestContentEncryption covers the steps every content encryption plugin shares, around its seal
// call: the "enc" header, key management, and the key length check.
func TestContentEncryption(t *testing.T) {
	t.Parallel()

	for _, plugin := range contentEncryptions {
		testCases := []struct {
			name string

			// header, when set, runs Header; otherwise Transform runs on rawToken.
			header   *jwa.JWH
			manager  *fakeCEKManager
			rawToken string

			expectErr error
		}{
			{
				name:      "Error/EncAlreadySet",
				header:    &jwa.JWH{JWHCommon: jwa.JWHCommon{Enc: plugin.enc}},
				manager:   &fakeCEKManager{},
				expectErr: jwt.ErrConflictingHeader,
			},
			{
				// A CEKManager may pin the token to one enc, which the plugin must then match.
				name:      "Error/ManagerPinsOtherEnc",
				header:    &jwa.JWH{},
				manager:   &fakeCEKManager{pinEnc: jwa.A192GCM},
				expectErr: jwt.ErrConflictingHeader,
			},
			{
				name:      "Error/ManagerHeader",
				header:    &jwa.JWH{},
				manager:   &fakeCEKManager{headerErr: errFoo},
				expectErr: errFoo,
			},
			{
				name:      "Error/MalformedToken",
				manager:   &fakeCEKManager{},
				rawToken:  "header.payload.signature",
				expectErr: jwt.ErrUnsupportedTokenFormat,
			},
			{
				name:      "Error/ComputeCEK",
				manager:   &fakeCEKManager{cekErr: errFoo},
				rawToken:  "e30.e30",
				expectErr: errFoo,
			},
			{
				name:      "Error/CEKLength",
				manager:   &fakeCEKManager{cek: make([]byte, plugin.keyLen-1)},
				rawToken:  "e30.e30",
				expectErr: jwe.ErrInvalidSecret,
			},
			{
				name:      "Error/EncryptCEK",
				manager:   &fakeCEKManager{cek: make([]byte, plugin.keyLen), encryptErr: errFoo},
				rawToken:  "e30.e30",
				expectErr: errFoo,
			},
		}

		for _, testCase := range testCases {
			t.Run(string(plugin.enc)+"/"+testCase.name, func(t *testing.T) {
				t.Parallel()

				encryption := plugin.newEncryption(testCase.manager)

				var err error
				if testCase.header != nil {
					_, err = encryption.Header(t.Context(), testCase.header)
				} else {
					_, err = encryption.Transform(t.Context(), &jwa.JWH{}, testCase.rawToken)
				}

				require.ErrorIs(t, err, testCase.expectErr)
			})
		}
	}
}

// TestContentDecryption covers the steps every content decryption plugin shares, around its open
// call: the "enc" match, the token shape, key management, and the key length check.
func TestContentDecryption(t *testing.T) {
	t.Parallel()

	// A well-formed token with no encrypted key, whose segments decode but never reach the cipher.
	const wellFormed = "e30..AAAA.AAAA.AAAA"

	for _, plugin := range contentEncryptions {
		testCases := []struct {
			name string

			enc      jwa.Enc
			zip      jwa.Zip
			decoder  *fakeCEKDecoder
			rawToken string

			expectErr error
		}{
			{
				// A token for another enc belongs to another plugin.
				name:      "Error/OtherEnc",
				enc:       jwa.A192GCM,
				decoder:   &fakeCEKDecoder{},
				rawToken:  wellFormed,
				expectErr: jwt.ErrMismatchRecipientPlugin,
			},
			{
				name:      "Error/MalformedToken",
				enc:       plugin.enc,
				decoder:   &fakeCEKDecoder{},
				rawToken:  "header.payload.signature",
				expectErr: jwt.ErrUnsupportedTokenFormat,
			},
			{
				// This package performs no decompression.
				name:      "Error/Compression",
				enc:       plugin.enc,
				zip:       jwa.ZipDeflate,
				decoder:   &fakeCEKDecoder{},
				rawToken:  wellFormed,
				expectErr: jwt.ErrUnsupportedTokenFormat,
			},
			{
				name:      "Error/MalformedSegment/EncKey",
				enc:       plugin.enc,
				decoder:   &fakeCEKDecoder{},
				rawToken:  "e30." + testutils.UndecodableSegment + ".AAAA.AAAA.AAAA",
				expectErr: jwt.ErrUnsupportedTokenFormat,
			},
			{
				name:      "Error/MalformedSegment/IV",
				enc:       plugin.enc,
				decoder:   &fakeCEKDecoder{},
				rawToken:  "e30.." + testutils.UndecodableSegment + ".AAAA.AAAA",
				expectErr: jwt.ErrUnsupportedTokenFormat,
			},
			{
				name:      "Error/MalformedSegment/CipherText",
				enc:       plugin.enc,
				decoder:   &fakeCEKDecoder{},
				rawToken:  "e30..AAAA." + testutils.UndecodableSegment + ".AAAA",
				expectErr: jwt.ErrUnsupportedTokenFormat,
			},
			{
				name:      "Error/MalformedSegment/Tag",
				enc:       plugin.enc,
				decoder:   &fakeCEKDecoder{},
				rawToken:  "e30..AAAA.AAAA." + testutils.UndecodableSegment,
				expectErr: jwt.ErrUnsupportedTokenFormat,
			},
			{
				name:      "Error/ComputeCEK",
				enc:       plugin.enc,
				decoder:   &fakeCEKDecoder{encrypted: []byte("another key")},
				rawToken:  wellFormed,
				expectErr: errFoo,
			},
			{
				name:      "Error/CEKLength",
				enc:       plugin.enc,
				decoder:   &fakeCEKDecoder{cek: make([]byte, plugin.keyLen+1)},
				rawToken:  wellFormed,
				expectErr: jwe.ErrInvalidSecret,
			},
		}

		for _, testCase := range testCases {
			t.Run(string(plugin.enc)+"/"+testCase.name, func(t *testing.T) {
				t.Parallel()

				header := &jwa.JWH{JWHCommon: jwa.JWHCommon{Enc: testCase.enc, Zip: testCase.zip}}

				_, err := plugin.newDecryption(testCase.decoder).Transform(t.Context(), header, testCase.rawToken)
				require.ErrorIs(t, err, testCase.expectErr)
			})
		}

		// A lenient decoder reads a tag with an unused trailing bit set as the same bytes, so accepting it
		// would turn one issued token into several strings that all decrypt.
		t.Run(string(plugin.enc)+"/Error/NonCanonicalTag", func(t *testing.T) {
			t.Parallel()

			cek := make([]byte, plugin.keyLen)
			producer := jwt.NewProducer(jwt.ProducerConfig{
				Plugins: []jwt.ProducerPlugin{plugin.newEncryption(&fakeCEKManager{cek: cek})},
			})
			recipient := jwt.NewRecipient(jwt.RecipientConfig{
				Plugins: []jwt.RecipientPlugin{plugin.newDecryption(&fakeCEKDecoder{cek: cek})},
			})

			token, err := producer.Issue(t.Context(), map[string]any{"foo": "bar"}, nil)
			require.NoError(t, err)

			var claims map[string]any

			require.NoError(t, recipient.Consume(t.Context(), token, &claims))

			parts, err := (&jwt.EncryptedTokenDecoder{}).Decode(token)
			require.NoError(t, err)

			// Both tags hold 16 bytes, which leave unused bits. mustDecodeBase64 decodes leniently.
			tag, ok := nonCanonical(parts.Tag)
			require.True(t, ok)
			require.Equal(t, mustDecodeBase64(t, parts.Tag), mustDecodeBase64(t, tag))

			parts.Tag = tag
			require.ErrorIs(t, recipient.Consume(t.Context(), parts.String(), &claims), jwt.ErrUnsupportedTokenFormat)
		})
	}
}
