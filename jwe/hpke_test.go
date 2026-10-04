package jwe_test

import (
	"crypto/ecdh"
	"crypto/hpke"
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/a-novel-kit/jwt/v2"
	"github.com/a-novel-kit/jwt/v2/jwa"
	"github.com/a-novel-kit/jwt/v2/jwe"
	"github.com/a-novel-kit/jwt/v2/jwk"
	"github.com/a-novel-kit/jwt/v2/jwk/serializers"
	"github.com/a-novel-kit/jwt/v2/testutils"
)

// hpkeVectors are the Integrated Encryption vectors of draft-ietf-jose-hpke-encrypt Appendix A, with
// the plaintext the authors' generator encrypts.
//
// https://datatracker.ietf.org/doc/html/draft-ietf-jose-hpke-encrypt#appendix-A
type hpkeVectors struct {
	Plaintext string `json:"plaintext"`
	Vectors   []struct {
		Alg     jwa.Alg                 `json:"alg"`
		JWK     serializers.ECDHPayload `json:"jwk"`
		Compact string                  `json:"compact"`
	} `json:"vectors"`
}

func TestHPKE(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name string

		keyPreset jwk.ECDHPreset
		preset    jwe.HPKEPreset
	}{
		{name: "HPKE0", keyPreset: jwk.HPKE0, preset: jwe.HPKE0},
		{name: "HPKE1", keyPreset: jwk.HPKE1, preset: jwe.HPKE1},
		{name: "HPKE2", keyPreset: jwk.HPKE2, preset: jwe.HPKE2},
		{name: "HPKE3", keyPreset: jwk.HPKE3, preset: jwe.HPKE3},
		{name: "HPKE4", keyPreset: jwk.HPKE4, preset: jwe.HPKE4},
		{name: "HPKE7", keyPreset: jwk.HPKE7, preset: jwe.HPKE7},
	}

	producerClaims := map[string]any{"foo": "bar"}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			privateKey, publicKey, err := jwk.GenerateECDHKey(testCase.keyPreset)
			require.NoError(t, err)

			producer := jwt.NewProducer(jwt.ProducerConfig{
				Plugins: []jwt.ProducerPlugin{
					jwe.NewHPKEEncryption(&jwe.HPKEEncryptionConfig{RecipientKey: publicKey.Key()}, testCase.preset),
				},
			})
			recipient := jwt.NewRecipient(jwt.RecipientConfig{
				Plugins: []jwt.RecipientPlugin{
					jwe.NewHPKEDecryption(&jwe.HPKEDecryptionConfig{RecipientKey: privateKey.Key()}, testCase.preset),
				},
			})

			first, err := producer.Issue(t.Context(), producerClaims, nil)
			require.NoError(t, err)

			second, err := producer.Issue(t.Context(), producerClaims, nil)
			require.NoError(t, err)

			var recipientClaims map[string]any

			require.NoError(t, recipient.Consume(t.Context(), first, &recipientClaims))
			require.Equal(t, producerClaims, recipientClaims)

			firstToken, err := jwt.DecodeToken(first, &jwt.EncryptedTokenDecoder{})
			require.NoError(t, err)

			secondToken, err := jwt.DecodeToken(second, &jwt.EncryptedTokenDecoder{})
			require.NoError(t, err)

			// Integrated Encryption carries the encapsulated secret as the encrypted key, leaves the IV and
			// tag empty, and encapsulates afresh for every token.
			require.Empty(t, firstToken.IV)
			require.Empty(t, firstToken.Tag)
			require.NotEqual(t, firstToken.EncKey, secondToken.EncKey)

			var header map[string]any

			require.NoError(t, json.Unmarshal(mustDecodeBase64(t, firstToken.Header), &header))
			require.Equal(t, string(testCase.preset.Alg), header["alg"])
			require.NotContains(t, header, "enc")
		})
	}

	t.Run("DraftVectors", func(t *testing.T) {
		t.Parallel()

		raw, err := os.ReadFile("testdata/hpke-integrated.json")
		require.NoError(t, err)

		var fixture hpkeVectors

		require.NoError(t, json.Unmarshal(raw, &fixture))

		presets := map[jwa.Alg]jwe.HPKEPreset{
			jwa.HPKE0: jwe.HPKE0, jwa.HPKE1: jwe.HPKE1, jwa.HPKE2: jwe.HPKE2,
			jwa.HPKE3: jwe.HPKE3, jwa.HPKE4: jwe.HPKE4, jwa.HPKE7: jwe.HPKE7,
		}
		require.Len(t, fixture.Vectors, len(presets))

		for _, vector := range fixture.Vectors {
			privateKey, _, err := serializers.DecodeECDH(&vector.JWK)
			require.NoError(t, err)

			recipient := jwt.NewRecipient(jwt.RecipientConfig{
				Plugins: []jwt.RecipientPlugin{
					jwe.NewHPKEDecryption(&jwe.HPKEDecryptionConfig{RecipientKey: privateKey}, presets[vector.Alg]),
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

func TestHPKEDecryptionRejects(t *testing.T) {
	t.Parallel()

	privateKey, publicKey, err := jwk.GenerateECDHKey(jwk.HPKE0)
	require.NoError(t, err)

	otherPrivateKey, _, err := jwk.GenerateECDHKey(jwk.HPKE0)
	require.NoError(t, err)

	x25519Private, _, err := jwk.GenerateECDHKey(jwk.HPKE3)
	require.NoError(t, err)

	token, err := jwt.NewProducer(jwt.ProducerConfig{
		Plugins: []jwt.ProducerPlugin{
			jwe.NewHPKEEncryption(&jwe.HPKEEncryptionConfig{RecipientKey: publicKey.Key()}, jwe.HPKE0),
		},
	}).Issue(t.Context(), map[string]any{"foo": "bar"}, nil)
	require.NoError(t, err)

	decrypter := jwe.NewHPKEDecryption(&jwe.HPKEDecryptionConfig{RecipientKey: privateKey.Key()}, jwe.HPKE0)
	header := &jwa.JWH{JWHCommon: jwa.JWHCommon{Alg: jwa.HPKE0}}

	testCases := []struct {
		name string

		decrypter *jwe.HPKEDecryption
		header    *jwa.JWH
		token     func(parts *jwt.EncryptedToken)

		expectErr error
	}{
		{
			name:      "OtherAlgorithm",
			decrypter: decrypter,
			header:    &jwa.JWH{JWHCommon: jwa.JWHCommon{Alg: jwa.HPKE7}},
			expectErr: jwt.ErrMismatchRecipientPlugin,
		},
		{
			name:      "WrongKey",
			decrypter: jwe.NewHPKEDecryption(&jwe.HPKEDecryptionConfig{RecipientKey: otherPrivateKey.Key()}, jwe.HPKE0),
			header:    header,
			expectErr: jwe.ErrInvalidSecret,
		},
		{
			name:      "KeyOffCurve",
			decrypter: jwe.NewHPKEDecryption(&jwe.HPKEDecryptionConfig{RecipientKey: x25519Private.Key()}, jwe.HPKE0),
			header:    header,
			expectErr: jwt.ErrInvalidSecretKey,
		},
		{
			name:      "IV",
			decrypter: decrypter,
			header:    header,
			token:     func(parts *jwt.EncryptedToken) { parts.IV = "AAAA" },
			expectErr: jwe.ErrInvalidToken,
		},
		{
			// Valid base64url, but no encapsulated secret: decapsulation fails before any decryption.
			name:      "Undecapsulable",
			decrypter: decrypter,
			header:    header,
			token:     func(parts *jwt.EncryptedToken) { parts.EncKey = "AAAA" },
			expectErr: jwe.ErrInvalidToken,
		},
		{
			name:      "MalformedEncKey",
			decrypter: decrypter,
			header:    header,
			token:     func(parts *jwt.EncryptedToken) { parts.EncKey = testutils.UndecodableSegment },
			expectErr: jwt.ErrUnsupportedTokenFormat,
		},
		{
			name:      "MalformedCipherText",
			decrypter: decrypter,
			header:    header,
			token:     func(parts *jwt.EncryptedToken) { parts.CipherText = testutils.UndecodableSegment },
			expectErr: jwt.ErrUnsupportedTokenFormat,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			parts, err := jwt.DecodeToken(token, &jwt.EncryptedTokenDecoder{})
			require.NoError(t, err)

			if testCase.token != nil {
				testCase.token(parts)
			}

			_, err = testCase.decrypter.Transform(t.Context(), testCase.header, parts.String())
			require.ErrorIs(t, err, testCase.expectErr)
		})
	}
}

// The draft keys "enc", "ek", and "psk_id" on presence, so an empty or null value still counts. Each
// header here is sealed as the AAD of its ciphertext, so only the member check can reject the token:
// the control proves the same construction decrypts.
func TestHPKEDecryptionRefusesHeaderMembers(t *testing.T) {
	t.Parallel()

	privateKey, publicKey, err := jwk.GenerateECDHKey(jwk.HPKE0)
	require.NoError(t, err)

	recipient := jwt.NewRecipient(jwt.RecipientConfig{
		Plugins: []jwt.RecipientPlugin{
			jwe.NewHPKEDecryption(&jwe.HPKEDecryptionConfig{RecipientKey: privateKey.Key()}, jwe.HPKE0),
		},
	})

	testCases := []struct {
		name   string
		header string

		expectErr error
	}{
		{name: "Control", header: `{"alg":"HPKE-0"}`},
		{name: "EmptyPSKID", header: `{"alg":"HPKE-0","psk_id":""}`, expectErr: jwt.ErrUnsupportedTokenFormat},
		{name: "NullPSKID", header: `{"alg":"HPKE-0","psk_id":null}`, expectErr: jwt.ErrUnsupportedTokenFormat},
		{name: "EmptyEnc", header: `{"alg":"HPKE-0","enc":""}`, expectErr: jwt.ErrUnsupportedTokenFormat},
		{name: "NullEK", header: `{"alg":"HPKE-0","ek":null}`, expectErr: jwt.ErrUnsupportedTokenFormat},
		{name: "Zip", header: `{"alg":"HPKE-0","zip":"DEF"}`, expectErr: jwt.ErrUnsupportedTokenFormat},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			token := sealHPKE0(t, publicKey.Key(), testCase.header, []byte(`{"foo":"bar"}`))

			var claims map[string]any

			err := recipient.Consume(t.Context(), token, &claims)
			require.ErrorIs(t, err, testCase.expectErr)

			if testCase.expectErr == nil {
				require.Equal(t, map[string]any{"foo": "bar"}, claims)
			}
		})
	}
}

// sealHPKE0 builds an HPKE-0 Integrated Encryption token for an arbitrary protected header, sealing
// the payload with that header as AAD the way the draft specifies.
func sealHPKE0(t *testing.T, recipientKey *ecdh.PublicKey, header string, payload []byte) string {
	t.Helper()

	publicKey, err := hpke.NewDHKEMPublicKey(recipientKey)
	if err != nil {
		panic(err)
	}

	encapsulated, sender, err := hpke.NewSender(publicKey, hpke.HKDFSHA256(), hpke.AES128GCM(), nil)
	if err != nil {
		panic(err)
	}

	encodedHeader := base64.RawURLEncoding.EncodeToString([]byte(header))

	cipherText, err := sender.Seal([]byte(encodedHeader), payload)
	if err != nil {
		panic(err)
	}

	return jwt.EncryptedToken{
		Header:     encodedHeader,
		EncKey:     base64.RawURLEncoding.EncodeToString(encapsulated),
		CipherText: base64.RawURLEncoding.EncodeToString(cipherText),
	}.String()
}

func TestHPKEEncryptionRejects(t *testing.T) {
	t.Parallel()

	_, publicKey, err := jwk.GenerateECDHKey(jwk.HPKE0)
	require.NoError(t, err)

	_, x25519Public, err := jwk.GenerateECDHKey(jwk.HPKE3)
	require.NoError(t, err)

	testCases := []struct {
		name string

		recipientKey *ecdh.PublicKey
		header       jwa.JWHCommon

		expectErr error
	}{
		{
			name:         "AlgSet",
			recipientKey: publicKey.Key(),
			header:       jwa.JWHCommon{Alg: jwa.RS256},
			expectErr:    jwt.ErrConflictingHeader,
		},
		{
			name:         "EncSet",
			recipientKey: publicKey.Key(),
			header:       jwa.JWHCommon{Enc: jwa.A128GCM},
			expectErr:    jwt.ErrConflictingHeader,
		},
		{name: "NoKey", expectErr: jwt.ErrInvalidSecretKey},
		{name: "KeyOffCurve", recipientKey: x25519Public.Key(), expectErr: jwt.ErrInvalidSecretKey},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			encrypter := jwe.NewHPKEEncryption(&jwe.HPKEEncryptionConfig{RecipientKey: testCase.recipientKey}, jwe.HPKE0)

			_, err := encrypter.Header(t.Context(), &jwa.JWH{JWHCommon: testCase.header})
			require.ErrorIs(t, err, testCase.expectErr)
		})
	}
}
