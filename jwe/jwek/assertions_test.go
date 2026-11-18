package jwek_test

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/a-novel-kit/jwt/v2"
	"github.com/a-novel-kit/jwt/v2/jwa"
	"github.com/a-novel-kit/jwt/v2/jwe"
	"github.com/a-novel-kit/jwt/v2/jwe/jwek"
)

// cbcPresets and gcmPresets map each "enc" to the jwe preset that encrypts with it.
var (
	cbcPresets = map[jwa.Enc]jwe.AESCBCPreset{
		jwa.A128CBC: jwe.A128CBCHS256,
		jwa.A192CBC: jwe.A192CBCHS384,
		jwa.A256CBC: jwe.A256CBCHS512,
	}
	gcmPresets = map[jwa.Enc]jwe.AESGCMPreset{
		jwa.A128GCM: jwe.A128GCM,
		jwa.A192GCM: jwe.A192GCM,
		jwa.A256GCM: jwe.A256GCM,
	}
)

// TestCEKManager issues tokens through every key manager and reads them back through its decoder.
// RFC 7516 §5.1 draws a fresh content encryption key for every token, and RFC 7518 §4.6 a fresh
// ephemeral key. A manager and decoder tested alone share one header object, so only a token issued
// by a Producer and read by a Recipient proves the per-token parameters reach the serialized header.
//
// DirectKeyManager is left out, since it reuses one content encryption key by design. It has its own
// TestDirectEncryption.
func TestCEKManager(t *testing.T) {
	t.Parallel()

	type keyManagementCase struct {
		name string

		// enc is the content encryption of the token, which ECDH-ES pins.
		enc jwa.Enc

		manager jwe.CEKManager
		decoder jwe.CEKDecoder
		// wrongDecoder holds a key other than the one the manager issues tokens to.
		wrongDecoder jwe.CEKDecoder
	}

	var testCases []keyManagementCase //nolint:prealloc // Built once, from the preset lists below.

	for _, preset := range []jwek.KeyWrapPreset{jwek.A128KW, jwek.A192KW, jwek.A256KW} {
		wrapKey := randomKey(preset.KeyLen)

		testCases = append(testCases, keyManagementCase{
			name:         string(preset.Alg),
			enc:          jwa.A256GCM,
			manager:      jwek.NewAESKWManager(&jwek.AESKWManagerConfig{WrapKey: wrapKey}, preset),
			decoder:      jwek.NewAESKWDecoder(&jwek.AESKWDecoderConfig{WrapKey: wrapKey}, preset),
			wrongDecoder: jwek.NewAESKWDecoder(&jwek.AESKWDecoderConfig{WrapKey: randomKey(preset.KeyLen)}, preset),
		})
	}

	for _, preset := range []jwek.KeyWrapPreset{jwek.A128GCMKW, jwek.A192GCMKW, jwek.A256GCMKW} {
		wrapKey := randomKey(preset.KeyLen)

		testCases = append(testCases, keyManagementCase{
			name:         string(preset.Alg),
			enc:          jwa.A256GCM,
			manager:      jwek.NewAESGCMKWManager(&jwek.AESGCMKWManagerConfig{WrapKey: wrapKey}, preset),
			decoder:      jwek.NewAESGCMKWDecoder(&jwek.AESGCMKWDecoderConfig{WrapKey: wrapKey}, preset),
			wrongDecoder: jwek.NewAESGCMKWDecoder(&jwek.AESGCMKWDecoderConfig{WrapKey: randomKey(preset.KeyLen)}, preset),
		})
	}

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	otherRSAKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	for _, preset := range []jwek.RSAOAEPKeyEncPreset{jwek.RSAOAEP, jwek.RSAOAEP256} {
		testCases = append(testCases, keyManagementCase{
			name:         string(preset.Alg),
			enc:          jwa.A256GCM,
			manager:      jwek.NewRSAOAEPKeyEncManager(&jwek.RSAOAEPKeyEncManagerConfig{EncKey: &rsaKey.PublicKey}, preset),
			decoder:      jwek.NewRSAOAEPKeyEncDecoder(&jwek.RSAOAEPKeyEncDecoderConfig{EncKey: rsaKey}, preset),
			wrongDecoder: jwek.NewRSAOAEPKeyEncDecoder(&jwek.RSAOAEPKeyEncDecoderConfig{EncKey: otherRSAKey}, preset),
		})
	}

	for _, preset := range []jwek.PBES2KeyEncKWPreset{jwek.PBES2A128KW, jwek.PBES2A192KW, jwek.PBES2A256KW} {
		testCases = append(testCases, keyManagementCase{
			name: string(preset.Alg),
			enc:  jwa.A256GCM,
			manager: jwek.NewPBES2KeyEncKWManager(
				&jwek.PBES2KeyEncKWManagerConfig{Secret: "a password", Iterations: 1000}, preset,
			),
			decoder:      jwek.NewPBES2KeyEncKWDecoder(&jwek.PBES2KeyEncKWDecoderConfig{Secret: "a password"}, preset),
			wrongDecoder: jwek.NewPBES2KeyEncKWDecoder(&jwek.PBES2KeyEncKWDecoderConfig{Secret: "another password"}, preset),
		})
	}

	ecdhPresets := []jwek.ECDHKeyAgrPreset{
		jwek.ECDHESA128CBC, jwek.ECDHESA192CBC, jwek.ECDHESA256CBC,
		jwek.ECDHESA128GCM, jwek.ECDHESA192GCM, jwek.ECDHESA256GCM,
	}

	for _, curve := range []ecdh.Curve{ecdh.X25519(), ecdh.P256(), ecdh.P384(), ecdh.P521()} {
		recipientKey, otherKey := mustGenerateECDH(t, curve), mustGenerateECDH(t, curve)

		for _, preset := range ecdhPresets {
			testCases = append(testCases, keyManagementCase{
				name: "ECDH-ES/" + string(preset.Enc) + "/" + fmt.Sprint(curve),
				enc:  preset.Enc,
				manager: jwek.NewECDHKeyAgrManager(
					&jwek.ECDHKeyAgrManagerConfig{RecipientKey: recipientKey.PublicKey()}, preset,
				),
				decoder:      jwek.NewECDHKeyAgrDecoder(&jwek.ECDHKeyAgrDecoderConfig{RecipientKey: recipientKey}, preset),
				wrongDecoder: jwek.NewECDHKeyAgrDecoder(&jwek.ECDHKeyAgrDecoderConfig{RecipientKey: otherKey}, preset),
			})
		}

		for _, preset := range []jwek.KeyWrapPreset{jwek.ECDHESA128KW, jwek.ECDHESA192KW, jwek.ECDHESA256KW} {
			testCases = append(testCases, keyManagementCase{
				name: string(preset.Alg) + "/" + fmt.Sprint(curve),
				enc:  jwa.A256GCM,
				manager: jwek.NewECDHKeyAgrKWManager(
					&jwek.ECDHKeyAgrKWManagerConfig{RecipientKey: recipientKey.PublicKey()}, preset,
				),
				decoder:      jwek.NewECDHKeyAgrKWDecoder(&jwek.ECDHKeyAgrKWDecoderConfig{RecipientKey: recipientKey}, preset),
				wrongDecoder: jwek.NewECDHKeyAgrKWDecoder(&jwek.ECDHKeyAgrKWDecoderConfig{RecipientKey: otherKey}, preset),
			})
		}
	}

	hpkePresets := []jwek.HPKEKeyEncPreset{jwek.HPKE0KE, jwek.HPKE1KE, jwek.HPKE2KE, jwek.HPKE3KE, jwek.HPKE7KE}

	for _, preset := range hpkePresets {
		recipientKey, otherKey := mustGenerateECDH(t, preset.Curve), mustGenerateECDH(t, preset.Curve)

		testCases = append(testCases, keyManagementCase{
			name: string(preset.Alg),
			enc:  jwa.A256GCM,
			manager: jwek.NewHPKEKeyEncManager(
				&jwek.HPKEKeyEncManagerConfig{RecipientKey: recipientKey.PublicKey()}, preset,
			),
			decoder:      jwek.NewHPKEKeyEncDecoder(&jwek.HPKEKeyEncDecoderConfig{RecipientKey: recipientKey}, preset),
			wrongDecoder: jwek.NewHPKEKeyEncDecoder(&jwek.HPKEKeyEncDecoderConfig{RecipientKey: otherKey}, preset),
		})
	}

	claims := map[string]any{"sub": "user"}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			encryption, decryption := contentPlugins(testCase.enc, testCase.manager, testCase.decoder)
			producer := jwt.NewProducer(jwt.ProducerConfig{Plugins: []jwt.ProducerPlugin{encryption}})

			token, err := producer.Issue(t.Context(), claims, nil)
			require.NoError(t, err)

			t.Run("Success", func(t *testing.T) {
				t.Parallel()

				recipient := jwt.NewRecipient(jwt.RecipientConfig{Plugins: []jwt.RecipientPlugin{decryption}})

				var decoded map[string]any

				require.NoError(t, recipient.Consume(t.Context(), token, &decoded))
				require.Equal(t, claims, decoded)
			})

			t.Run("Success/FreshKeyMaterial", func(t *testing.T) {
				t.Parallel()

				other, err := producer.Issue(t.Context(), claims, nil)
				require.NoError(t, err)

				first, err := (&jwt.EncryptedTokenDecoder{}).Decode(token)
				require.NoError(t, err)

				second, err := (&jwt.EncryptedTokenDecoder{}).Decode(other)
				require.NoError(t, err)

				// Every token carries its own key material: a wrapped CEK, an ephemeral key, or both.
				require.NotEqual(t, first.Header+first.EncKey, second.Header+second.EncKey)
			})

			t.Run("Error/WrongKey", func(t *testing.T) {
				t.Parallel()

				_, wrongDecryption := contentPlugins(testCase.enc, testCase.manager, testCase.wrongDecoder)
				recipient := jwt.NewRecipient(jwt.RecipientConfig{Plugins: []jwt.RecipientPlugin{wrongDecryption}})

				var decoded map[string]any

				require.ErrorIs(t, recipient.Consume(t.Context(), token, &decoded), jwt.ErrTokenRejected)
			})
		})
	}
}

// contentPlugins returns the jwe plugins that encrypt a payload with enc under the key manager gives,
// and decrypt it under the key decoder recovers.
func contentPlugins(
	enc jwa.Enc, manager jwe.CEKManager, decoder jwe.CEKDecoder,
) (jwt.ProducerPlugin, jwt.RecipientPlugin) {
	if preset, ok := cbcPresets[enc]; ok {
		return jwe.NewAESCBCEncryption(&jwe.AESCBCEncryptionConfig{CEKManager: manager}, preset),
			jwe.NewAESCBCDecryption(&jwe.AESCBCDecryptionConfig{CEKDecoder: decoder}, preset)
	}

	preset := gcmPresets[enc]

	return jwe.NewAESGCMEncryption(&jwe.AESGCMEncryptionConfig{CEKManager: manager}, preset),
		jwe.NewAESGCMDecryption(&jwe.AESGCMDecryptionConfig{CEKDecoder: decoder}, preset)
}
