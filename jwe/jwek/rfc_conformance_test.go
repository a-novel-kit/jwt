package jwek_test

import (
	"crypto/ecdh"
	"crypto/rand"
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
)

// These assert the two encoding rules against the specification text rather than against the
// library's own round trip. Both defects were invisible precisely because producer and consumer
// agreed on the wrong value, so any test that encrypts and then decrypts passes either way.

func TestPBES2AppliesItsDefaults(t *testing.T) {
	t.Parallel()

	// A zero SaltSize used to produce a zero-length salt with no error — rand.Read on an empty
	// slice returns (0, nil) — so every token from one password shared a wrap key. A zero
	// Iterations produced p2c=0, which the decoder rejects, so the token was undecryptable and
	// only the recipient found out.
	manager := jwek.NewPBES2KeyEncKWManager(&jwek.PBES2KeyEncKWManagerConfig{
		Secret: "a password",
	}, jwek.PBES2A128KW)

	first, err := manager.SetHeader(t.Context(), &jwa.JWH{})
	require.NoError(t, err)

	saltInput, err := base64.RawURLEncoding.DecodeString(first.P2S)
	require.NoError(t, err)
	require.Len(t, saltInput, jwek.DefaultPBES2SaltSize)
	require.Equal(t, jwek.DefaultPBES2Iterations, first.P2C)

	second, err := manager.SetHeader(t.Context(), &jwa.JWH{})
	require.NoError(t, err)
	require.NotEqual(t, first.P2S, second.P2S, "each token must carry a fresh salt")
}

// RFC 7518 §4.6.1.2 and §4.6.1.3 define apu and apv as base64url-encoded values. The header must
// carry the encoded form, and the KDF must mix in the decoded bytes.
func TestECDHAgreementInfoIsEncodedInTheHeader(t *testing.T) {
	t.Parallel()

	const (
		producerInfo  = "Alice"
		recipientInfo = "Bob"
	)

	_, recipientPublicKey, err := jwk.GenerateECDH()
	require.NoError(t, err)

	manager := jwek.NewECDHKeyAgrManager(&jwek.ECDHKeyAgrManagerConfig{
		RecipientKey:  recipientPublicKey.Key(),
		ProducerInfo:  producerInfo,
		RecipientInfo: recipientInfo,
	}, jwek.ECDHESA128GCM)

	header, err := manager.SetHeader(t.Context(), &jwa.JWH{})
	require.NoError(t, err)

	require.NotEqual(t, producerInfo, header.APU, "apu travels encoded, not as the raw string")

	decodedAPU, err := base64.RawURLEncoding.DecodeString(header.APU)
	require.NoError(t, err, "apu must be valid base64url")
	require.Equal(t, producerInfo, string(decodedAPU))

	decodedAPV, err := base64.RawURLEncoding.DecodeString(header.APV)
	require.NoError(t, err, "apv must be valid base64url")
	require.Equal(t, recipientInfo, string(decodedAPV))
}

// RFC 7516 §5.1 draws a fresh content encryption key for every token, and RFC 7518 §4.6 a fresh
// ephemeral key. A manager and decoder tested alone share one header object, so only a token issued
// by a Producer and read by a Recipient proves the per-token parameters reach the serialized header.
func TestKeyManagementPerToken(t *testing.T) {
	t.Parallel()

	wrapKey, err := jwk.GenerateAES(jwk.A256KW)
	require.NoError(t, err)

	gcmWrapKey, err := jwk.GenerateAES(jwk.A256GCMKW)
	require.NoError(t, err)

	rsaPrivateKey, rsaPublicKey, err := jwk.GenerateRSA(jwk.RSAOAEP256)
	require.NoError(t, err)

	ecdhPrivateKey, ecdhPublicKey, err := jwk.GenerateECDH()
	require.NoError(t, err)

	testCases := []struct {
		name string

		manager jwe.CEKManager
		decoder jwe.CEKDecoder
	}{
		{
			name:    "AESKW",
			manager: jwek.NewAESKWManager(&jwek.AESKWManagerConfig{WrapKey: wrapKey.Key()}, jwek.A256KW),
			decoder: jwek.NewAESKWDecoder(&jwek.AESKWDecoderConfig{WrapKey: wrapKey.Key()}, jwek.A256KW),
		},
		{
			name:    "AESGCMKW",
			manager: jwek.NewAESGCMKWManager(&jwek.AESGCMKWManagerConfig{WrapKey: gcmWrapKey.Key()}, jwek.A256GCMKW),
			decoder: jwek.NewAESGCMKWDecoder(&jwek.AESGCMKWDecoderConfig{WrapKey: gcmWrapKey.Key()}, jwek.A256GCMKW),
		},
		{
			name: "RSAOAEP256",
			manager: jwek.NewRSAOAEPKeyEncManager(
				&jwek.RSAOAEPKeyEncManagerConfig{EncKey: rsaPublicKey.Key()}, jwek.RSAOAEP256,
			),
			decoder: jwek.NewRSAOAEPKeyEncDecoder(
				&jwek.RSAOAEPKeyEncDecoderConfig{EncKey: rsaPrivateKey.Key()}, jwek.RSAOAEP256,
			),
		},
		{
			name: "PBES2",
			manager: jwek.NewPBES2KeyEncKWManager(
				&jwek.PBES2KeyEncKWManagerConfig{Secret: "a password", Iterations: 1000}, jwek.PBES2A256KW,
			),
			decoder: jwek.NewPBES2KeyEncKWDecoder(&jwek.PBES2KeyEncKWDecoderConfig{Secret: "a password"}, jwek.PBES2A256KW),
		},
		{
			name: "ECDHES",
			manager: jwek.NewECDHKeyAgrManager(
				&jwek.ECDHKeyAgrManagerConfig{RecipientKey: ecdhPublicKey.Key()}, jwek.ECDHESA256GCM,
			),
			decoder: jwek.NewECDHKeyAgrDecoder(
				&jwek.ECDHKeyAgrDecoderConfig{RecipientKey: ecdhPrivateKey.Key()}, jwek.ECDHESA256GCM,
			),
		},
		{
			name: "ECDHESKW",
			manager: jwek.NewECDHKeyAgrKWManager(
				&jwek.ECDHKeyAgrKWManagerConfig{RecipientKey: ecdhPublicKey.Key()}, jwek.ECDHESA256KW,
			),
			decoder: jwek.NewECDHKeyAgrKWDecoder(
				&jwek.ECDHKeyAgrKWDecoderConfig{RecipientKey: ecdhPrivateKey.Key()}, jwek.ECDHESA256KW,
			),
		},
	}

	claims := map[string]any{"sub": "user"}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			producer := jwt.NewProducer(jwt.ProducerConfig{
				Plugins: []jwt.ProducerPlugin{
					jwe.NewAESGCMEncryption(&jwe.AESGCMEncryptionConfig{CEKManager: testCase.manager}, jwe.A256GCM),
				},
			})
			recipient := jwt.NewRecipient(jwt.RecipientConfig{
				Plugins: []jwt.RecipientPlugin{
					jwe.NewAESGCMDecryption(&jwe.AESGCMDecryptionConfig{CEKDecoder: testCase.decoder}, jwe.A256GCM),
				},
			})

			first, err := producer.Issue(t.Context(), claims, nil)
			require.NoError(t, err)

			second, err := producer.Issue(t.Context(), claims, nil)
			require.NoError(t, err)

			var decoded map[string]any

			require.NoError(t, recipient.Consume(t.Context(), first, &decoded))
			require.Equal(t, claims, decoded)

			firstToken, err := jwt.DecodeToken(first, &jwt.EncryptedTokenDecoder{})
			require.NoError(t, err)

			secondToken, err := jwt.DecodeToken(second, &jwt.EncryptedTokenDecoder{})
			require.NoError(t, err)

			// Every token carries its own key material: a wrapped CEK, an ephemeral key, or both.
			require.NotEqual(t, firstToken.Header+firstToken.EncKey, secondToken.Header+secondToken.EncKey)
		})
	}
}

// RFC 7518 §4.6.1.1 makes "epk" a JSON Web Key, and RFC 7517 §4.1 makes "kty" its one required
// member. The decoder reads only the curve and point, so a round trip passes without it.
func TestECDHEphemeralKeyNamesItsKeyType(t *testing.T) {
	t.Parallel()

	_, recipientPublicKey, err := jwk.GenerateECDH()
	require.NoError(t, err)

	manager := jwek.NewECDHKeyAgrManager(
		&jwek.ECDHKeyAgrManagerConfig{RecipientKey: recipientPublicKey.Key()}, jwek.ECDHESA128GCM,
	)

	header, err := manager.SetHeader(t.Context(), &jwa.JWH{})
	require.NoError(t, err)

	_, err = manager.ComputeCEK(t.Context(), header)
	require.NoError(t, err)

	epk, err := json.Marshal(header.EPK)
	require.NoError(t, err)

	var members map[string]any

	require.NoError(t, json.Unmarshal(epk, &members))
	require.Equal(t, "OKP", members["kty"])
}

func TestKeyManagementRejects(t *testing.T) {
	t.Parallel()

	wrapKey, err := jwk.GenerateAES(jwk.A256KW)
	require.NoError(t, err)

	p256Key, err := ecdh.P256().GenerateKey(rand.Reader)
	require.NoError(t, err)

	t.Run("UnknownEnc", func(t *testing.T) {
		t.Parallel()

		// The CEK's size comes from "enc", so a manager cannot draw one for an algorithm it does not know.
		manager := jwek.NewAESKWManager(&jwek.AESKWManagerConfig{WrapKey: wrapKey.Key()}, jwek.A256KW)

		_, err := manager.ComputeCEK(t.Context(), &jwa.JWH{JWHCommon: jwa.JWHCommon{Enc: "C20P"}})
		require.ErrorIs(t, err, jwt.ErrUnsupportedTokenFormat)
	})

	t.Run("RecipientCurve", func(t *testing.T) {
		t.Parallel()

		// The "epk" serializes X25519 points only, so a key on another curve is refused up front.
		manager := jwek.NewECDHKeyAgrManager(
			&jwek.ECDHKeyAgrManagerConfig{RecipientKey: p256Key.PublicKey()}, jwek.ECDHESA256GCM,
		)

		_, err := manager.ComputeCEK(t.Context(), &jwa.JWH{})
		require.ErrorIs(t, err, serializers.ErrUnsupportedCurve)
	})
}
