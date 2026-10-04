package jwek_test

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

	_, recipientPublicKey, err := jwk.GenerateECDHKey(jwk.ECDHESX25519)
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

	ecdhPrivateKey, ecdhPublicKey, err := jwk.GenerateECDHKey(jwk.ECDHESX25519)
	require.NoError(t, err)

	p256PrivateKey, p256PublicKey, err := jwk.GenerateECDHKey(jwk.ECDHESP256)
	require.NoError(t, err)

	p521PrivateKey, p521PublicKey, err := jwk.GenerateECDHKey(jwk.ECDHESP521)
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
		{
			name: "ECDHES/P256",
			manager: jwek.NewECDHKeyAgrManager(
				&jwek.ECDHKeyAgrManagerConfig{RecipientKey: p256PublicKey.Key()}, jwek.ECDHESA256GCM,
			),
			decoder: jwek.NewECDHKeyAgrDecoder(
				&jwek.ECDHKeyAgrDecoderConfig{RecipientKey: p256PrivateKey.Key()}, jwek.ECDHESA256GCM,
			),
		},
		{
			name: "ECDHESKW/P521",
			manager: jwek.NewECDHKeyAgrKWManager(
				&jwek.ECDHKeyAgrKWManagerConfig{RecipientKey: p521PublicKey.Key()}, jwek.ECDHESA256KW,
			),
			decoder: jwek.NewECDHKeyAgrKWDecoder(
				&jwek.ECDHKeyAgrKWDecoderConfig{RecipientKey: p521PrivateKey.Key()}, jwek.ECDHESA256KW,
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

	testCases := []struct {
		name string

		preset jwk.ECDHPreset
		kty    string
	}{
		{name: "X25519", preset: jwk.ECDHESX25519, kty: "OKP"},
		{name: "P256", preset: jwk.ECDHESP256, kty: "EC"},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			_, recipientPublicKey, err := jwk.GenerateECDHKey(testCase.preset)
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
			require.Equal(t, testCase.kty, members["kty"])
		})
	}
}

// RFC 7518 Appendix C derives a content key from Alice's ephemeral P-256 key and Bob's static one.
// Decoding Bob's side of it pins the whole path: the "EC" epk, the x-coordinate shared secret, and
// the Concat KDF.
//
// https://datatracker.ietf.org/doc/html/rfc7518#appendix-C
func TestECDHKeyAgrDecoderRFC7518Vector(t *testing.T) {
	t.Parallel()

	bobKey, err := json.Marshal(map[string]any{
		"kty": "EC", "use": "enc", "key_ops": []string{"deriveKey"}, "alg": "ECDH-ES",
		"crv": "P-256",
		"x":   "weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ",
		"y":   "e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck",
		"d":   "VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw",
	})
	require.NoError(t, err)

	var bobJWK jwa.JWK

	require.NoError(t, json.Unmarshal(bobKey, &bobJWK))

	bobPrivateKey, _, err := jwk.ConsumeECDHKey(&bobJWK, jwk.ECDHESP256)
	require.NoError(t, err)

	var header jwa.JWH

	require.NoError(t, json.Unmarshal([]byte(`{
		"alg":"ECDH-ES","enc":"A128GCM","apu":"QWxpY2U","apv":"Qm9i",
		"epk":{"kty":"EC","crv":"P-256",
			"x":"gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0",
			"y":"SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps"}
	}`), &header))

	decoder := jwek.NewECDHKeyAgrDecoder(
		&jwek.ECDHKeyAgrDecoderConfig{RecipientKey: bobPrivateKey.Key()}, jwek.ECDHESA128GCM,
	)

	cek, err := decoder.ComputeCEK(t.Context(), &header, nil)
	require.NoError(t, err)
	require.Equal(t, "VqqN6vgjbSBcIijNcacQGg", base64.RawURLEncoding.EncodeToString(cek))
}

func TestKeyManagementRejects(t *testing.T) {
	t.Parallel()

	wrapKey, err := jwk.GenerateAES(jwk.A256KW)
	require.NoError(t, err)

	t.Run("UnknownEnc", func(t *testing.T) {
		t.Parallel()

		// The CEK's size comes from "enc", so a manager cannot draw one for an algorithm it does not know.
		manager := jwek.NewAESKWManager(&jwek.AESKWManagerConfig{WrapKey: wrapKey.Key()}, jwek.A256KW)

		_, err := manager.ComputeCEK(t.Context(), &jwa.JWH{JWHCommon: jwa.JWHCommon{Enc: "C20P"}})
		require.ErrorIs(t, err, jwt.ErrUnsupportedTokenFormat)
	})

	t.Run("NoRecipientKey", func(t *testing.T) {
		t.Parallel()

		manager := jwek.NewECDHKeyAgrManager(&jwek.ECDHKeyAgrManagerConfig{}, jwek.ECDHESA256GCM)

		_, err := manager.ComputeCEK(t.Context(), &jwa.JWH{})
		require.ErrorIs(t, err, jwt.ErrInvalidSecretKey)
	})
}
