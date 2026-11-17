package jwek_test

import (
	"crypto/ecdh"
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

func TestECDHKeyAgrManager(t *testing.T) {
	t.Parallel()

	// RFC 7518 §4.6.1.2 and §4.6.1.3 define apu and apv as base64url-encoded values. The header must
	// carry the encoded form, and the KDF must mix in the decoded bytes.
	t.Run("Success/EncodedAgreementInfo", func(t *testing.T) {
		t.Parallel()

		manager := jwek.NewECDHKeyAgrManager(&jwek.ECDHKeyAgrManagerConfig{
			RecipientKey:  mustGenerateECDH(t, ecdh.X25519()).PublicKey(),
			ProducerInfo:  "Alice",
			RecipientInfo: "Bob",
		}, jwek.ECDHESA128GCM)

		header, err := manager.SetHeader(t.Context(), &jwa.JWH{})
		require.NoError(t, err)

		require.NotEqual(t, "Alice", header.APU, "apu travels encoded, not as the raw string")
		require.Equal(t, "Alice", string(mustDecodeBase64(t, header.APU)))
		require.Equal(t, "Bob", string(mustDecodeBase64(t, header.APV)))
	})

	// RFC 7518 §4.6.1.1 makes "epk" a JSON Web Key, and RFC 7517 §4.1 makes "kty" its one required
	// member. The decoder reads only the curve and point, so a round trip passes without it.
	epkCases := []struct {
		name string

		curve ecdh.Curve
		kty   string
	}{
		{name: "Success/EPKKeyType/X25519", curve: ecdh.X25519(), kty: "OKP"},
		{name: "Success/EPKKeyType/P256", curve: ecdh.P256(), kty: "EC"},
	}

	for _, testCase := range epkCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			manager := jwek.NewECDHKeyAgrManager(
				&jwek.ECDHKeyAgrManagerConfig{RecipientKey: mustGenerateECDH(t, testCase.curve).PublicKey()},
				jwek.ECDHESA128GCM,
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

	t.Run("Error/NoRecipientKey", func(t *testing.T) {
		t.Parallel()

		manager := jwek.NewECDHKeyAgrManager(&jwek.ECDHKeyAgrManagerConfig{}, jwek.ECDHESA256GCM)

		_, err := manager.ComputeCEK(t.Context(), &jwa.JWH{})
		require.ErrorIs(t, err, jwt.ErrInvalidSecretKey)
		require.NotErrorIs(t, err, jwt.ErrTokenRejected)
	})

	t.Run("Error/UnknownEnc", func(t *testing.T) {
		t.Parallel()

		// ECDH-ES derives a key of the length "enc" takes, so it cannot serve an algorithm it does not know.
		manager := jwek.NewECDHKeyAgrManager(
			&jwek.ECDHKeyAgrManagerConfig{RecipientKey: mustGenerateECDH(t, ecdh.X25519()).PublicKey()},
			jwek.ECDHKeyAgrPreset{Enc: "C20P"},
		)

		_, err := manager.ComputeCEK(t.Context(), &jwa.JWH{})
		require.ErrorIs(t, err, jwt.ErrInvalidSecretKey)
		require.NotErrorIs(t, err, jwt.ErrTokenRejected)
	})
}

func TestECDHKeyAgrDecoder(t *testing.T) {
	t.Parallel()

	recipientKey, recipientPublicKey, err := jwk.GenerateECDHKey(jwk.ECDHESX25519)
	require.NoError(t, err)

	manager := jwek.NewECDHKeyAgrManager(&jwek.ECDHKeyAgrManagerConfig{
		RecipientKey:  recipientPublicKey.Key(),
		ProducerInfo:  "producer",
		RecipientInfo: "recipient",
	}, jwek.ECDHESA128GCM)

	header, err := manager.SetHeader(t.Context(), &jwa.JWH{})
	require.NoError(t, err)

	cek, err := manager.ComputeCEK(t.Context(), header)
	require.NoError(t, err)

	newDecoder := func(key *ecdh.PrivateKey) jwe.CEKDecoder {
		return jwek.NewECDHKeyAgrDecoder(&jwek.ECDHKeyAgrDecoderConfig{RecipientKey: key}, jwek.ECDHESA128GCM)
	}

	// A mismatched apu or apv derives another key without error.
	runAgreementFaults(t, newDecoder, recipientKey, header, nil, cek, nil)

	t.Run("Error/UnexpectedEncKey", func(t *testing.T) {
		t.Parallel()

		// ECDH-ES derives the content encryption key, so the token carries no encrypted key.
		_, err := newDecoder(recipientKey.Key()).ComputeCEK(t.Context(), header, []byte("fake-enc-key"))
		require.ErrorIs(t, err, jwt.ErrUnsupportedTokenFormat)
	})

	t.Run("Error/UnknownEnc", func(t *testing.T) {
		t.Parallel()

		decoder := jwek.NewECDHKeyAgrDecoder(
			&jwek.ECDHKeyAgrDecoderConfig{RecipientKey: recipientKey.Key()}, jwek.ECDHKeyAgrPreset{Enc: "C20P"},
		)

		_, err := decoder.ComputeCEK(t.Context(), &jwa.JWH{JWHCommon: jwa.JWHCommon{Alg: jwa.ECDHES, Enc: "C20P"}}, nil)
		require.ErrorIs(t, err, jwt.ErrInvalidSecretKey)
		require.NotErrorIs(t, err, jwt.ErrTokenRejected)
	})

	// RFC 7518 Appendix C derives a content key from Alice's ephemeral P-256 key and Bob's static one.
	// Decoding Bob's side of it pins the whole path: the "EC" epk, the x-coordinate shared secret, and
	// the Concat KDF.
	//
	// https://datatracker.ietf.org/doc/html/rfc7518#appendix-C
	t.Run("Success/RFC7518C", func(t *testing.T) {
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

		var vectorHeader jwa.JWH

		require.NoError(t, json.Unmarshal([]byte(`{
			"alg":"ECDH-ES","enc":"A128GCM","apu":"QWxpY2U","apv":"Qm9i",
			"epk":{"kty":"EC","crv":"P-256",
				"x":"gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0",
				"y":"SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps"}
		}`), &vectorHeader))

		vectorCEK, err := newDecoder(bobPrivateKey.Key()).ComputeCEK(t.Context(), &vectorHeader, nil)
		require.NoError(t, err)
		require.Equal(t, "VqqN6vgjbSBcIijNcacQGg", base64.RawURLEncoding.EncodeToString(vectorCEK))
	})
}

// runAgreementFaults runs the faults both ECDH-ES decoders meet in the key agreement they share.
// newDecoder builds the decoder under test around a recipient key. The header and encryptedKey come
// from a token issued to recipientKey under the content encryption key cek. A mismatched apu or apv
// fails with wrongInfoErr, and never recovers cek.
func runAgreementFaults(
	t *testing.T,
	newDecoder func(key *ecdh.PrivateKey) jwe.CEKDecoder,
	recipientKey *jwk.Key[*ecdh.PrivateKey],
	header *jwa.JWH,
	encryptedKey, cek []byte,
	wrongInfoErr error,
) {
	t.Helper()

	otherInfo := base64.RawURLEncoding.EncodeToString([]byte("another party"))

	_, otherCurveKey, err := jwk.GenerateECDHKey(jwk.ECDHESP256)
	require.NoError(t, err)

	testCases := []struct {
		name string

		// noRecipientKey builds the decoder without a key.
		noRecipientKey bool
		malform        func(common *jwa.JWHCommon)

		expectErr error
	}{
		{
			name:           "Error/NoRecipientKey",
			noRecipientKey: true,
			expectErr:      jwt.ErrInvalidSecretKey,
		},
		{
			name:      "Error/MalformedAgreementInfo",
			malform:   func(common *jwa.JWHCommon) { common.APU = "!!!" },
			expectErr: jwt.ErrUnsupportedTokenFormat,
		},
		{
			name:      "Error/MissingEPK",
			malform:   func(common *jwa.JWHCommon) { common.EPK = nil },
			expectErr: jwt.ErrUnsupportedTokenFormat,
		},
		{
			name: "Error/MalformedEPK",
			malform: func(common *jwa.JWHCommon) {
				epk := *common.EPK
				epk.Payload = []byte("not json")
				common.EPK = &epk
			},
			expectErr: jwt.ErrUnsupportedTokenFormat,
		},
		{
			// RFC 7518 §4.6.1.1: the ephemeral key holds public parameters only.
			name: "Error/PrivateEPK",
			malform: func(common *jwa.JWHCommon) {
				epk := *common.EPK
				epk.Payload = recipientKey.Payload
				common.EPK = &epk
			},
			expectErr: jwt.ErrUnsupportedTokenFormat,
		},
		{
			// RFC 8037 §2: an X25519 key is an "OKP" key.
			name: "Error/EPKKeyTypeMismatch",
			malform: func(common *jwa.JWHCommon) {
				epk := *common.EPK
				epk.KTY = jwa.KTYEC
				common.EPK = &epk
			},
			expectErr: jwt.ErrUnsupportedTokenFormat,
		},
		{
			// The EPK is a valid P-256 key, but the recipient key is X25519.
			name: "Error/EPKOnAnotherCurve",
			malform: func(common *jwa.JWHCommon) {
				epk := *common.EPK
				epk.KTY = jwa.KTYEC
				epk.Payload = otherCurveKey.Payload
				common.EPK = &epk
			},
			expectErr: jwt.ErrTokenRejected,
		},
		{
			name:      "Error/WrongProducerInfo",
			malform:   func(common *jwa.JWHCommon) { common.APU = otherInfo },
			expectErr: wrongInfoErr,
		},
		{
			name:      "Error/WrongRecipientInfo",
			malform:   func(common *jwa.JWHCommon) { common.APV = otherInfo },
			expectErr: wrongInfoErr,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			common := header.JWHCommon
			if testCase.malform != nil {
				testCase.malform(&common)
			}

			key := recipientKey.Key()
			if testCase.noRecipientKey {
				key = nil
			}

			decoded, err := newDecoder(key).ComputeCEK(t.Context(), &jwa.JWH{JWHCommon: common}, encryptedKey)
			require.ErrorIs(t, err, testCase.expectErr)
			require.NotEqual(t, cek, decoded)
		})
	}
}
