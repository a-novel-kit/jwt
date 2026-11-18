package jws_test

import (
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/base64"
	"math/big"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/a-novel-kit/jwt/v2"
	"github.com/a-novel-kit/jwt/v2/jwa"
	"github.com/a-novel-kit/jwt/v2/jwk"
	"github.com/a-novel-kit/jwt/v2/jws"
	"github.com/a-novel-kit/jwt/v2/testutils"
)

func TestSignerVerifier(t *testing.T) {
	t.Parallel()

	// RFC 7515 Appendix A signs with fixed keys. Verifying its tokens checks the signature encoding
	// other implementations produce, which a round trip through this package cannot.
	// Each token is stored as its three segments, one per line as the RFC prints it.
	var vectors map[jwa.Alg]struct {
		JWK     jwa.JWK  `json:"jwk"`
		JWS     []string `json:"jws"`
		Payload string   `json:"payload"`
	}

	readVector(t, "rfc7515.json", &vectors)

	for _, testCase := range signatureCases {
		t.Run(string(testCase.alg), func(t *testing.T) {
			t.Parallel()

			keys := testCase.newKeys()
			token := issue(t, keys.signer, "")

			t.Run("Success", func(t *testing.T) {
				t.Parallel()

				require.NoError(t, consume(t, keys.verifier, token))
			})

			t.Run("Success/Header", func(t *testing.T) {
				t.Parallel()

				header, err := keys.signer.Header(t.Context(), &jwa.JWH{})
				require.NoError(t, err)
				require.Equal(t, testCase.alg, header.Alg)
			})

			t.Run("Error/AlgorithmAlreadySet", func(t *testing.T) {
				t.Parallel()

				_, err := keys.signer.Header(t.Context(), &jwa.JWH{JWHCommon: jwa.JWHCommon{Alg: testCase.alg}})
				require.ErrorIs(t, err, jwt.ErrConflictingHeader)
			})

			t.Run("Error/MalformedSigningInput", func(t *testing.T) {
				t.Parallel()

				_, err := keys.signer.Transform(t.Context(), &jwa.JWH{}, "header.payload.signature")
				require.ErrorIs(t, err, jwt.ErrUnsupportedTokenFormat)
			})

			t.Run("Error/OtherAlgorithm", func(t *testing.T) {
				t.Parallel()

				otherHeader := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"foo"}`))
				parts := strings.Split(token, ".")

				err := consume(t, keys.verifier, strings.Join(append([]string{otherHeader}, parts[1:]...), "."))
				require.ErrorIs(t, err, jwt.ErrMismatchRecipientPlugin)
			})

			t.Run("Error/MalformedSignature", func(t *testing.T) {
				t.Parallel()

				parts := strings.Split(token, ".")

				err := consume(t, keys.verifier, strings.Join(append(parts[:2:2], testutils.UndecodableSegment), "."))
				require.ErrorIs(t, err, jwt.ErrUnsupportedTokenFormat)
			})

			t.Run("Error/InvalidSignature", func(t *testing.T) {
				t.Parallel()

				otherToken := issue(t, testCase.newKeys().signer, "")

				require.ErrorIs(t, consume(t, keys.verifier, otherToken), jws.ErrInvalidSignature)
			})

			t.Run("Error/TruncatedSignature", func(t *testing.T) {
				t.Parallel()

				truncated := token[:strings.LastIndex(token, ".")] + ".AAAA"

				require.ErrorIs(t, consume(t, keys.verifier, truncated), jws.ErrInvalidSignature)
			})

			// A lenient decoder ignores the unused trailing bits of the last character, so setting one
			// gives a second token string that decodes to the same signature.
			t.Run("Error/NonCanonicalSignature", func(t *testing.T) {
				t.Parallel()

				parts := strings.Split(token, ".")

				variant, ok := nonCanonical(parts[2])
				if !ok {
					t.Skip("a signature of a multiple of 3 bytes leaves no unused bit")
				}

				original, err := base64.RawURLEncoding.DecodeString(parts[2])
				require.NoError(t, err)
				lenient, err := base64.RawURLEncoding.DecodeString(variant)
				require.NoError(t, err)
				require.Equal(t, original, lenient)

				err = consume(t, keys.verifier, strings.Join(append(parts[:2:2], variant), "."))
				require.ErrorIs(t, err, jwt.ErrUnsupportedTokenFormat)
			})

			t.Run("Error/TamperedPayload", func(t *testing.T) {
				t.Parallel()

				parts := strings.Split(token, ".")
				parts[1] = base64.RawURLEncoding.EncodeToString([]byte(`{"foo":"baz"}`))

				require.ErrorIs(t, consume(t, keys.verifier, strings.Join(parts, ".")), jws.ErrInvalidSignature)
			})

			// The signature covers the payload segment as written, so only decoding it fails.
			t.Run("Error/MalformedPayload", func(t *testing.T) {
				t.Parallel()

				header := strings.Split(token, ".")[0]

				signed, err := keys.signer.Transform(t.Context(), &jwa.JWH{}, header+"."+testutils.UndecodableSegment)
				require.NoError(t, err)

				require.ErrorIs(t, consume(t, keys.verifier, signed), jwt.ErrUnsupportedTokenFormat)
			})

			vector, ok := vectors[testCase.alg]
			if !ok {
				return
			}

			t.Run("Success/RFC7515Vector", func(t *testing.T) {
				t.Parallel()

				// The RFC keys carry neither "use" nor "key_ops", which the jwk decoders require (see
				// the jwk package documentation), so the test binds each one to its example.
				key := &vector.JWK
				key.Alg = testCase.alg
				key.Use = jwa.UseSig
				key.KeyOps = jwa.KeyOps{jwa.KeyOpSign, jwa.KeyOpVerify}

				// HMAC and RSASSA-PKCS1-v1_5 are deterministic, so signing the RFC's input must
				// reproduce its token. ECDSA signatures are randomized, so those rows only verify.
				if key.KTY != jwa.KTYEC {
					signer, _ := testCase.newSourced(newSource(key))

					signed, err := signer.Transform(t.Context(), &jwa.JWH{}, vector.JWS[0]+"."+vector.JWS[1])
					require.NoError(t, err)
					require.Equal(t, strings.Join(vector.JWS, "."), signed)
				}

				// An asymmetric key is published as its public half, which only verifies.
				if key.KTY != jwa.KTYOct {
					var err error

					key, err = jwk.Public(key)
					require.NoError(t, err)
				}

				_, verifier := testCase.newSourced(newSource(key))

				header := &jwa.JWH{JWHCommon: jwa.JWHCommon{Alg: testCase.alg}}

				payload, err := verifier.Transform(t.Context(), header, strings.Join(vector.JWS, "."))
				require.NoError(t, err)
				require.Equal(t, vector.Payload, string(payload))
			})
		})
	}
}

// TestCheckKey covers the key check of every family: a plugin holding a key its algorithm cannot
// use fails with jwt.ErrInvalidSecretKey, which a caller tells apart from a bad token, instead of
// signing or verifying with it.
func TestCheckKey(t *testing.T) {
	t.Parallel()

	shortSecret := []byte("too-short") // 9 bytes, under the 32-byte HS256 floor.

	// The size floor reads only the modulus before any crypto, so a bogus small key exercises it
	// without a slow weak-key generation.
	smallRSAKey := &rsa.PrivateKey{PublicKey: rsa.PublicKey{N: big.NewInt(12345), E: 65537}}

	// |N| clears the bit-length floor, but N is negative. BitLen reads the absolute value, so only
	// the sign check rejects it.
	negativeRSAKey := &rsa.PublicKey{N: new(big.Int).Neg(new(big.Int).Lsh(big.NewInt(1), 2048)), E: 65537}

	offCurvePrivateKey, offCurvePublicKey, err := jwk.GenerateECDSA(jwk.ES384)
	require.NoError(t, err)

	testCases := []struct {
		name string

		alg jwa.Alg
		// signer and verifier hold the faulty key. A nil plugin is not covered by the case.
		signer   jwt.ProducerPlugin
		verifier jwt.RecipientPlugin
	}{
		{
			name:     "Error/ShortHMACSecret",
			alg:      jwa.HS256,
			signer:   jws.NewHMACSigner(shortSecret, jws.HS256),
			verifier: jws.NewHMACVerifier(shortSecret, jws.HS256),
		},
		{
			name:     "Error/SmallRSAKey",
			alg:      jwa.RS256,
			signer:   jws.NewRSASigner(smallRSAKey, jws.RS256),
			verifier: jws.NewRSAVerifier(&smallRSAKey.PublicKey, jws.RS256),
		},
		{
			name:     "Error/SmallRSAPSSKey",
			alg:      jwa.PS256,
			signer:   jws.NewRSASigner(smallRSAKey, jws.PS256),
			verifier: jws.NewRSAVerifier(&smallRSAKey.PublicKey, jws.PS256),
		},
		{
			name:     "Error/NilRSAKey",
			alg:      jwa.RS256,
			signer:   jws.NewRSASigner(nil, jws.RS256),
			verifier: jws.NewRSAVerifier(nil, jws.RS256),
		},
		{
			name:     "Error/NilRSAPSSKey",
			alg:      jwa.PS256,
			signer:   jws.NewRSASigner(nil, jws.PS256),
			verifier: jws.NewRSAVerifier(&rsa.PublicKey{}, jws.PS256),
		},
		{
			name:     "Error/NilRSAModulus",
			alg:      jwa.RS256,
			verifier: jws.NewRSAVerifier(&rsa.PublicKey{}, jws.RS256),
		},
		{
			name:     "Error/NegativeRSAModulus",
			alg:      jwa.RS256,
			verifier: jws.NewRSAVerifier(negativeRSAKey, jws.RS256),
		},
		{
			name:     "Error/NilECDSAKey",
			alg:      jwa.ES256,
			signer:   jws.NewECDSASigner(nil, jws.ES256),
			verifier: jws.NewECDSAVerifier(nil, jws.ES256),
		},
		{
			// RFC 7518 §3.4 binds each ES* algorithm to one curve.
			name:     "Error/ECDSAKeyOffTheCurve",
			alg:      jwa.ES256,
			signer:   jws.NewECDSASigner(offCurvePrivateKey.Key(), jws.ES256),
			verifier: jws.NewECDSAVerifier(offCurvePublicKey.Key(), jws.ES256),
		},
		{
			// crypto/ed25519 panics on a key of the wrong length.
			name:     "Error/ShortED25519Key",
			alg:      jwa.Ed25519,
			signer:   jws.NewED25519Signer(make(ed25519.PrivateKey, ed25519.SeedSize)),
			verifier: jws.NewED25519Verifier(make(ed25519.PublicKey, ed25519.PublicKeySize-1)),
		},
		{
			name:     "Error/NilED25519Key",
			alg:      jwa.Ed25519,
			signer:   jws.NewED25519Signer(nil),
			verifier: jws.NewED25519Verifier(nil),
		},
		{
			name:     "Error/NilMLDSAKey",
			alg:      jwa.MLDSA44,
			signer:   jws.NewMLDSASigner(nil),
			verifier: jws.NewMLDSAVerifier(nil),
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			if testCase.signer != nil {
				_, err := testCase.signer.Header(t.Context(), &jwa.JWH{})
				require.ErrorIs(t, err, jwt.ErrInvalidSecretKey)

				// A sourced signer reaches Transform without going through Header.
				_, err = testCase.signer.Transform(t.Context(), &jwa.JWH{}, "header.payload")
				require.ErrorIs(t, err, jwt.ErrInvalidSecretKey)
			}

			if testCase.verifier != nil {
				header := &jwa.JWH{JWHCommon: jwa.JWHCommon{Alg: testCase.alg}}

				_, err := testCase.verifier.Transform(t.Context(), header, "header.payload.signature")
				require.ErrorIs(t, err, jwt.ErrInvalidSecretKey)
			}
		})
	}
}
