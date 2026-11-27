package jwk_test

import (
	"crypto/mldsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/a-novel-kit/jwt/v2/jwa"
	"github.com/a-novel-kit/jwt/v2/jwk"
	"github.com/a-novel-kit/jwt/v2/jwk/serializers"
)

// parseJWK decodes a JSON Web Key from its serialized form.
func parseJWK(t *testing.T, serialized string) *jwa.JWK {
	t.Helper()

	var key jwa.JWK

	require.NoError(t, json.Unmarshal([]byte(serialized), &key))

	return &key
}

// thumbprintOf hashes a hash input of RFC 7638 §3 that a test wrote out by hand, so the expected
// value owes nothing to the member table under test.
func thumbprintOf(hashInput string) string {
	sum := sha256.Sum256([]byte(hashInput))

	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func TestThumbprint(t *testing.T) {
	t.Parallel()

	const (
		// The "n" of the RSA key in RFC 7638 §3.1, broken where the RFC breaks it.
		rfc7638N = "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAt" +
			"VT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn6" +
			"4tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FD" +
			"W2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n9" +
			"1CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINH" +
			"aQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"
		rfc7638Thumbprint = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"

		// The Ed25519 key of RFC 8037 appendix A.1, and its thumbprint from appendix A.3.
		rfc8037X          = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
		rfc8037D          = "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A"
		rfc8037Thumbprint = "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"

		// The "kid" of the ML-DSA-44 key in RFC 9964 appendix A.1, which is its thumbprint.
		rfc9964Thumbprint = "T4xl70S7MT6Zeq6r9V9fPJGVn76wfnXJ21-gyo0Gu6o"
	)

	// RFC 9964 appendix A.1 expands its example keys from the all-zeros seed.
	zeroSeedKey, err := mldsa.NewPrivateKey(mldsa.MLDSA44(), make([]byte, mldsa.PrivateKeySize))
	require.NoError(t, err)

	zeroSeedPayload, err := json.Marshal(serializers.EncodeMLDSA(zeroSeedKey))
	require.NoError(t, err)

	// Each generated key takes its expected thumbprint from the raw members of its public half.
	rsaPrivate, rsaPublic, err := jwk.GenerateRSA(jwk.RS256)
	require.NoError(t, err)

	rsaMembers := members(t, rsaPublic.JWK)
	rsaExpect := thumbprintOf(fmt.Sprintf(`{"e":%s,"kty":"RSA","n":%s}`, rsaMembers["e"], rsaMembers["n"]))

	ecPrivate, ecPublic, err := jwk.GenerateECDSA(jwk.ES256)
	require.NoError(t, err)

	ecMembers := members(t, ecPublic.JWK)
	ecExpect := thumbprintOf(fmt.Sprintf(
		`{"crv":%s,"kty":"EC","x":%s,"y":%s}`, ecMembers["crv"], ecMembers["x"], ecMembers["y"],
	))

	okpPrivate, okpPublic, err := jwk.GenerateECDHKey(jwk.ECDHESX25519)
	require.NoError(t, err)

	okpMembers := members(t, okpPublic.JWK)
	okpExpect := thumbprintOf(fmt.Sprintf(`{"crv":%s,"kty":"OKP","x":%s}`, okpMembers["crv"], okpMembers["x"]))

	akpPrivate, akpPublic, err := jwk.GenerateMLDSA(jwk.MLDSA65)
	require.NoError(t, err)

	akpExpect := thumbprintOf(fmt.Sprintf(
		`{"alg":"ML-DSA-65","kty":"AKP","pub":%s}`, members(t, akpPublic.JWK)["pub"],
	))

	octKey, err := jwk.GenerateHMAC(jwk.HS256)
	require.NoError(t, err)

	octExpect := thumbprintOf(fmt.Sprintf(`{"k":%s,"kty":"oct"}`, members(t, octKey.JWK)["k"]))

	testCases := []struct {
		name string

		key *jwa.JWK

		expect    string
		expectErr error
	}{
		{
			name:   "Success/RFC7638",
			key:    parseJWK(t, `{"kty":"RSA","n":"`+rfc7638N+`","e":"AQAB","alg":"RS256","kid":"2011-04-29"}`),
			expect: rfc7638Thumbprint,
		},
		{
			name:   "Success/RFC8037/Public",
			key:    parseJWK(t, `{"kty":"OKP","crv":"Ed25519","x":"`+rfc8037X+`"}`),
			expect: rfc8037Thumbprint,
		},
		{
			name:   "Success/RFC8037/Private",
			key:    parseJWK(t, `{"kty":"OKP","crv":"Ed25519","d":"`+rfc8037D+`","x":"`+rfc8037X+`"}`),
			expect: rfc8037Thumbprint,
		},
		{
			name: "Success/RFC9964",
			key: &jwa.JWK{
				JWKCommon: jwa.JWKCommon{KTY: jwa.KTYAKP, Alg: jwa.MLDSA44},
				Payload:   zeroSeedPayload,
			},
			expect: rfc9964Thumbprint,
		},

		{name: "Success/RSA/Private", key: rsaPrivate.JWK, expect: rsaExpect},
		{name: "Success/RSA/Public", key: rsaPublic.JWK, expect: rsaExpect},
		{name: "Success/EC/Private", key: ecPrivate.JWK, expect: ecExpect},
		{name: "Success/EC/Public", key: ecPublic.JWK, expect: ecExpect},
		{name: "Success/OKP/Private", key: okpPrivate.JWK, expect: okpExpect},
		{name: "Success/OKP/Public", key: okpPublic.JWK, expect: okpExpect},
		{name: "Success/AKP/Private", key: akpPrivate.JWK, expect: akpExpect},
		{name: "Success/AKP/Public", key: akpPublic.JWK, expect: akpExpect},
		{name: "Success/Oct", key: octKey.JWK, expect: octExpect},

		{
			name:   "Success/MemberOrder",
			key:    parseJWK(t, `{"x":"`+rfc8037X+`","crv":"Ed25519","kty":"OKP"}`),
			expect: rfc8037Thumbprint,
		},
		{
			name: "Success/OtherMembers",
			key: parseJWK(t, `{"kty":"OKP","use":"sig","key_ops":["verify"],"alg":"Ed25519","kid":"key-1",`+
				`"crv":"Ed25519","x":"`+rfc8037X+`","y":"AQAB","ext":true}`),
			expect: rfc8037Thumbprint,
		},
		{
			// RFC 7638 §3.3 hashes the value unescaped, so an escape in the source changes nothing. The
			// escape below spells the leading "1" of the public key.
			name:   "Success/EscapeInSource",
			key:    parseJWK(t, `{"kty":"OKP","crv":"Ed25519","x":"1`+rfc8037X[1:]+`"}`),
			expect: rfc8037Thumbprint,
		},

		// Every failing key carries SECRET, which no message may quote.
		{name: "Error/Nil", expectErr: jwk.ErrNoThumbprint},
		{
			name:      "Error/UnknownKeyType",
			key:       parseJWK(t, `{"kty":"unknown","k":"SECRET"}`),
			expectErr: jwk.ErrNoThumbprint,
		},
		{
			name:      "Error/InvalidPayload",
			key:       &jwa.JWK{JWKCommon: jwa.JWKCommon{KTY: jwa.KTYOct}, Payload: json.RawMessage(`{"k":SECRET}`)},
			expectErr: jwk.ErrNoThumbprint,
		},
		{
			name:      "Error/MissingMember",
			key:       parseJWK(t, `{"kty":"OKP","crv":"Ed25519","d":"SECRET"}`),
			expectErr: jwk.ErrNoThumbprint,
		},
		{
			name:      "Error/NullMember",
			key:       parseJWK(t, `{"kty":"OKP","crv":"Ed25519","x":null,"d":"SECRET"}`),
			expectErr: jwk.ErrNoThumbprint,
		},
		{
			name:      "Error/EmptyMember",
			key:       parseJWK(t, `{"kty":"OKP","crv":"Ed25519","x":"","d":"SECRET"}`),
			expectErr: jwk.ErrNoThumbprint,
		},
		{
			name:      "Error/MemberNotString",
			key:       parseJWK(t, `{"kty":"oct","k":["SECRET"]}`),
			expectErr: jwk.ErrNoThumbprint,
		},
		{
			name:      "Error/MissingAlgorithm",
			key:       parseJWK(t, `{"kty":"AKP","pub":"SECRET"}`),
			expectErr: jwk.ErrNoThumbprint,
		},
		{
			name:      "Error/EscapedCharacter/Quote",
			key:       parseJWK(t, `{"kty":"oct","k":"SECRET\"SECRET"}`),
			expectErr: jwk.ErrNoThumbprint,
		},
		{
			name:      "Error/EscapedCharacter/Backslash",
			key:       parseJWK(t, `{"kty":"oct","k":"SECRET\\SECRET"}`),
			expectErr: jwk.ErrNoThumbprint,
		},
		{
			name:      "Error/EscapedCharacter/Control",
			key:       parseJWK(t, `{"kty":"oct","k":"SECRET\nSECRET"}`),
			expectErr: jwk.ErrNoThumbprint,
		},
		{
			// The algorithm of an AKP key enters the hash input like any payload member.
			name:      "Error/EscapedCharacter/Algorithm",
			key:       parseJWK(t, `{"kty":"AKP","alg":"ML-DSA-44\"","pub":"SECRET"}`),
			expectErr: jwk.ErrNoThumbprint,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			thumbprint, err := jwk.Thumbprint(testCase.key)
			require.ErrorIs(t, err, testCase.expectErr)
			require.Equal(t, testCase.expect, thumbprint)

			if err != nil {
				require.NotContains(t, err.Error(), "SECRET")
			}
		})
	}
}
