package jws_test

import (
	"crypto/ed25519"
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/a-novel-kit/jwt/v2/jwa"
	"github.com/a-novel-kit/jwt/v2/jwk"
	"github.com/a-novel-kit/jwt/v2/jws"
)

func TestED25519Signer(t *testing.T) {
	t.Parallel()

	privateKey, publicKey, err := jwk.GenerateED25519()
	require.NoError(t, err)

	// A peer that verifies only "EdDSA" keeps working while this service signs with the legacy label.
	t.Run("Success/LegacyEdDSALabel", func(t *testing.T) {
		t.Parallel()

		legacySigner := jws.NewEdDSASigner(privateKey.Key())

		header, err := legacySigner.Header(t.Context(), &jwa.JWH{})
		require.NoError(t, err)
		require.Equal(t, jwa.EdDSA, header.Alg) //nolint:staticcheck // The legacy label is the expected output.

		require.NoError(t, consume(t, jws.NewED25519Verifier(publicKey.Key()), issue(t, legacySigner, "")))
	})
}

func TestSourcedED25519Signer(t *testing.T) {
	t.Parallel()

	privateKey, _, err := jwk.GenerateED25519()
	require.NoError(t, err)

	t.Run("Success/LegacyEdDSALabel", func(t *testing.T) {
		t.Parallel()

		legacySigner := jws.NewSourcedEdDSASigner(newSource(privateKey.JWK))

		header, err := legacySigner.Header(t.Context(), &jwa.JWH{})
		require.NoError(t, err)
		require.Equal(t, jwa.EdDSA, header.Alg) //nolint:staticcheck // The legacy label is the expected output.
	})
}

func TestED25519Verifier(t *testing.T) {
	t.Parallel()

	// RFC 8037 Appendix A.4 signs under the "EdDSA" label RFC 9864 deprecates. Verifying it pins both
	// interoperability and the acceptance of tokens issued before the fully-specified identifier.
	t.Run("Success/RFC8037Vector", func(t *testing.T) {
		t.Parallel()

		rfcPublicKey, err := base64.RawURLEncoding.DecodeString("11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo")
		require.NoError(t, err)

		payload, err := jws.NewED25519Verifier(ed25519.PublicKey(rfcPublicKey)).Transform(
			t.Context(),
			&jwa.JWH{JWHCommon: jwa.JWHCommon{Alg: jwa.EdDSA}}, //nolint:staticcheck // The vector predates RFC 9864.
			"eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc."+
				"hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg",
		)
		require.NoError(t, err)
		require.Equal(t, "Example of Ed25519 signing", string(payload))
	})
}
