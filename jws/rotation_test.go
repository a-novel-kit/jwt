package jws_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/a-novel-kit/jwt/v2"
	"github.com/a-novel-kit/jwt/v2/jwa"
	"github.com/a-novel-kit/jwt/v2/jwk"
	"github.com/a-novel-kit/jwt/v2/jws"
)

// TestSourcedMixedRotation is the acceptance test for the raw source: one Source serves keys of two
// families, and a single recipient — configured with a verifier per accepted algorithm — verifies
// tokens of both through the same code, routing on the header's alg. This is the shape an algorithm
// rotation takes: keep verifiers for the old and new algorithms while both keys live, and the same
// endpoint accepts either. A token whose algorithm has no configured verifier is rejected, so the
// header can only route among the verifiers the operator pinned — never introduce a new algorithm.
func TestSourcedMixedRotation(t *testing.T) {
	t.Parallel()

	rsaPriv, rsaPub, err := jwk.GenerateRSA(jwk.RS256)
	require.NoError(t, err)

	ecPriv, ecPub, err := jwk.GenerateECDSA(jwk.ES256)
	require.NoError(t, err)

	// One source, mixed key families.
	source := jwk.NewSource(jwk.SourceConfig{
		Fetch: func(_ context.Context) ([]*jwa.JWK, error) {
			return []*jwa.JWK{rsaPub.JWK, ecPub.JWK}, nil
		},
	})

	// One recipient accepting both algorithms.
	recipient := jwt.NewRecipient(jwt.RecipientConfig{
		Plugins: []jwt.RecipientPlugin{
			jws.NewSourcedRSAVerifier(source, jws.RS256),
			jws.NewSourcedECDSAVerifier(source, jws.ES256),
		},
	})

	claims := map[string]any{"foo": "bar"}

	rsaToken, err := jwt.NewProducer(jwt.ProducerConfig{
		Plugins: []jwt.ProducerPlugin{jws.NewRSASigner(rsaPriv.Key(), jws.RS256)},
	}).Issue(t.Context(), claims, nil)
	require.NoError(t, err)

	ecToken, err := jwt.NewProducer(jwt.ProducerConfig{
		Plugins: []jwt.ProducerPlugin{jws.NewECDSASigner(ecPriv.Key(), jws.ES256)},
	}).Issue(t.Context(), claims, nil)
	require.NoError(t, err)

	// Both algorithms verify through the same recipient: the RSA verifier skips the EC key (it fails
	// to decode as RSA) and vice versa.
	var got map[string]any

	require.NoError(t, recipient.Consume(t.Context(), rsaToken, &got))
	require.Equal(t, claims, got)

	got = nil

	require.NoError(t, recipient.Consume(t.Context(), ecToken, &got))
	require.Equal(t, claims, got)

	// A token whose algorithm has no configured verifier is rejected.
	hmacKey, err := jwk.GenerateHMAC(jwk.HS256)
	require.NoError(t, err)

	hmacToken, err := jwt.NewProducer(jwt.ProducerConfig{
		Plugins: []jwt.ProducerPlugin{jws.NewHMACSigner(hmacKey.Key(), jws.HS256)},
	}).Issue(t.Context(), claims, nil)
	require.NoError(t, err)

	require.ErrorIs(t, recipient.Consume(t.Context(), hmacToken, &got), jwt.ErrMismatchRecipientPlugin)
}
