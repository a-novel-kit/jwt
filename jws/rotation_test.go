package jws_test

import (
	"context"
	"crypto/rsa"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/a-novel-kit/jwt/v2"
	"github.com/a-novel-kit/jwt/v2/jwa"
	"github.com/a-novel-kit/jwt/v2/jwk"
	"github.com/a-novel-kit/jwt/v2/jws"
)

// TestSourcedMixedRotation is the acceptance test for the raw source: one Source serves keys of two
// families, and a single recipient — configured with a verifier per accepted algorithm — verifies
// tokens of both, routing on the header's alg. That is the shape of an algorithm rotation: keep
// verifiers for the old and new algorithms while both keys live. A token whose algorithm has no
// configured verifier is rejected, so the header routes only among the verifiers the operator
// pinned.
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

// TestSourcedVerifierSurfacesMalformedKey checks that a key of the verifier's own family that fails
// to decode surfaces as an error, rather than being skipped and masked as an invalid signature.
func TestSourcedVerifierSurfacesMalformedKey(t *testing.T) {
	t.Parallel()

	rsaPriv, rsaPub, err := jwk.GenerateRSA(jwk.RS256)
	require.NoError(t, err)

	// Keep the metadata (so it still matches the RSA family filter) but corrupt the key material.
	malformed := *rsaPub.JWK
	malformed.Payload = []byte(`{"n":"!!!not-base64","e":"AQAB"}`)

	source := jwk.NewSource(jwk.SourceConfig{
		Fetch: func(_ context.Context) ([]*jwa.JWK, error) {
			return []*jwa.JWK{&malformed}, nil
		},
	})

	token, err := jwt.NewProducer(jwt.ProducerConfig{
		Plugins: []jwt.ProducerPlugin{jws.NewRSASigner(rsaPriv.Key(), jws.RS256)},
	}).Issue(t.Context(), map[string]any{"foo": "bar"}, nil)
	require.NoError(t, err)

	recipient := jwt.NewRecipient(jwt.RecipientConfig{
		Plugins: []jwt.RecipientPlugin{jws.NewSourcedRSAVerifier(source, jws.RS256)},
	})

	var got map[string]any

	err = recipient.Consume(t.Context(), token, &got)
	require.Error(t, err)
	require.NotErrorIs(t, err, jws.ErrInvalidSignature)
}

// TestSourcedRotationUnknownKeyID is the acceptance test for RefreshOnUnknownKeyID on the path a
// recipient actually takes: verifyFromSource walks Source.List, so a refresh wired only into
// Source.Get would leave it reading a stale set, skipping every key whose id misses the header, and
// reporting an invalid signature for the whole of CacheDuration.
func TestSourcedRotationUnknownKeyID(t *testing.T) {
	t.Parallel()

	oldPriv, oldPub, err := jwk.GenerateRSA(jwk.RS256)
	require.NoError(t, err)

	newPriv, newPub, err := jwk.GenerateRSA(jwk.RS256)
	require.NoError(t, err)

	claims := map[string]any{"foo": "bar"}

	// The issuer signs with whichever key it currently holds, naming it in the header, which is what
	// gives the consumer an id to miss on.
	issue := func(t *testing.T, key *jwk.Key[*rsa.PrivateKey]) string {
		t.Helper()

		issuerSource := jwk.NewSource(jwk.SourceConfig{
			Fetch: func(_ context.Context) ([]*jwa.JWK, error) { return []*jwa.JWK{key.JWK}, nil },
		})

		token, issueErr := jwt.NewProducer(jwt.ProducerConfig{
			Plugins: []jwt.ProducerPlugin{jws.NewSourcedRSASigner(issuerSource, jws.RS256)},
		}).Issue(t.Context(), claims, nil)
		require.NoError(t, issueErr)

		return token
	}

	oldToken := issue(t, oldPriv)
	newToken := issue(t, newPriv)

	// A consumer whose cache is an hour long. Rotation is invisible to it until the cache expires,
	// unless an unknown key id can force the issue.
	newConsumer := func(t *testing.T, rotated *atomic.Bool, refreshOnUnknown bool) *jwt.Recipient {
		t.Helper()

		source := jwk.NewSource(jwk.SourceConfig{
			CacheDuration:         time.Hour,
			RefreshOnUnknownKeyID: refreshOnUnknown,
			UnknownKeyIDInterval:  time.Nanosecond,
			Fetch: func(_ context.Context) ([]*jwa.JWK, error) {
				if rotated.Load() {
					return []*jwa.JWK{newPub.JWK}, nil
				}

				return []*jwa.JWK{oldPub.JWK}, nil
			},
		})

		return jwt.NewRecipient(jwt.RecipientConfig{
			Plugins: []jwt.RecipientPlugin{jws.NewSourcedRSAVerifier(source, jws.RS256)},
		})
	}

	t.Run("Disabled", func(t *testing.T) {
		t.Parallel()

		var rotated atomic.Bool

		recipient := newConsumer(t, &rotated, false)

		var got map[string]any

		// Warm the cache on the pre-rotation key set.
		require.NoError(t, recipient.Consume(t.Context(), oldToken, &got))

		rotated.Store(true)

		// The default is unchanged: the rotated key stays unverifiable until CacheDuration elapses.
		require.Error(t, recipient.Consume(t.Context(), newToken, &got))
	})

	t.Run("Enabled", func(t *testing.T) {
		t.Parallel()

		var rotated atomic.Bool

		recipient := newConsumer(t, &rotated, true)

		var got map[string]any

		require.NoError(t, recipient.Consume(t.Context(), oldToken, &got))

		rotated.Store(true)

		got = nil

		// The header names a key id the cached set does not hold, so the source is asked for it
		// directly and re-fetches — inside the same request, without waiting out the cache.
		require.NoError(t, recipient.Consume(t.Context(), newToken, &got))
		require.Equal(t, claims, got)
	})
}
