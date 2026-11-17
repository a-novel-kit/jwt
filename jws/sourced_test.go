package jws_test

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/a-novel-kit/jwt/v2"
	"github.com/a-novel-kit/jwt/v2/jwa"
	"github.com/a-novel-kit/jwt/v2/jwk"
	"github.com/a-novel-kit/jwt/v2/jws"
)

// foreignKeys returns keys of a family other than alg's, which its plugins skip.
func foreignKeys(alg jwa.Alg) signatureKeys {
	if alg == jwa.Ed25519 {
		return hmacCase(jwk.HS256, jws.HS256).newKeys()
	}

	return ed25519Case().newKeys()
}

// errFetch is the failure of a source that cannot reach its keys.
var errFetch = errors.New("fetch keys")

// failingSource returns a [jwk.Source] whose every fetch fails with errFetch.
func failingSource() *jwk.Source {
	return jwk.NewSource(jwk.SourceConfig{
		Fetch: func(_ context.Context) ([]*jwa.JWK, error) { return nil, errFetch },
	})
}

func TestSourcedSigner(t *testing.T) {
	t.Parallel()

	for _, testCase := range signatureCases {
		t.Run(string(testCase.alg), func(t *testing.T) {
			t.Parallel()

			first, second := testCase.newKeys(), testCase.newKeys()
			signer, _ := testCase.newSourced(newSource(foreignKeys(testCase.alg).signing, first.signing, second.signing))

			// Without a key ID, the signer takes the first key of its family and names it, so
			// recipients can select it.
			t.Run("Success/FirstKey", func(t *testing.T) {
				t.Parallel()

				token := issue(t, signer, "")

				require.NoError(t, consume(t, first.verifier, token))
				require.ErrorIs(t, consume(t, second.verifier, token), jws.ErrInvalidSignature)

				header, err := signer.Header(t.Context(), &jwa.JWH{})
				require.NoError(t, err)
				require.Equal(t, first.signing.KID, header.KID)
			})

			t.Run("Success/NamedKey", func(t *testing.T) {
				t.Parallel()

				token := issue(t, signer, second.signing.KID)

				require.NoError(t, consume(t, second.verifier, token))
			})

			t.Run("Error/EmptySource", func(t *testing.T) {
				t.Parallel()

				emptySigner, _ := testCase.newSourced(newSource())

				_, err := emptySigner.Header(t.Context(), &jwa.JWH{})
				require.ErrorIs(t, err, jwk.ErrKeyNotFound)
			})

			// A private key labeled for verification decodes like any other, so only its key_ops keep
			// a signer from using it.
			t.Run("Error/VerifyOnlyKey", func(t *testing.T) {
				t.Parallel()

				verifyOnly := withKeyOps(first.signing, jwa.KeyOpVerify)
				verifyOnlySigner, _ := testCase.newSourced(newSource(verifyOnly))

				_, err := verifyOnlySigner.Header(t.Context(), &jwa.JWH{})
				require.ErrorIs(t, err, jwk.ErrKeyNotFound)

				named := &jwa.JWH{JWHCommon: jwa.JWHCommon{JWHEmbeddedKey: jwa.JWHEmbeddedKey{KID: verifyOnly.KID}}}

				_, err = verifyOnlySigner.Header(t.Context(), named)
				require.ErrorIs(t, err, jwk.ErrJWKMismatch)
			})

			t.Run("Error/SourceFailure", func(t *testing.T) {
				t.Parallel()

				failingSigner, _ := testCase.newSourced(failingSource())

				_, err := failingSigner.Header(t.Context(), &jwa.JWH{})
				require.ErrorIs(t, err, errFetch)

				_, err = failingSigner.Transform(t.Context(), &jwa.JWH{}, "header.payload")
				require.ErrorIs(t, err, errFetch)
			})
		})
	}
}

func TestSourcedVerifier(t *testing.T) {
	t.Parallel()

	for _, testCase := range signatureCases {
		t.Run(string(testCase.alg), func(t *testing.T) {
			t.Parallel()

			signing, other := testCase.newKeys(), testCase.newKeys()
			token := issue(t, signing.signer, "")

			keyLists := []struct {
				name string

				keys []*jwa.JWK

				expectErr error
			}{
				{name: "Success/SigningKeyFirst", keys: []*jwa.JWK{signing.verification, other.verification}},
				{name: "Success/SigningKeySecond", keys: []*jwa.JWK{other.verification, signing.verification}},
				{name: "Success/OtherFamilyFirst", keys: []*jwa.JWK{foreignKeys(testCase.alg).verification, signing.verification}},
				{name: "Error/KeyMissing", keys: []*jwa.JWK{other.verification}, expectErr: jws.ErrInvalidSignature},
				{
					name:      "Error/SignOnlyKey",
					keys:      []*jwa.JWK{withKeyOps(signing.verification, jwa.KeyOpSign)},
					expectErr: jws.ErrInvalidSignature,
				},
			}

			for _, keyList := range keyLists {
				t.Run(keyList.name, func(t *testing.T) {
					t.Parallel()

					_, verifier := testCase.newSourced(newSource(keyList.keys...))

					require.ErrorIs(t, consume(t, verifier, token), keyList.expectErr)
				})
			}

			// A source exposing private material is misconfigured, so its keys are skipped. The key is
			// labeled for verification, so only the exposure check refuses it. An HMAC secret has no
			// public half to expose instead.
			if signing.signing != signing.verification {
				t.Run("Error/PrivateKeyExposed", func(t *testing.T) {
					t.Parallel()

					_, verifier := testCase.newSourced(newSource(withKeyOps(signing.signing, jwa.KeyOpVerify)))

					require.ErrorIs(t, consume(t, verifier, token), jws.ErrInvalidSignature)
				})
			}

			// A source that cannot fetch its keys fails the recipient without rejecting the token, so
			// the holder keeps a token that may still be valid.
			t.Run("Error/SourceFailure", func(t *testing.T) {
				t.Parallel()

				_, verifier := testCase.newSourced(failingSource())

				err := consume(t, verifier, token)
				require.ErrorIs(t, err, errFetch)
				require.NotErrorIs(t, err, jwt.ErrTokenRejected)
			})
		})
	}

	// One source serves keys of two families during an algorithm rotation. The recipient holds a
	// verifier per accepted algorithm and routes on the header's alg, so a token whose algorithm has
	// no configured verifier is rejected.
	t.Run("Success/MixedFamilies", func(t *testing.T) {
		t.Parallel()

		rsaKeys := rsaCase(jwk.RS256, jws.RS256).newKeys()
		ecdsaKeys := ecdsaCase(jwk.ES256, jws.ES256).newKeys()
		source := newSource(rsaKeys.verification, ecdsaKeys.verification)

		recipient := jwt.NewRecipient(jwt.RecipientConfig{
			Plugins: []jwt.RecipientPlugin{
				jws.NewSourcedRSAVerifier(source, jws.RS256),
				jws.NewSourcedECDSAVerifier(source, jws.ES256),
			},
		})

		var claims map[string]any

		require.NoError(t, recipient.Consume(t.Context(), issue(t, rsaKeys.signer, ""), &claims))
		require.NoError(t, recipient.Consume(t.Context(), issue(t, ecdsaKeys.signer, ""), &claims))

		hmacToken := issue(t, hmacCase(jwk.HS256, jws.HS256).newKeys().signer, "")
		require.ErrorIs(t, recipient.Consume(t.Context(), hmacToken, &claims), jwt.ErrMismatchRecipientPlugin)
	})

	// A key of the verifier's own family that fails to decode is malformed material, not a bad token.
	t.Run("Error/MalformedKey", func(t *testing.T) {
		t.Parallel()

		keys := rsaCase(jwk.RS256, jws.RS256).newKeys()

		malformed := *keys.verification
		malformed.Payload = []byte(`{"n":"!!!not-base64","e":"AQAB"}`)

		err := consume(t, jws.NewSourcedRSAVerifier(newSource(&malformed), jws.RS256), issue(t, keys.signer, ""))
		require.Error(t, err)
		require.NotErrorIs(t, err, jwt.ErrTokenRejected)
	})

	// A token naming a key the cached set lacks is how a rotation looks to a recipient whose cache
	// is an hour long. RefreshOnUnknownKeyID lets it fetch the rotated set within the request.
	t.Run("RefreshOnUnknownKeyID", func(t *testing.T) {
		t.Parallel()

		family := rsaCase(jwk.RS256, jws.RS256)
		oldKeys, rotatedKeys := family.newKeys(), family.newKeys()

		// A sourced signer names its key, which gives the recipient an ID to miss on.
		oldToken := issue(t, jws.NewSourcedRSASigner(newSource(oldKeys.signing), jws.RS256), "")
		rotatedToken := issue(t, jws.NewSourcedRSASigner(newSource(rotatedKeys.signing), jws.RS256), "")

		testCases := []struct {
			name string

			refreshOnUnknownKeyID bool

			expectErr error
		}{
			// The default is unchanged: the rotated key stays unknown until CacheDuration elapses.
			{name: "Error/Disabled", expectErr: jws.ErrInvalidSignature},
			{name: "Success/Enabled", refreshOnUnknownKeyID: true},
		}

		for _, testCase := range testCases {
			t.Run(testCase.name, func(t *testing.T) {
				t.Parallel()

				var rotated atomic.Bool

				source := jwk.NewSource(jwk.SourceConfig{
					CacheDuration:         time.Hour,
					RefreshOnUnknownKeyID: testCase.refreshOnUnknownKeyID,
					UnknownKeyIDInterval:  time.Nanosecond,
					Fetch: func(_ context.Context) ([]*jwa.JWK, error) {
						if rotated.Load() {
							return []*jwa.JWK{rotatedKeys.verification}, nil
						}

						return []*jwa.JWK{oldKeys.verification}, nil
					},
				})

				verifier := jws.NewSourcedRSAVerifier(source, jws.RS256)

				// Warm the cache on the pre-rotation key set.
				require.NoError(t, consume(t, verifier, oldToken))

				rotated.Store(true)

				require.ErrorIs(t, consume(t, verifier, rotatedToken), testCase.expectErr)
			})
		}
	})
}
