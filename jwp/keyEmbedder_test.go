package jwp_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/a-novel-kit/jwt/v2/jwa"
	"github.com/a-novel-kit/jwt/v2/jwk"
	"github.com/a-novel-kit/jwt/v2/jwp"
	"github.com/a-novel-kit/jwt/v2/testutils"
)

func TestKeyEmbedder(t *testing.T) {
	t.Parallel()

	key, err := jwk.GenerateHMAC(jwk.HS256)
	require.NoError(t, err)

	olderKey, err := jwk.GenerateHMAC(jwk.HS256)
	require.NoError(t, err)

	otherKey, err := jwk.GenerateHMAC(jwk.HS256)
	require.NoError(t, err)

	keySource := testutils.NewStaticKeysSource(t, []*jwk.Key[[]byte]{otherKey, olderKey})

	// An asymmetric pair, to separate "carries private material" from "is
	// symmetric": the private half must be refused and the public half embedded.
	signingKey, _, err := jwk.GenerateED25519()
	require.NoError(t, err)

	publicKey, err := jwk.Public(signingKey.JWK)
	require.NoError(t, err)

	testCases := []struct {
		name string

		config jwp.EmbedKeyConfig

		expect *jwa.JWH
		// expectErr is set on the configurations that must not produce a header
		// at all.
		expectErr error
	}{
		{
			name: "Minimalistic",

			config: jwp.EmbedKeyConfig{},

			expect: &jwa.JWH{},
		},
		{
			name: "URL",

			config: jwp.EmbedKeyConfig{URL: "http://test.com"},

			expect: &jwa.JWH{
				JWHCommon: jwa.JWHCommon{
					JWHEmbeddedKey: jwa.JWHEmbeddedKey{JKU: "http://test.com"},
				},
			},
		},
		{
			name: "KeyDirect",

			config: jwp.EmbedKeyConfig{Key: key.JWK},

			expect: &jwa.JWH{
				JWHCommon: jwa.JWHCommon{
					JWHEmbeddedKey: jwa.JWHEmbeddedKey{KID: key.KID},
				},
			},
		},
		{
			name: "KeySourced",

			config: jwp.EmbedKeyConfig{Source: keySource},

			expect: &jwa.JWH{
				JWHCommon: jwa.JWHCommon{
					JWHEmbeddedKey: jwa.JWHEmbeddedKey{KID: otherKey.KID},
				},
			},
		},
		{
			name: "KeySourcedAndDirect",

			config: jwp.EmbedKeyConfig{Source: keySource, Key: key.JWK},

			expect: &jwa.JWH{
				JWHCommon: jwa.JWHCommon{
					JWHEmbeddedKey: jwa.JWHEmbeddedKey{KID: otherKey.KID},
				},
			},
		},
		{
			// A symmetric key is its own secret, so embedding one publishes the
			// signing key in every token it signs.
			name: "KeyDirectEmbed/Symmetric",

			config: jwp.EmbedKeyConfig{Key: key.JWK, Embed: true},

			expectErr: jwk.ErrPrivateKeyMaterial,
		},
		{
			// Source resolves signing keys, which is where a private key comes
			// from. This is the configuration that would leak on every token.
			name: "KeySourcedEmbed/Symmetric",

			config: jwp.EmbedKeyConfig{Source: keySource, Embed: true},

			expectErr: jwk.ErrPrivateKeyMaterial,
		},
		{
			name: "KeyDirectEmbed/AsymmetricPrivate",

			config: jwp.EmbedKeyConfig{Key: signingKey.JWK, Embed: true},

			expectErr: jwk.ErrPrivateKeyMaterial,
		},
		{
			// The public half is what the affordance exists for: a recipient can
			// verify with it, and it gives nothing away.
			name: "KeyDirectEmbed/AsymmetricPublic",

			config: jwp.EmbedKeyConfig{Key: publicKey, Embed: true},

			expect: &jwa.JWH{
				JWHCommon: jwa.JWHCommon{
					JWHEmbeddedKey: jwa.JWHEmbeddedKey{KID: publicKey.KID, JWK: publicKey},
				},
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			embedder := jwp.NewEmbedKey(testCase.config)

			header, err := embedder.Header(t.Context(), &jwa.JWH{})

			if testCase.expectErr != nil {
				require.ErrorIs(t, err, testCase.expectErr)
				require.Nil(t, header)

				return
			}

			require.NoError(t, err)
			require.Equal(t, testCase.expect, header)
		})
	}
}
