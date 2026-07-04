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

	testCases := []struct {
		name string

		config jwp.EmbedKeyConfig

		expect *jwa.JWH
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
			name: "KeyDirectEmbed",

			config: jwp.EmbedKeyConfig{Key: key.JWK, Embed: true},

			expect: &jwa.JWH{
				JWHCommon: jwa.JWHCommon{
					JWHEmbeddedKey: jwa.JWHEmbeddedKey{KID: key.KID, JWK: key.JWK},
				},
			},
		},
		{
			name: "KeySourcedEmbed",

			config: jwp.EmbedKeyConfig{Source: keySource, Embed: true},

			expect: &jwa.JWH{
				JWHCommon: jwa.JWHCommon{
					JWHEmbeddedKey: jwa.JWHEmbeddedKey{KID: otherKey.KID, JWK: otherKey.JWK},
				},
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			embedder := jwp.NewEmbedKey(testCase.config)
			header, err := embedder.Header(t.Context(), &jwa.JWH{})
			require.NoError(t, err)
			require.Equal(t, testCase.expect, header)
		})
	}
}
