package jwp_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/a-novel-kit/jwt/jwa"
	"github.com/a-novel-kit/jwt/jwk"
	"github.com/a-novel-kit/jwt/jwp"
	"github.com/a-novel-kit/jwt/testutils"
)

func TestKeyEmbedder(t *testing.T) {
	key, err := jwk.GenerateHMAC(jwk.HS256)
	require.NoError(t, err)

	olderKey, err := jwk.GenerateHMAC(jwk.HS256)
	require.NoError(t, err)

	otherKey, err := jwk.GenerateHMAC(jwk.HS256)
	require.NoError(t, err)

	keySource := testutils.NewStaticKeysSource(t, []*jwk.Key[[]byte]{otherKey, olderKey})

	testCases := []struct {
		name string

		config jwp.EmbedKeyConfig[[]byte]

		expect *jwa.JWH
	}{
		{
			name: "Minimalistic",

			config: jwp.EmbedKeyConfig[[]byte]{},

			expect: &jwa.JWH{},
		},
		{
			name: "URL",

			config: jwp.EmbedKeyConfig[[]byte]{URL: "http://test.com"},

			expect: &jwa.JWH{
				JWHCommon: jwa.JWHCommon{
					JWHEmbeddedKey: jwa.JWHEmbeddedKey{JKU: "http://test.com"},
				},
			},
		},
		{
			name: "KeyDirect",

			config: jwp.EmbedKeyConfig[[]byte]{Key: key.JWK},

			expect: &jwa.JWH{
				JWHCommon: jwa.JWHCommon{
					JWHEmbeddedKey: jwa.JWHEmbeddedKey{KID: key.KID},
				},
			},
		},
		{
			name: "KeySourced",

			config: jwp.EmbedKeyConfig[[]byte]{Source: keySource},

			expect: &jwa.JWH{
				JWHCommon: jwa.JWHCommon{
					JWHEmbeddedKey: jwa.JWHEmbeddedKey{KID: otherKey.KID},
				},
			},
		},
		{
			name: "KeySourcedAndDirect",

			config: jwp.EmbedKeyConfig[[]byte]{Source: keySource, Key: key.JWK},

			expect: &jwa.JWH{
				JWHCommon: jwa.JWHCommon{
					JWHEmbeddedKey: jwa.JWHEmbeddedKey{KID: otherKey.KID},
				},
			},
		},
		{
			name: "KeyDirectEmbed",

			config: jwp.EmbedKeyConfig[[]byte]{Key: key.JWK, Embed: true},

			expect: &jwa.JWH{
				JWHCommon: jwa.JWHCommon{
					JWHEmbeddedKey: jwa.JWHEmbeddedKey{KID: key.KID, JWK: key.JWK},
				},
			},
		},
		{
			name: "KeySourcedEmbed",

			config: jwp.EmbedKeyConfig[[]byte]{Source: keySource, Embed: true},

			expect: &jwa.JWH{
				JWHCommon: jwa.JWHCommon{
					JWHEmbeddedKey: jwa.JWHEmbeddedKey{KID: otherKey.KID, JWK: otherKey.JWK},
				},
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			embedder := jwp.NewEmbedKey(testCase.config)
			header, err := embedder.Header(context.Background(), &jwa.JWH{})
			require.NoError(t, err)
			require.Equal(t, testCase.expect, header)
		})
	}
}
