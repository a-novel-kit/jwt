package jwt_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/a-novel-kit/jwt/v2"
	"github.com/a-novel-kit/jwt/v2/jwa"
)

type fakeProducerPlugin struct {
	header    func(*jwa.JWH) *jwa.JWH
	headerErr error
	token     func(string) string
	tokenErr  error
}

func (fake *fakeProducerPlugin) Header(_ context.Context, header *jwa.JWH) (*jwa.JWH, error) {
	return fake.header(header), fake.headerErr
}

func (fake *fakeProducerPlugin) Transform(_ context.Context, _ *jwa.JWH, token string) (string, error) {
	return fake.token(token), fake.tokenErr
}

// signingPlugin stands in for a signer. It stamps the algorithm on the header, the value a custom
// header member must not replace.
type signingPlugin struct{ alg jwa.Alg }

func (plugin *signingPlugin) Header(_ context.Context, header *jwa.JWH) (*jwa.JWH, error) {
	header.Alg = plugin.alg

	return header, nil
}

func (plugin *signingPlugin) Transform(_ context.Context, _ *jwa.JWH, token string) (string, error) {
	return token + ".signature", nil
}

func newSigningProducer(alg jwa.Alg) *jwt.Producer {
	return jwt.NewProducer(jwt.ProducerConfig{
		Plugins: []jwt.ProducerPlugin{&signingPlugin{alg: alg}},
	})
}

func decodeSegment(t *testing.T, token string, index int) string {
	t.Helper()

	segments := strings.Split(token, ".")
	require.Greater(t, len(segments), index)

	raw, err := base64.RawURLEncoding.DecodeString(segments[index])
	require.NoError(t, err)

	return string(raw)
}

// withPayload returns a token transform that swaps the payload segment of a "header.payload" token.
func withPayload(payload string) func(string) string {
	return func(tokenRaw string) string {
		token, err := (&jwt.RawTokenDecoder{}).Decode(tokenRaw)
		if err != nil {
			panic(err)
		}

		token.Payload = payload

		return token.String()
	}
}

func TestProducer(t *testing.T) {
	t.Parallel()

	errFoo := errors.New("foo")

	testCases := []struct {
		name string

		config jwt.ProducerConfig

		customClaims any
		customHeader any

		expectToken string
		expectErr   error
	}{
		{
			name: "Minimalistic",

			config: jwt.ProducerConfig{},

			customClaims: map[string]any{"foo": "bar"},

			expectToken: "eyJhbGciOiJub25lIn0.eyJmb28iOiJiYXIifQ.",
		},
		{
			name: "CustomHeader",

			config: jwt.ProducerConfig{},

			customClaims: map[string]any{"foo": "bar"},
			customHeader: map[string]any{"test": true},

			expectToken: "eyJhbGciOiJub25lIiwidGVzdCI6dHJ1ZX0.eyJmb28iOiJiYXIifQ.",
		},
		{
			name: "Plugins",

			config: jwt.ProducerConfig{
				StaticPlugins: []jwt.ProducerStaticPlugin{
					&fakeProducerPlugin{
						header: func(jwh *jwa.JWH) *jwa.JWH {
							jwh.KID = "static-key-id"
							jwh.CTY = "static-test"

							return jwh
						},
					},
				},
				Plugins: []jwt.ProducerPlugin{
					&fakeProducerPlugin{
						header: func(jwh *jwa.JWH) *jwa.JWH {
							jwh.CTY = "test"

							return jwh
						},
						token: withPayload("foobarqux"),
					},
					&fakeProducerPlugin{
						header: func(jwh *jwa.JWH) *jwa.JWH {
							jwh.Alg = "test-alg"

							return jwh
						},
						token: withPayload("abcdefghi"),
					},
				},
			},

			customClaims: map[string]any{"foo": "bar"},
			// {"cty":"test","alg":"test-alg","kid":"static-key-id"}.abcdefghi
			expectToken: "eyJraWQiOiJzdGF0aWMta2V5LWlkIiwiY3R5IjoidGVzdCIsImFsZyI6InRlc3QtYWxnIn0.abcdefghi",
		},
		{
			// A claim a plugin replicates in the header is checked like one from the header config.
			name: "PluginReplicatedClaim",

			config: jwt.ProducerConfig{
				StaticPlugins: []jwt.ProducerStaticPlugin{
					&fakeProducerPlugin{
						header: func(jwh *jwa.JWH) *jwa.JWH {
							jwh.Iss = "accounts"

							return jwh
						},
					},
				},
			},

			customClaims: map[string]any{"iss": "billing"},

			expectErr: jwt.ErrReplicatedClaimMismatch,
		},
		{
			name: "StaticPluginError",

			config: jwt.ProducerConfig{
				StaticPlugins: []jwt.ProducerStaticPlugin{
					&fakeProducerPlugin{
						header:    func(_ *jwa.JWH) *jwa.JWH { return nil },
						headerErr: errFoo,
					},
				},
			},

			customClaims: map[string]any{"foo": "bar"},

			expectErr: errFoo,
		},
		{
			name: "PluginHeaderError",

			config: jwt.ProducerConfig{
				Plugins: []jwt.ProducerPlugin{
					&fakeProducerPlugin{
						header:    func(_ *jwa.JWH) *jwa.JWH { return nil },
						headerErr: errFoo,
						token:     withPayload("foobarqux"),
					},
				},
			},

			customClaims: map[string]any{"foo": "bar"},

			expectErr: errFoo,
		},
		{
			name: "PluginTransformError",

			config: jwt.ProducerConfig{
				Plugins: []jwt.ProducerPlugin{
					&fakeProducerPlugin{
						header: func(jwh *jwa.JWH) *jwa.JWH {
							jwh.CTY = "test"

							return jwh
						},
						token:    func(_ string) string { return "" },
						tokenErr: errFoo,
					},
				},
			},

			customClaims: map[string]any{"foo": "bar"},

			expectErr: errFoo,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			producer := jwt.NewProducer(testCase.config)

			token, err := producer.Issue(t.Context(), testCase.customClaims, testCase.customHeader)
			require.ErrorIs(t, err, testCase.expectErr)

			if testCase.expectErr == nil {
				require.Equal(t, testCase.expectToken, token)
			}
		})
	}

	t.Run("UnmarshalableClaims", func(t *testing.T) {
		t.Parallel()

		producer := jwt.NewProducer(jwt.ProducerConfig{})

		_, err := producer.Issue(t.Context(), map[string]any{"bad": make(chan int)}, nil)
		require.Error(t, err)
	})

	t.Run("UnmarshalableHeader", func(t *testing.T) {
		t.Parallel()

		producer := jwt.NewProducer(jwt.ProducerConfig{})

		_, err := producer.Issue(t.Context(), map[string]any{"foo": "bar"}, map[string]any{"bad": make(chan int)})
		require.Error(t, err)
	})

	// A signer checks the alg struct field, and a custom member joins the encoding only inside
	// MarshalJSON, after every such check. The encoding is therefore what refuses the override.
	t.Run("Error/ReservedCustomHeader", func(t *testing.T) {
		t.Parallel()

		producer := newSigningProducer(jwa.HS256)

		_, err := producer.Issue(t.Context(), map[string]any{"role": "user"}, map[string]any{
			"alg": "none",
			"kid": "attacker-kid",
		})

		require.ErrorIs(t, err, jwa.ErrReservedMember)
		require.ErrorContains(t, err, "alg")
		require.ErrorContains(t, err, "kid")
	})

	t.Run("Success/UnreservedCustomHeader", func(t *testing.T) {
		t.Parallel()

		producer := newSigningProducer(jwa.HS256)

		token, err := producer.Issue(t.Context(), map[string]any{"role": "user"}, map[string]any{
			"myapp-tenant": "acme",
		})
		require.NoError(t, err)

		header := decodeSegment(t, token, 0)
		require.JSONEq(t, `{"alg":"HS256","myapp-tenant":"acme"}`, header)
	})

	t.Run("Success/UnreservedCustomClaims", func(t *testing.T) {
		t.Parallel()

		claims, err := jwt.NewBasicClaims(
			map[string]any{"role": "admin"},
			jwt.ClaimsProducerConfig{TTL: time.Hour},
		)
		require.NoError(t, err)

		producer := newSigningProducer(jwa.HS256)

		token, err := producer.Issue(t.Context(), claims, nil)
		require.NoError(t, err)

		var payload map[string]any

		require.NoError(t, json.Unmarshal([]byte(decodeSegment(t, token, 1)), &payload))
		require.Equal(t, "admin", payload["role"])
		require.NotZero(t, payload["exp"], "the producer's own exp must survive")
	})
}
