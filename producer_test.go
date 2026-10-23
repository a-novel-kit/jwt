package jwt_test

import (
	"context"
	"errors"
	"testing"

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

// withPayload returns a token transform that swaps the payload segment of a "header.payload" token.
func withPayload(payload string) func(string) string {
	return func(tokenRaw string) string {
		token, err := jwt.DecodeToken(tokenRaw, &jwt.RawTokenDecoder{})
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

			expectToken: "eyJhbGciOiJub25lIn0.eyJmb28iOiJiYXIifQ",
		},
		{
			name: "CustomHeader",

			config: jwt.ProducerConfig{},

			customClaims: map[string]any{"foo": "bar"},
			customHeader: map[string]any{"test": true},

			expectToken: "eyJhbGciOiJub25lIiwidGVzdCI6dHJ1ZX0.eyJmb28iOiJiYXIifQ",
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
}
