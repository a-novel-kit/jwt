package jwt_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/a-novel-kit/jwt"
	"github.com/a-novel-kit/jwt/jwa"
)

type fakeRecipientPlugin struct {
	payload    func(*jwa.JWH, string) []byte
	payloadErr error
}

func (fake *fakeRecipientPlugin) Transform(_ context.Context, header *jwa.JWH, token string) ([]byte, error) {
	if fake.payload == nil {
		return nil, fake.payloadErr
	}

	return fake.payload(header, token), fake.payloadErr
}

func TestRecipient(t *testing.T) {
	t.Parallel()

	errFoo := errors.New("foo")

	producer := jwt.NewProducer(jwt.ProducerConfig{})
	token, err := producer.Issue(t.Context(), map[string]interface{}{"foo": "bar"}, nil)
	require.NoError(t, err)

	tokenNotJSON, err := jwt.DecodeToken(token, &jwt.RawTokenDecoder{})
	require.NoError(t, err)

	tokenNotJSON.Payload = base64.RawURLEncoding.EncodeToString([]byte("qux"))

	testCases := []struct {
		name string

		config jwt.RecipientConfig

		token string
		dst   any

		expect    any
		expectErr error
	}{
		{
			name: "Minimalistic",

			config: jwt.RecipientConfig{},

			token: token,
			dst:   map[string]any{},

			expect: map[string]any{"foo": "bar"},
		},
		{
			name: "CustomDeserializer",

			config: jwt.RecipientConfig{
				Deserializer: func(raw []byte, dst any) error {
					return json.Unmarshal([]byte(fmt.Sprintf(`{"foo":"%s"}`, string(raw))), dst)
				},
			},

			token: tokenNotJSON.String(),
			dst:   map[string]any{},

			expect: map[string]any{"foo": "qux"},
		},
		{
			name: "Plugins",

			config: jwt.RecipientConfig{
				Plugins: []jwt.RecipientPlugin{
					// First plugin will return a mismatch error.
					&fakeRecipientPlugin{payloadErr: jwt.ErrMismatchRecipientPlugin},
					// Second plugin success!
					&fakeRecipientPlugin{
						payload: func(_ *jwa.JWH, _ string) []byte {
							return []byte(`{"ping":"pong"}`)
						},
					},
					// Third plugin fails, but because previous is successful, it won't be called.
					&fakeRecipientPlugin{payloadErr: errFoo},
				},
			},

			token: token,
			dst:   map[string]any{},

			expect: map[string]any{"ping": "pong"},
		},
		{
			name: "PluginError",

			config: jwt.RecipientConfig{
				Plugins: []jwt.RecipientPlugin{
					// First plugin will return a mismatch error.
					&fakeRecipientPlugin{payloadErr: jwt.ErrMismatchRecipientPlugin},
					// Second plugin fails!
					&fakeRecipientPlugin{payloadErr: errFoo},
				},
			},

			token: token,
			dst:   map[string]any{},

			expectErr: errFoo,
			expect:    map[string]any{},
		},
		{
			name: "NoPluginFound",

			config: jwt.RecipientConfig{
				Plugins: []jwt.RecipientPlugin{
					// First plugin will return a mismatch error.
					&fakeRecipientPlugin{payloadErr: jwt.ErrMismatchRecipientPlugin},
					// Second plugin also mismatch.
					// Third plugin fails, but because previous is successful, it won't be called.
					&fakeRecipientPlugin{payloadErr: jwt.ErrMismatchRecipientPlugin},
				},
			},

			token: token,
			dst:   map[string]any{},

			expectErr: jwt.ErrMismatchRecipientPlugin,
			expect:    map[string]any{},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			recipient := jwt.NewRecipient(testCase.config)
			err = recipient.Consume(t.Context(), testCase.token, &testCase.dst)
			require.ErrorIs(t, err, testCase.expectErr)
			require.Equal(t, testCase.expect, testCase.dst)
		})
	}
}
