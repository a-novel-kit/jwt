package jwt_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/a-novel-kit/jwt/v2"
	"github.com/a-novel-kit/jwt/v2/jwa"
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
		{
			name: "TokenTooLarge",

			config: jwt.RecipientConfig{MaxTokenBytes: 8},

			token: token,
			dst:   map[string]any{},

			expectErr: jwt.ErrTokenTooLarge,
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

func TestRecipientConcurrentConsume(t *testing.T) {
	t.Parallel()

	producer := jwt.NewProducer(jwt.ProducerConfig{})
	token, err := producer.Issue(t.Context(), map[string]any{"foo": "bar"}, nil)
	require.NoError(t, err)

	// A Recipient with a defaulted deserializer is shared across goroutines. The default must be
	// resolved at construction, not written on first Consume — the latter races under -race.
	recipient := jwt.NewRecipient(jwt.RecipientConfig{})

	var wg sync.WaitGroup

	for range 16 {
		wg.Add(1)

		go func() {
			defer wg.Done()

			dst := map[string]any{}

			err := recipient.Consume(t.Context(), token, &dst)
			if err != nil {
				t.Errorf("concurrent consume: %v", err)
			}
		}()
	}

	wg.Wait()
}

func TestRecipientDecodeUnverified(t *testing.T) {
	t.Parallel()

	// A signed token whose signature would never verify — DecodeUnverified reads its claims anyway.
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"alice","jti":"abc"}`))
	token := header + "." + payload + ".not-a-real-signature"

	recipient := jwt.NewRecipient(jwt.RecipientConfig{})

	var claims map[string]any

	require.NoError(t, recipient.DecodeUnverified(token, &claims))
	require.Equal(t, map[string]any{"sub": "alice", "jti": "abc"}, claims)
}

func TestRecipientDecodeUnverifiedTooLarge(t *testing.T) {
	t.Parallel()

	recipient := jwt.NewRecipient(jwt.RecipientConfig{MaxTokenBytes: 8})

	var claims map[string]any

	require.ErrorIs(t, recipient.DecodeUnverified("aaaa.bbbb.cccc", &claims), jwt.ErrTokenTooLarge)
}
