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
	"github.com/a-novel-kit/jwt/v2/testutils"
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

	issueTyped := func(typ jwa.Typ) string {
		typed, err := jwt.NewProducer(jwt.ProducerConfig{Header: jwt.HeaderProducerConfig{Typ: typ}}).
			Issue(t.Context(), map[string]any{"foo": "bar"}, nil)
		require.NoError(t, err)

		return typed
	}

	unsecured := []jwt.RecipientPlugin{jwt.NewDefaultRecipientPlugin()}

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

			config: jwt.RecipientConfig{Plugins: unsecured},

			token: token,
			dst:   map[string]any{},

			expect: map[string]any{"foo": "bar"},
		},
		{
			// RFC 7518 §3.6: an unsecured token is accepted only by a recipient configured for it.
			name: "NoPlugins",

			config: jwt.RecipientConfig{},

			token: token,
			dst:   map[string]any{},

			expectErr: jwt.ErrMismatchRecipientPlugin,
			expect:    map[string]any{},
		},
		{
			name: "IllegalCharacter",

			config: jwt.RecipientConfig{Plugins: unsecured},

			// The base64 decoder skips line breaks, so only the alphabet check rejects this one.
			token: token[:4] + "\n" + token[4:],
			dst:   map[string]any{},

			expectErr: jwt.ErrUnsupportedTokenFormat,
			expect:    map[string]any{},
		},
		{
			name: "Typ",

			config: jwt.RecipientConfig{Plugins: unsecured, Typ: "application/AT+JWT"},

			token: issueTyped("at+jwt"),
			dst:   map[string]any{},

			expect: map[string]any{"foo": "bar"},
		},
		{
			// RFC 7515 §4.1.9: parameter names ignore case, like the type and subtype.
			name: "TypParameterName",

			config: jwt.RecipientConfig{Plugins: unsecured, Typ: `application/example;Profile="admin"`},

			token: issueTyped(`EXAMPLE;profile="admin"`),
			dst:   map[string]any{},

			expect: map[string]any{"foo": "bar"},
		},
		{
			// RFC 7515 §4.1.9: parameter values keep their case.
			name: "TypParameterValue",

			config: jwt.RecipientConfig{Plugins: unsecured, Typ: `application/example;profile="admin"`},

			token: issueTyped(`example;profile="Admin"`),
			dst:   map[string]any{},

			expectErr: jwt.ErrUnexpectedTyp,
			expect:    map[string]any{},
		},
		{
			// RFC 7515 §4.1.9: a value holding any "/" does not take the "application/" prefix.
			name: "TypSlashInParameter",

			config: jwt.RecipientConfig{Plugins: unsecured, Typ: `application/example;part="1/2"`},

			token: issueTyped(`example;part="1/2"`),
			dst:   map[string]any{},

			expectErr: jwt.ErrUnexpectedTyp,
			expect:    map[string]any{},
		},
		{
			name: "UnexpectedTyp",

			config: jwt.RecipientConfig{Plugins: unsecured, Typ: "at+jwt"},

			token: token,
			dst:   map[string]any{},

			expectErr: jwt.ErrUnexpectedTyp,
			expect:    map[string]any{},
		},
		{
			name: "CustomDeserializer",

			config: jwt.RecipientConfig{
				Plugins: unsecured,
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
					&fakeRecipientPlugin{payloadErr: jwt.ErrMismatchRecipientPlugin},
					&fakeRecipientPlugin{
						payload: func(_ *jwa.JWH, _ string) []byte {
							return []byte(`{"ping":"pong"}`)
						},
					},
					// Never reached: the plugin above already consumed the token.
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
					&fakeRecipientPlugin{payloadErr: jwt.ErrMismatchRecipientPlugin},
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
					&fakeRecipientPlugin{payloadErr: jwt.ErrMismatchRecipientPlugin},
					&fakeRecipientPlugin{payloadErr: jwt.ErrMismatchRecipientPlugin},
				},
			},

			token: token,
			dst:   map[string]any{},

			expectErr: jwt.ErrMismatchRecipientPlugin,
			expect:    map[string]any{},
		},
		{
			name: "MalformedHeader/NotBase64",

			config: jwt.RecipientConfig{},

			token: testutils.UndecodableSegment + "." + tokenNotJSON.Payload,
			dst:   map[string]any{},

			expectErr: jwt.ErrUnsupportedTokenFormat,
			expect:    map[string]any{},
		},
		{
			name: "MalformedHeader/NotJSON",

			config: jwt.RecipientConfig{},

			token: base64.RawURLEncoding.EncodeToString([]byte("not json")) + "." + tokenNotJSON.Payload,
			dst:   map[string]any{},

			expectErr: jwt.ErrUnsupportedTokenFormat,
			expect:    map[string]any{},
		},
		{
			name: "MalformedPayload",

			// The payload is the plugin's to decode, so the unsecured plugin has to be listed.
			config: jwt.RecipientConfig{Plugins: unsecured},

			token: tokenNotJSON.Header + "." + testutils.UndecodableSegment,
			dst:   map[string]any{},

			expectErr: jwt.ErrUnsupportedTokenFormat,
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
			err := recipient.Consume(t.Context(), testCase.token, &testCase.dst)
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

	// A Recipient with a defaulted deserializer is shared across goroutines; the default is resolved
	// at construction, so nothing writes config here.
	recipient := jwt.NewRecipient(jwt.RecipientConfig{
		Plugins: []jwt.RecipientPlugin{jwt.NewDefaultRecipientPlugin()},
	})

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

func TestRecipientDecodeUnverifiedRejects(t *testing.T) {
	t.Parallel()

	b64 := func(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }
	goodHeader := b64(`{"alg":"HS256"}`)
	goodPayload := b64(`{"sub":"alice"}`)

	testCases := []struct {
		name  string
		token string

		// expectErr is nil where the token parses and only its claims are rejected.
		expectErr error
	}{
		{"NotThreeSegments", goodHeader + "." + goodPayload, jwt.ErrUnsupportedTokenFormat},
		{"HeaderNotBase64", testutils.UndecodableSegment + "." + goodPayload + ".sig", jwt.ErrUnsupportedTokenFormat},
		{"HeaderNotJSON", b64("not json") + "." + goodPayload + ".sig", jwt.ErrUnsupportedTokenFormat},
		{"NullHeader", b64("null") + "." + goodPayload + ".sig", jwt.ErrUnsupportedTokenFormat},
		{"PayloadNotBase64", goodHeader + "." + testutils.UndecodableSegment + ".sig", jwt.ErrUnsupportedTokenFormat},
		{"PayloadNotJSON", goodHeader + "." + b64("not json") + ".sig", nil},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			recipient := jwt.NewRecipient(jwt.RecipientConfig{})

			var claims map[string]any

			err := recipient.DecodeUnverified(testCase.token, &claims)
			require.Error(t, err)

			if testCase.expectErr != nil {
				require.ErrorIs(t, err, testCase.expectErr)
			}
		})
	}
}
