package jwt_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
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
	token, err := producer.Issue(t.Context(), map[string]any{"foo": "bar"}, nil)
	require.NoError(t, err)

	tokenNotJSON, err := (&jwt.SignedTokenDecoder{}).Decode(token)
	require.NoError(t, err)

	tokenNotJSON.Payload = base64.RawURLEncoding.EncodeToString([]byte("qux"))

	issueTyped := func(typ jwa.Typ) string {
		typed, err := jwt.NewProducer(jwt.ProducerConfig{Header: jwt.HeaderProducerConfig{Typ: typ}}).
			Issue(t.Context(), map[string]any{"foo": "bar"}, nil)
		require.NoError(t, err)

		return typed
	}

	critToken, err := jwt.NewProducer(jwt.ProducerConfig{Header: jwt.HeaderProducerConfig{Crit: []string{"foo"}}}).
		Issue(t.Context(), map[string]any{"sub": "x"}, map[string]any{"foo": "bar"})
	require.NoError(t, err)

	unsecured := []jwt.RecipientPlugin{jwt.NewDefaultRecipientPlugin()}

	encode := base64.RawURLEncoding.EncodeToString
	claimsSegment := encode([]byte(`{"foo":"bar"}`))

	testCases := []struct {
		name string

		config jwt.RecipientConfig

		token string
		dst   any

		expect    any
		expectErr error
		// expectRejected is whether the error matches jwt.ErrTokenRejected.
		expectRejected bool
	}{
		{
			name: "Success",

			config: jwt.RecipientConfig{Plugins: unsecured},

			token: token,
			dst:   map[string]any{},

			expect: map[string]any{"foo": "bar"},
		},
		{
			// RFC 7518 §3.6: an unsecured token is accepted only by a recipient configured for it.
			name: "Error/NoPlugins",

			config: jwt.RecipientConfig{},

			token: token,
			dst:   map[string]any{},

			expectErr:      jwt.ErrMismatchRecipientPlugin,
			expectRejected: true,
			expect:         map[string]any{},
		},
		{
			name: "Error/IllegalCharacter",

			config: jwt.RecipientConfig{Plugins: unsecured},

			// The base64 decoder skips line breaks, so only the alphabet check rejects this one.
			token: token[:4] + "\n" + token[4:],
			dst:   map[string]any{},

			expectErr:      jwt.ErrUnsupportedTokenFormat,
			expectRejected: true,
			expect:         map[string]any{},
		},
		{
			// Releases up to v2.6.0 issued unsecured tokens without the empty signature segment.
			name: "Success/LegacyUnsecured",

			config: jwt.RecipientConfig{Plugins: unsecured},

			token: strings.TrimSuffix(token, "."),
			dst:   map[string]any{},

			expect: map[string]any{"foo": "bar"},
		},
		{
			// RFC 7518 §3.6: the signature of an unsecured JWS is the empty octet sequence.
			name: "Error/UnsecuredWithSignature",

			config: jwt.RecipientConfig{Plugins: unsecured},

			token: token + "c2ln",
			dst:   map[string]any{},

			expectErr:      jwt.ErrUnsupportedTokenFormat,
			expectRejected: true,
			expect:         map[string]any{},
		},
		{
			// RFC 7515 §4.1.1: "alg" is required, so its absence does not read as "none".
			name: "Error/MissingAlg",

			config: jwt.RecipientConfig{Plugins: unsecured},

			token: encode([]byte(`{}`)) + "." + claimsSegment + ".",
			dst:   map[string]any{},

			expectErr:      jwt.ErrUnsupportedTokenFormat,
			expectRejected: true,
			expect:         map[string]any{},
		},
		{
			// RFC 7515 §5.2 step 3: the header is UTF-8.
			name: "Error/InvalidUTF8Header",

			config: jwt.RecipientConfig{Plugins: unsecured},

			token: encode([]byte("{\"alg\":\"none\",\"x\":\"\xff\"}")) + "." + claimsSegment + ".",
			dst:   map[string]any{},

			expectErr:      jwt.ErrUnsupportedTokenFormat,
			expectRejected: true,
			expect:         map[string]any{},
		},
		{
			// RFC 7519 §7.2 step 10: the claims set is UTF-8.
			name: "Error/InvalidUTF8Claims",

			config: jwt.RecipientConfig{Plugins: unsecured},

			token: encode([]byte(`{"alg":"none"}`)) + "." + encode([]byte("{\"foo\":\"\xff\"}")) + ".",
			dst:   map[string]any{},

			expectErr:      jwt.ErrUnsupportedTokenFormat,
			expectRejected: true,
			expect:         map[string]any{},
		},
		{
			name: "Success/Typ",

			config: jwt.RecipientConfig{Plugins: unsecured, Typ: "application/AT+JWT"},

			token: issueTyped("at+jwt"),
			dst:   map[string]any{},

			expect: map[string]any{"foo": "bar"},
		},
		{
			// RFC 7515 §4.1.9: parameter names ignore case, like the type and subtype.
			name: "Success/TypParameterName",

			config: jwt.RecipientConfig{Plugins: unsecured, Typ: `application/example;Profile="admin"`},

			token: issueTyped(`EXAMPLE;profile="admin"`),
			dst:   map[string]any{},

			expect: map[string]any{"foo": "bar"},
		},
		{
			// RFC 7515 §4.1.9: parameter values keep their case.
			name: "Error/TypParameterValue",

			config: jwt.RecipientConfig{Plugins: unsecured, Typ: `application/example;profile="admin"`},

			token: issueTyped(`example;profile="Admin"`),
			dst:   map[string]any{},

			expectErr:      jwt.ErrUnexpectedTyp,
			expectRejected: true,
			expect:         map[string]any{},
		},
		{
			// RFC 7515 §4.1.9: a value holding any "/" does not take the "application/" prefix.
			name: "Error/TypSlashInParameter",

			config: jwt.RecipientConfig{Plugins: unsecured, Typ: `application/example;part="1/2"`},

			token: issueTyped(`example;part="1/2"`),
			dst:   map[string]any{},

			expectErr:      jwt.ErrUnexpectedTyp,
			expectRejected: true,
			expect:         map[string]any{},
		},
		{
			name: "Error/UnexpectedTyp",

			config: jwt.RecipientConfig{Plugins: unsecured, Typ: "at+jwt"},

			token: token,
			dst:   map[string]any{},

			expectErr:      jwt.ErrUnexpectedTyp,
			expectRejected: true,
			expect:         map[string]any{},
		},
		{
			name: "Success/CustomDeserializer",

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
			name: "Success/Plugins",

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
			name: "Error/Plugin",

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
			name: "Error/NoPluginFound",

			config: jwt.RecipientConfig{
				Plugins: []jwt.RecipientPlugin{
					&fakeRecipientPlugin{payloadErr: jwt.ErrMismatchRecipientPlugin},
					&fakeRecipientPlugin{payloadErr: jwt.ErrMismatchRecipientPlugin},
				},
			},

			token: token,
			dst:   map[string]any{},

			expectErr:      jwt.ErrMismatchRecipientPlugin,
			expectRejected: true,
			expect:         map[string]any{},
		},
		{
			name: "Error/MalformedHeader/NotBase64",

			config: jwt.RecipientConfig{},

			token: testutils.UndecodableSegment + "." + tokenNotJSON.Payload,
			dst:   map[string]any{},

			expectErr:      jwt.ErrUnsupportedTokenFormat,
			expectRejected: true,
			expect:         map[string]any{},
		},
		{
			name: "Error/MalformedHeader/NotJSON",

			config: jwt.RecipientConfig{},

			token: base64.RawURLEncoding.EncodeToString([]byte("not json")) + "." + tokenNotJSON.Payload,
			dst:   map[string]any{},

			expectErr:      jwt.ErrUnsupportedTokenFormat,
			expectRejected: true,
			expect:         map[string]any{},
		},
		{
			// A header of JSON null unmarshals to a nil pointer; Consume must reject it, not panic.
			name: "Error/MalformedHeader/Null",

			config: jwt.RecipientConfig{},

			token: encode([]byte("null")) + "." + claimsSegment,
			dst:   map[string]any{},

			expectErr:      jwt.ErrUnsupportedTokenFormat,
			expectRejected: true,
			expect:         map[string]any{},
		},
		{
			// A present-but-empty crit list is invalid per RFC 7515 §4.1.11.
			name: "Error/MalformedHeader/EmptyCrit",

			config: jwt.RecipientConfig{},

			token: encode([]byte(`{"alg":"none","crit":[]}`)) + "." + claimsSegment,
			dst:   map[string]any{},

			expectErr:      jwt.ErrUnsupportedCritHeader,
			expectRejected: true,
			expect:         map[string]any{},
		},
		{
			// No CriticalHeaders configured: a token that marks "foo" critical must be rejected.
			name: "Error/Crit/NotUnderstood",

			config: jwt.RecipientConfig{},

			token: critToken,
			dst:   map[string]any{},

			expectErr:      jwt.ErrUnsupportedCritHeader,
			expectRejected: true,
			expect:         map[string]any{},
		},
		{
			name: "Success/Crit/Understood",

			config: jwt.RecipientConfig{Plugins: unsecured, CriticalHeaders: []string{"foo"}},

			token: critToken,
			dst:   map[string]any{},

			expect: map[string]any{"sub": "x"},
		},
		{
			name: "Error/MalformedPayload",

			// The payload is the plugin's to decode, so the unsecured plugin has to be listed.
			config: jwt.RecipientConfig{Plugins: unsecured},

			token: tokenNotJSON.Header + "." + testutils.UndecodableSegment,
			dst:   map[string]any{},

			expectErr:      jwt.ErrUnsupportedTokenFormat,
			expectRejected: true,
			expect:         map[string]any{},
		},
		{
			name: "Error/TokenTooLarge",

			config: jwt.RecipientConfig{MaxTokenBytes: 8},

			token: token,
			dst:   map[string]any{},

			expectErr:      jwt.ErrTokenTooLarge,
			expectRejected: true,
			expect:         map[string]any{},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			recipient := jwt.NewRecipient(testCase.config)
			err := recipient.Consume(t.Context(), testCase.token, &testCase.dst)
			require.ErrorIs(t, err, testCase.expectErr)
			require.Equal(t, testCase.expectRejected, errors.Is(err, jwt.ErrTokenRejected))
			require.Equal(t, testCase.expect, testCase.dst)
		})
	}

	t.Run("Error/CaseVariantHeader", func(t *testing.T) {
		t.Parallel()

		// A verifier routes on alg, and a parser that matches names exactly reads HS256 from this
		// header. encoding/json alone would decode alg as none.
		header := encode([]byte(`{"alg":"HS256","ALG":"none"}`))
		payload := encode([]byte(`{"role":"admin"}`))

		recipient := jwt.NewRecipient(jwt.RecipientConfig{Plugins: unsecured})

		var claims map[string]any

		err := recipient.Consume(t.Context(), header+"."+payload, &claims)
		require.ErrorIs(t, err, jwt.ErrUnsupportedTokenFormat)
		require.ErrorIs(t, err, jwa.ErrReservedMember)
	})

	t.Run("Success/Concurrent", func(t *testing.T) {
		t.Parallel()

		// A Recipient with a defaulted deserializer is shared across goroutines; the default is
		// resolved at construction, so nothing writes config here.
		recipient := jwt.NewRecipient(jwt.RecipientConfig{Plugins: unsecured})

		var wg sync.WaitGroup

		for range 16 {
			wg.Go(func() {
				dst := map[string]any{}

				err := recipient.Consume(t.Context(), token, &dst)
				if err != nil {
					t.Errorf("concurrent consume: %v", err)
				}
			})
		}

		wg.Wait()
	})
}

func TestRecipientDecodeUnverified(t *testing.T) {
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
		t.Run("Error/"+testCase.name, func(t *testing.T) {
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

	t.Run("Success", func(t *testing.T) {
		t.Parallel()

		// The signature of this token never verifies, and DecodeUnverified reads its claims anyway.
		token := goodHeader + "." + b64(`{"sub":"alice","jti":"abc"}`) + ".not-a-real-signature"

		recipient := jwt.NewRecipient(jwt.RecipientConfig{})

		var claims map[string]any

		require.NoError(t, recipient.DecodeUnverified(token, &claims))
		require.Equal(t, map[string]any{"sub": "alice", "jti": "abc"}, claims)
	})

	t.Run("Error/TooLarge", func(t *testing.T) {
		t.Parallel()

		recipient := jwt.NewRecipient(jwt.RecipientConfig{MaxTokenBytes: 8})

		var claims map[string]any

		require.ErrorIs(t, recipient.DecodeUnverified("aaaa.bbbb.cccc", &claims), jwt.ErrTokenTooLarge)
	})
}
