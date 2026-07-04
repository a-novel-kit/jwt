package jwt_test

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/a-novel-kit/jwt"
)

func TestCheckCritUnderstood(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name string

		data       json.RawMessage
		crit       []string
		understood []string

		expectErr error
	}{
		{
			name:       "OK",
			data:       json.RawMessage(`{"foo":"bar"}`),
			crit:       []string{"foo"},
			understood: []string{"foo"},
		},
		{
			name:      "EmptyCritRejected",
			data:      json.RawMessage(`{}`),
			crit:      []string{},
			expectErr: jwt.ErrUnsupportedCritHeader,
		},
		{
			name:       "NotUnderstood",
			data:       json.RawMessage(`{"foo":"bar"}`),
			crit:       []string{"foo"},
			understood: nil,
			expectErr:  jwt.ErrUnsupportedCritHeader,
		},
		{
			name:       "ReservedParam",
			data:       json.RawMessage(`{"alg":"none"}`),
			crit:       []string{"alg"},
			understood: []string{"alg"},
			expectErr:  jwt.ErrUnsupportedCritHeader,
		},
		{
			name:       "UnderstoodButAbsent",
			data:       json.RawMessage(`{}`),
			crit:       []string{"foo"},
			understood: []string{"foo"},
			expectErr:  jwt.ErrMissingCritHeader,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			err := jwt.CheckCritUnderstood(testCase.data, testCase.crit, testCase.understood)

			if testCase.expectErr != nil {
				require.ErrorIs(t, err, testCase.expectErr)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestRecipientCrit(t *testing.T) {
	t.Parallel()

	producer := jwt.NewProducer(jwt.ProducerConfig{
		Header: jwt.HeaderProducerConfig{Crit: []string{"foo"}},
	})

	token, err := producer.Issue(t.Context(), map[string]any{"sub": "x"}, map[string]any{"foo": "bar"})
	require.NoError(t, err)

	t.Run("RejectedByDefault", func(t *testing.T) {
		t.Parallel()

		// No CriticalHeaders configured: a token that marks "foo" critical must be rejected.
		recipient := jwt.NewRecipient(jwt.RecipientConfig{})

		var claims map[string]any
		require.ErrorIs(t, recipient.Consume(t.Context(), token, &claims), jwt.ErrUnsupportedCritHeader)
	})

	t.Run("AcceptedWhenUnderstood", func(t *testing.T) {
		t.Parallel()

		recipient := jwt.NewRecipient(jwt.RecipientConfig{CriticalHeaders: []string{"foo"}})

		var claims map[string]any
		require.NoError(t, recipient.Consume(t.Context(), token, &claims))
	})
}

func TestRecipientMalformedHeader(t *testing.T) {
	t.Parallel()

	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"x"}`))
	recipient := jwt.NewRecipient(jwt.RecipientConfig{})

	t.Run("NullHeader", func(t *testing.T) {
		t.Parallel()

		// A header of JSON null unmarshals to a nil pointer; Consume must reject it, not panic.
		token := base64.RawURLEncoding.EncodeToString([]byte("null")) + "." + payload

		var claims map[string]any
		require.Error(t, recipient.Consume(t.Context(), token, &claims))
	})

	t.Run("EmptyCrit", func(t *testing.T) {
		t.Parallel()

		// A present-but-empty crit list is invalid per RFC 7515 §4.1.11.
		token := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","crit":[]}`)) + "." + payload

		var claims map[string]any
		require.ErrorIs(t, recipient.Consume(t.Context(), token, &claims), jwt.ErrUnsupportedCritHeader)
	})
}
