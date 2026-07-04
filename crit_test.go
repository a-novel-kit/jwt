package jwt_test

import (
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
			name: "EmptyCritPasses",
			data: json.RawMessage(`{}`),
			crit: nil,
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
