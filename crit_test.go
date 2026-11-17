package jwt_test

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/a-novel-kit/jwt/v2"
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
