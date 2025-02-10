package jwp_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/a-novel-kit/jwt"
	"github.com/a-novel-kit/jwt/jwp"
)

func TestClaimsChecker(t *testing.T) {
	t.Parallel()

	hourAgo := time.Now().Add(-time.Hour).Unix()
	hourAfter := time.Now().Add(time.Hour).Unix()

	testCases := []struct {
		name string

		config *jwp.ClaimsCheckerConfig

		raw any
		dst any

		expect    any
		expectErr error
	}{
		{
			name: "Minimalistic",

			config: &jwp.ClaimsCheckerConfig{},

			raw: map[string]any{"foo": "bar"},

			dst:    map[string]any{},
			expect: map[string]any{"foo": "bar"},
		},
		{
			name: "WithTarget/Success",

			config: &jwp.ClaimsCheckerConfig{
				Target: &jwt.TargetConfig{
					Audience: "audience",
					Issuer:   "issuer",
					Subject:  "subject",
				},
			},

			raw: map[string]any{
				"aud": "audience",
				"iss": "issuer",
				"sub": "subject",
				"foo": "bar",
			},

			dst: map[string]any{},

			expect: map[string]any{
				"aud": "audience",
				"iss": "issuer",
				"sub": "subject",
				"foo": "bar",
			},
		},
		{
			name: "WithTarget/InvalidAudience",

			config: &jwp.ClaimsCheckerConfig{
				Target: &jwt.TargetConfig{
					Audience: "audience",
					Issuer:   "issuer",
					Subject:  "subject",
				},
			},

			raw: map[string]any{
				"aud": "fake-audience",
				"iss": "issuer",
				"sub": "subject",
				"foo": "bar",
			},

			dst: map[string]any{},

			expect:    map[string]any{},
			expectErr: jwp.ErrInvalidClaims,
		},
		{
			name: "WithTarget/InvalidIssuer",

			config: &jwp.ClaimsCheckerConfig{
				Target: &jwt.TargetConfig{
					Audience: "audience",
					Issuer:   "issuer",
					Subject:  "subject",
				},
			},

			raw: map[string]any{
				"aud": "audience",
				"iss": "fake-issuer",
				"sub": "subject",
				"foo": "bar",
			},

			dst: map[string]any{},

			expect:    map[string]any{},
			expectErr: jwp.ErrInvalidClaims,
		},
		{
			name: "WithTarget/InvalidSubject",

			config: &jwp.ClaimsCheckerConfig{
				Target: &jwt.TargetConfig{
					Audience: "audience",
					Issuer:   "issuer",
					Subject:  "subject",
				},
			},

			raw: map[string]any{
				"aud": "audience",
				"iss": "issuer",
				"sub": "fake-subject",
				"foo": "bar",
			},

			dst: map[string]any{},

			expect:    map[string]any{},
			expectErr: jwp.ErrInvalidClaims,
		},
		{
			name: "NotBefore/Success",

			config: &jwp.ClaimsCheckerConfig{},

			raw: map[string]any{
				"nbf": hourAgo,
				"foo": "bar",
			},

			dst: map[string]any{},

			expect: map[string]any{
				"nbf": float64(hourAgo),
				"foo": "bar",
			},
		},
		{
			name: "NotBefore/Failure",

			config: &jwp.ClaimsCheckerConfig{},

			raw: map[string]any{
				"nbf": hourAfter,
				"foo": "bar",
			},

			dst: map[string]any{},

			expect:    map[string]any{},
			expectErr: jwp.ErrInvalidClaims,
		},
		{
			name: "Exp/Success",

			config: &jwp.ClaimsCheckerConfig{},

			raw: map[string]any{
				"exp": hourAfter,
				"foo": "bar",
			},

			dst: map[string]any{},

			expect: map[string]any{
				"exp": float64(hourAfter),
				"foo": "bar",
			},
		},
		{
			name: "Exp/Failure",

			config: &jwp.ClaimsCheckerConfig{},

			raw: map[string]any{
				"exp": hourAgo,
				"foo": "bar",
			},

			dst: map[string]any{},

			expect: map[string]any{},

			expectErr: jwp.ErrInvalidClaims,
		},
		{
			name: "Exp/Failure/Required",

			config: &jwp.ClaimsCheckerConfig{
				RequireExpiration: true,
			},

			raw: map[string]any{
				"foo": "bar",
			},

			dst: map[string]any{},

			expect: map[string]any{},

			expectErr: jwp.ErrInvalidClaims,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			serialized, err := json.Marshal(testCase.raw)
			require.NoError(t, err)

			checker := jwp.NewClaimsChecker(testCase.config)

			err = checker.Unmarshal(serialized, &testCase.dst)
			require.ErrorIs(t, err, testCase.expectErr)
			require.Equal(t, testCase.expect, testCase.dst)
		})
	}
}
