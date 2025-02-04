package jwt_test

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/a-novel-kit/jwt"
	"github.com/a-novel-kit/jwt/jwa"
)

func TestNewBasicHeaderProducer(t *testing.T) {
	testCases := []struct {
		name string

		config jwt.HeaderProducerConfig
		custom any

		expect    string
		expectErr error
	}{
		{
			name:   "NoConfig",
			config: jwt.HeaderProducerConfig{},
			expect: `{"alg":"none"}`,
		},
		{
			name: "BasicFields",
			config: jwt.HeaderProducerConfig{
				Typ: jwa.TypJOSE,
				CTY: jwa.CtyJWT,
				TargetConfig: jwt.TargetConfig{
					Issuer:   "issuer",
					Subject:  "subject",
					Audience: "audience",
				},
			},
			expect: `{"alg":"none","typ":"JOSE","cty":"JWT","iss":"issuer","sub":"subject","aud":"audience"}`,
		},
		{
			name: "CritFields",

			config: jwt.HeaderProducerConfig{
				Crit: []string{"crit1", "crit2"},
			},

			custom: map[string]any{
				"crit1": "value1",
				"crit2": 123,
			},

			expect: `{"alg":"none","crit":["crit1","crit2"],"crit1":"value1","crit2":123}`,
		},
		{
			name: "NoExtraHeaderWithCrit",

			config: jwt.HeaderProducerConfig{
				Crit: []string{"crit1", "crit2"},
			},

			expectErr: jwt.ErrMissingCritHeader,
		},
		{
			name: "MissingCrit",

			config: jwt.HeaderProducerConfig{
				Crit: []string{"crit1", "crit2"},
			},

			custom: map[string]any{
				"crit2": 123,
			},

			expectErr: jwt.ErrMissingCritHeader,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			producer := jwt.NewHeaderProducer(testCase.config)

			result, err := producer.New(testCase.custom)
			require.ErrorIs(t, err, testCase.expectErr)

			if testCase.expectErr == nil {
				headerJSON, err := json.Marshal(result)
				require.NoError(t, err)
				require.JSONEq(t, testCase.expect, string(headerJSON))
			}
		})
	}
}
