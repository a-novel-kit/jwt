package jwa_test

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/a-novel-kit/jwt/jwa"
)

func TestKeySerialization(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name string

		source     jwa.JWK
		expectJSON string
		expect     jwa.JWK
	}{
		{
			name: "Basic",

			source: jwa.JWK{
				JWKCommon: jwa.JWKCommon{
					KTY:    "test-kty",
					Use:    "test-use",
					KeyOps: []jwa.KeyOp{"test-key-op"},
					Alg:    "test-alg",
					KID:    "test-kid",
				},
				Payload: json.RawMessage(`{"foo":"bar"}`),
			},

			expectJSON: `{"alg":"test-alg","foo":"bar","kid":"test-kid","kty":"test-kty","use":"test-use",
"key_ops":["test-key-op"]}`,
			expect: jwa.JWK{
				JWKCommon: jwa.JWKCommon{
					KTY:    "test-kty",
					Use:    "test-use",
					KeyOps: []jwa.KeyOp{"test-key-op"},
					Alg:    "test-alg",
					KID:    "test-kid",
				},

				Payload: json.RawMessage(`{"alg":"test-alg","foo":"bar","kid":"test-kid","kty":"test-kty",

"use":"test-use","key_ops":["test-key-op"]}`),
			},
		},
		{
			name: "Conflict",
			source: jwa.JWK{
				JWKCommon: jwa.JWKCommon{
					KTY:    "test-kty",
					Use:    "test-use",
					KeyOps: []jwa.KeyOp{"test-key-op"},
					Alg:    "test-alg",
					KID:    "test-kid",
				},
				Payload: json.RawMessage(`{"kty":"bar"}`),
			},

			expectJSON: `{"alg":"test-alg","kid":"test-kid","kty":"bar","use":"test-use","key_ops":["test-key-op"]}`,
			expect: jwa.JWK{
				JWKCommon: jwa.JWKCommon{
					KTY:    "bar",
					Use:    "test-use",
					KeyOps: []jwa.KeyOp{"test-key-op"},
					Alg:    "test-alg",
					KID:    "test-kid",
				},

				Payload: json.RawMessage(`{"alg":"test-alg","kid":"test-kid","kty":"bar","use":"test-use",
"key_ops":["test-key-op"]}`),
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			serialized, err := json.Marshal(testCase.source)
			require.NoError(t, err)
			require.JSONEq(t, testCase.expectJSON, string(serialized))

			var unpacked jwa.JWK

			err = json.Unmarshal(serialized, &unpacked)
			require.NoError(t, err)
			require.Equal(t, testCase.expect.JWKCommon, unpacked.JWKCommon)
			require.JSONEq(t, string(testCase.expect.Payload), string(unpacked.Payload))
		})
	}
}
