package jwa_test

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/a-novel-kit/jwt/v2/jwa"
)

func TestAudienceMarshal(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name string
		aud  jwa.Audience
		want string
	}{
		{"Single", jwa.Audience{"a"}, `"a"`},
		{"Multiple", jwa.Audience{"a", "b"}, `["a","b"]`},
		{"Empty", jwa.Audience{}, `[]`},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			got, err := json.Marshal(testCase.aud)
			require.NoError(t, err)
			require.Equal(t, testCase.want, string(got))
		})
	}
}

func TestAudienceUnmarshal(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name string
		raw  string
		want jwa.Audience
	}{
		{"String", `"a"`, jwa.Audience{"a"}},
		{"Array", `["a","b"]`, jwa.Audience{"a", "b"}},
		{"Null", `null`, nil},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			var aud jwa.Audience

			require.NoError(t, json.Unmarshal([]byte(testCase.raw), &aud))
			require.Equal(t, testCase.want, aud)
		})
	}
}
