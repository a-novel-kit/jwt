package internal_test

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/a-novel-kit/jwt/jwa/internal"
)

func TestMarshalPartial(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name string

		value any
		extra json.RawMessage

		expect []byte
	}{
		{
			name: "Success",

			value: map[string]string{
				"a": "foo",
				"b": "bar",
			},
			extra: json.RawMessage(`{"c":"baz"}`),

			expect: []byte(`{"a":"foo","b":"bar","c":"baz"}`),
		},
		{
			name: "NoExtra",

			value: map[string]string{
				"a": "foo",
				"b": "bar",
			},

			expect: []byte(`{"a":"foo","b":"bar"}`),
		},
		{
			name: "Overlap",

			value: map[string]string{
				"a": "foo",
				"b": "bar",
			},
			extra: json.RawMessage(`{"b":"qux","c":"baz"}`),

			expect: []byte(`{"a":"foo","b":"qux","c":"baz"}`),
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			actual, err := internal.MarshalPartial(testCase.value, testCase.extra)
			require.NoError(t, err)
			require.JSONEq(t, string(testCase.expect), string(actual))
		})
	}
}

func TestUnmarshalPartial(t *testing.T) {
	t.Parallel()

	type partialType struct {
		A string `json:"a"`
		B string `json:"b"`
	}

	testCases := []struct {
		name string

		src []byte

		expect any
		extra  json.RawMessage
	}{
		{
			name: "Success",

			src: []byte(`{"a":"foo","b":"bar","c":"baz"}`),

			expect: partialType{
				A: "foo",
				B: "bar",
			},
			extra: json.RawMessage(`{"a":"foo","b":"bar","c":"baz"}`),
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			actual, extra, err := internal.UnmarshalPartial[partialType](testCase.src)
			require.NoError(t, err)
			require.Equal(t, testCase.expect, actual)
			require.JSONEq(t, string(testCase.extra), string(extra))
		})
	}
}
