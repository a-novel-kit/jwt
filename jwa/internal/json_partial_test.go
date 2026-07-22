package internal_test

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/a-novel-kit/jwt/v2/jwa/internal"
)

func TestMarshalPartial(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name string

		value any
		extra json.RawMessage

		expect      []byte
		expectNames string
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

			expectNames: "b",
		},
		{
			// The names are sorted, so one input yields one message.
			name: "SeveralOverlaps",

			value: map[string]string{
				"a": "foo",
				"b": "bar",
			},
			extra: json.RawMessage(`{"b":"qux","a":"quux"}`),

			expectNames: "a, b",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			actual, err := internal.MarshalPartial(testCase.value, testCase.extra)

			if testCase.expectNames != "" {
				require.ErrorIs(t, err, internal.ErrReservedMember)
				require.ErrorContains(t, err, testCase.expectNames)
				require.Nil(t, actual)

				return
			}

			require.NoError(t, err)
			require.JSONEq(t, string(testCase.expect), string(actual))
		})
	}
}

// A registered parameter is reserved whether or not the value being encoded
// carries one. Every registered parameter in this library is omitempty, so an
// unset one encodes to nothing and a check against the encoded object would
// leave exactly the absent parameters open.
func TestMarshalPartialReservesUnsetMembers(t *testing.T) {
	t.Parallel()

	type embedded struct {
		Kid string `json:"kid,omitempty"`
	}

	type common struct {
		embedded

		Alg     string `json:"alg,omitempty"`
		Exp     int64  `json:"exp,omitempty"`
		Renamed string `json:"cty,omitempty"`
		Skipped string `json:"-"`
		Untaged string
	}

	// Nothing is set, so alg, exp, cty and kid are absent from the encoding, and
	// each is reserved below on the strength of the declaration alone. Untaged
	// carries no tag and so cannot be omitempty, which is why it is here.
	require.JSONEq(t, `{"Untaged":""}`, string(mustMarshal(t, common{})))

	for _, name := range []string{"alg", "exp", "cty", "kid", "Untaged"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, err := internal.MarshalPartial(common{}, json.RawMessage(`{"`+name+`":"injected"}`))
			require.ErrorIs(t, err, internal.ErrReservedMember)
			require.ErrorContains(t, err, name)
		})
	}

	t.Run("a field the encoding drops is not reserved", func(t *testing.T) {
		t.Parallel()

		// `json:"-"` means the member never appears, so a custom member of that
		// name collides with nothing.
		out, err := internal.MarshalPartial(common{}, json.RawMessage(`{"Skipped":"mine"}`))
		require.NoError(t, err)
		require.JSONEq(t, `{"Untaged":"","Skipped":"mine"}`, string(out))
	})

	t.Run("an unrelated member still passes through", func(t *testing.T) {
		t.Parallel()

		out, err := internal.MarshalPartial(common{Alg: "HS256"}, json.RawMessage(`{"role":"admin"}`))
		require.NoError(t, err)
		require.JSONEq(t, `{"Untaged":"","alg":"HS256","role":"admin"}`, string(out))
	})
}

// An embedded field is reserved on the same terms encoding/json encodes it on,
// which differ by what is embedded. The encoding is asserted first in each case,
// so the rule is pinned against the encoder rather than against a reading of it.
func TestMarshalPartialReservesEmbeddedMembers(t *testing.T) {
	t.Parallel()

	type Promoted struct {
		Kid string `json:"kid,omitempty"`
	}

	type Named string

	type hidden string

	type Empty struct{}

	type common struct {
		Promoted // a struct: promotes kid
		Named    // not a struct: encodes under its type name
		hidden   // not a struct and unexported: encodes nothing
		Empty    // a struct with nothing to promote
	}

	require.JSONEq(t, `{"Named":""}`, string(mustMarshal(t, common{hidden: "set"})),
		"the encoder names an embedded non-struct after its type and drops an unexported one")

	for _, name := range []string{"kid", "Named"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, err := internal.MarshalPartial(common{}, json.RawMessage(`{"`+name+`":"injected"}`))
			require.ErrorIs(t, err, internal.ErrReservedMember)
		})
	}

	t.Run("an embedded type that encodes nothing reserves nothing", func(t *testing.T) {
		t.Parallel()

		// Empty promotes no member and hidden encodes none, so neither type name
		// is taken.
		out, err := internal.MarshalPartial(common{}, json.RawMessage(`{"Empty":1,"hidden":2}`))
		require.NoError(t, err)
		require.JSONEq(t, `{"Named":"","Empty":1,"hidden":2}`, string(out))
	})
}

func mustMarshal(t *testing.T, v any) []byte {
	t.Helper()

	out, err := json.Marshal(v)
	require.NoError(t, err)

	return out
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
