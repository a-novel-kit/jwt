package jwk_test

import (
	"context"
	"errors"
	"log"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/a-novel-kit/jwt/jwa"
	"github.com/a-novel-kit/jwt/jwk"
)

type simulatedParserResp[K any] struct {
	key *jwk.Key[K]
	err error
}

type simulateParser[K any] struct {
	responses []simulatedParserResp[K]
	pos       int
}

func (sp *simulateParser[K]) parse(_ context.Context, _ *jwa.JWK) (*jwk.Key[K], error) {
	if sp.pos >= len(sp.responses) {
		log.Fatalln("simulateParser.parse: no more responses to give")
	}

	resp := sp.responses[sp.pos]
	sp.pos++

	return resp.key, resp.err
}

func TestSourceList(t *testing.T) {
	t.Parallel()

	errFoo := errors.New("foo")

	testCases := []struct {
		name string

		fetcherResp []*jwa.JWK
		fetcherErr  error

		parserResponses []simulatedParserResp[string]

		expect    []*jwk.Key[string]
		expectErr error
	}{
		{
			name: "Success",

			fetcherResp: []*jwa.JWK{
				newBullshitKey[string](t, "kid-1").JWK,
				newBullshitKey[string](t, "kid-2").JWK,
			},

			parserResponses: []simulatedParserResp[string]{
				{key: newBullshitKey[string](t, "kid-1")},
				{key: newBullshitKey[string](t, "kid-2")},
			},

			expect: []*jwk.Key[string]{
				newBullshitKey[string](t, "kid-1"),
				newBullshitKey[string](t, "kid-2"),
			},
		},
		{
			name:       "FetcherError",
			fetcherErr: errFoo,
			expectErr:  errFoo,
		},
		{
			name: "ParserError",

			fetcherResp: []*jwa.JWK{
				newBullshitKey[string](t, "kid-1").JWK,
				newBullshitKey[string](t, "kid-2").JWK,
				newBullshitKey[string](t, "kid-3").JWK,
			},

			parserResponses: []simulatedParserResp[string]{
				{key: newBullshitKey[string](t, "kid-1")},
				{err: errFoo},
			},

			expectErr: errFoo,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			config := jwk.SourceConfig{
				Fetch: func(_ context.Context) ([]*jwa.JWK, error) {
					return testCase.fetcherResp, testCase.fetcherErr
				},
			}

			parser := simulateParser[string]{responses: testCase.parserResponses}

			source := jwk.NewGenericSource[string](config, parser.parse)

			keys, err := source.List(t.Context())
			require.ErrorIs(t, err, testCase.expectErr)
			require.Equal(t, testCase.expect, keys)
		})
	}
}

func TestSourceGet(t *testing.T) {
	t.Parallel()

	errFoo := errors.New("foo")

	testCases := []struct {
		name string

		kid string

		fetcherResp []*jwa.JWK
		fetcherErr  error

		parserResponses []simulatedParserResp[string]

		expect    *jwk.Key[string]
		expectErr error
	}{
		{
			name: "Success",

			fetcherResp: []*jwa.JWK{
				newBullshitKey[string](t, "kid-1").JWK,
				newBullshitKey[string](t, "kid-2").JWK,
			},

			parserResponses: []simulatedParserResp[string]{
				{key: newBullshitKey[string](t, "kid-1")},
				{key: newBullshitKey[string](t, "kid-2")},
			},

			expect: newBullshitKey[string](t, "kid-1"),
		},
		{
			name: "KID",

			fetcherResp: []*jwa.JWK{
				newBullshitKey[string](t, "kid-1").JWK,
				newBullshitKey[string](t, "kid-2").JWK,
			},

			kid: "kid-2",

			parserResponses: []simulatedParserResp[string]{
				{key: newBullshitKey[string](t, "kid-1")},
				{key: newBullshitKey[string](t, "kid-2")},
			},

			expect: newBullshitKey[string](t, "kid-2"),
		},
		{
			name:       "FetcherError",
			fetcherErr: errFoo,
			expectErr:  errFoo,
		},
		{
			name: "ParserError",

			fetcherResp: []*jwa.JWK{
				newBullshitKey[string](t, "kid-1").JWK,
				newBullshitKey[string](t, "kid-2").JWK,
				newBullshitKey[string](t, "kid-3").JWK,
			},

			parserResponses: []simulatedParserResp[string]{
				{key: newBullshitKey[string](t, "kid-1")},
				{err: errFoo},
			},

			expectErr: errFoo,
		},
		{
			name: "NoKey",

			fetcherResp: []*jwa.JWK{},

			expectErr: jwk.ErrKeyNotFound,
		},
		{
			name: "KIDNotFound",

			fetcherResp: []*jwa.JWK{
				newBullshitKey[string](t, "kid-1").JWK,
				newBullshitKey[string](t, "kid-2").JWK,
			},

			kid: "kid-3",

			parserResponses: []simulatedParserResp[string]{
				{key: newBullshitKey[string](t, "kid-1")},
				{key: newBullshitKey[string](t, "kid-2")},
			},

			expectErr: jwk.ErrKeyNotFound,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			config := jwk.SourceConfig{
				Fetch: func(_ context.Context) ([]*jwa.JWK, error) {
					return testCase.fetcherResp, testCase.fetcherErr
				},
			}

			parser := simulateParser[string]{responses: testCase.parserResponses}

			source := jwk.NewGenericSource[string](config, parser.parse)

			key, err := source.Get(t.Context(), testCase.kid)
			require.ErrorIs(t, err, testCase.expectErr)
			require.Equal(t, testCase.expect, key)
		})
	}
}

func TestSourceRefresh(t *testing.T) {
	t.Parallel()

	var keys []*jwa.JWK

	keys = []*jwa.JWK{
		newBullshitKey[string](t, `"number":1`).JWK,
		newBullshitKey[string](t, `"number":2`).JWK,
	}

	fetcher := func(_ context.Context) ([]*jwa.JWK, error) {
		// Copy the array to prevent side effects.
		copied := make([]*jwa.JWK, len(keys))
		copy(copied, keys)

		return copied, nil
	}

	parser := func(_ context.Context, jsonKey *jwa.JWK) (*jwk.Key[string], error) {
		return &jwk.Key[string]{JWK: jsonKey}, nil
	}

	config := jwk.SourceConfig{Fetch: fetcher, CacheDuration: 100 * time.Millisecond}

	source := jwk.NewGenericSource[string](config, parser)

	fetchedKeys, err := source.List(t.Context())
	require.NoError(t, err)
	require.Equal(t, []*jwk.Key[string]{
		newBullshitKey[string](t, `"number":1`),
		newBullshitKey[string](t, `"number":2`),
	}, fetchedKeys)

	keys = []*jwa.JWK{
		newBullshitKey[string](t, `"number":3`).JWK,
		newBullshitKey[string](t, `"number":4`).JWK,
	}

	time.Sleep(10 * time.Millisecond)

	fetchedKeys, err = source.List(t.Context())
	require.NoError(t, err)
	require.Equal(t, []*jwk.Key[string]{
		newBullshitKey[string](t, `"number":1`),
		newBullshitKey[string](t, `"number":2`),
	}, fetchedKeys)

	time.Sleep(100 * time.Millisecond)

	fetchedKeys, err = source.List(t.Context())
	require.NoError(t, err)
	require.Equal(t, []*jwk.Key[string]{
		newBullshitKey[string](t, `"number":3`),
		newBullshitKey[string](t, `"number":4`),
	}, fetchedKeys)
}

func TestSourceNegativeCache(t *testing.T) {
	t.Parallel()

	errFoo := errors.New("foo")

	fetchCount := 0
	config := jwk.SourceConfig{
		CacheDuration: time.Hour,
		RetryInterval: time.Hour,
		Fetch: func(_ context.Context) ([]*jwa.JWK, error) {
			fetchCount++

			return nil, errFoo
		},
	}

	source := jwk.NewGenericSource[string](config, (&simulateParser[string]{}).parse)

	// Two failing List calls: Fetch must run only once — the second is served from the negative
	// cache instead of hammering the upstream.
	_, err := source.List(t.Context())
	require.ErrorIs(t, err, errFoo)

	_, err = source.List(t.Context())
	require.ErrorIs(t, err, errFoo)

	require.Equal(t, 1, fetchCount)
}

func TestSourceCaches(t *testing.T) {
	t.Parallel()

	fetchCount := 0
	key := newBullshitKey[string](t, "kid-1")
	config := jwk.SourceConfig{
		CacheDuration: time.Hour,
		Fetch: func(_ context.Context) ([]*jwa.JWK, error) {
			fetchCount++

			return []*jwa.JWK{key.JWK}, nil
		},
	}

	parser := simulateParser[string]{responses: []simulatedParserResp[string]{{key: key}}}
	source := jwk.NewGenericSource[string](config, parser.parse)

	// A warm cache within CacheDuration serves without a second fetch (nor a second parse, which
	// would exhaust the one-response parser).
	_, err := source.List(t.Context())
	require.NoError(t, err)

	_, err = source.List(t.Context())
	require.NoError(t, err)

	require.Equal(t, 1, fetchCount)
}
