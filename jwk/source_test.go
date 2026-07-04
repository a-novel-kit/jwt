package jwk_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/a-novel-kit/jwt/v2/jwa"
	"github.com/a-novel-kit/jwt/v2/jwk"
)

func TestSourceList(t *testing.T) {
	t.Parallel()

	errFoo := errors.New("foo")

	testCases := []struct {
		name string

		fetcherResp []*jwa.JWK
		fetcherErr  error

		expect    []*jwa.JWK
		expectErr error
	}{
		{
			name: "Success",

			fetcherResp: []*jwa.JWK{
				newBullshitKey[string](t, "kid-1").JWK,
				newBullshitKey[string](t, "kid-2").JWK,
			},

			expect: []*jwa.JWK{
				newBullshitKey[string](t, "kid-1").JWK,
				newBullshitKey[string](t, "kid-2").JWK,
			},
		},
		{
			name:       "FetcherError",
			fetcherErr: errFoo,
			expectErr:  errFoo,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			source := jwk.NewSource(jwk.SourceConfig{
				Fetch: func(_ context.Context) ([]*jwa.JWK, error) {
					return testCase.fetcherResp, testCase.fetcherErr
				},
			})

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

		expect    *jwa.JWK
		expectErr error
	}{
		{
			name: "Success",

			fetcherResp: []*jwa.JWK{
				newBullshitKey[string](t, "kid-1").JWK,
				newBullshitKey[string](t, "kid-2").JWK,
			},

			expect: newBullshitKey[string](t, "kid-1").JWK,
		},
		{
			name: "KID",

			fetcherResp: []*jwa.JWK{
				newBullshitKey[string](t, "kid-1").JWK,
				newBullshitKey[string](t, "kid-2").JWK,
			},

			kid: "kid-2",

			expect: newBullshitKey[string](t, "kid-2").JWK,
		},
		{
			name:       "FetcherError",
			fetcherErr: errFoo,
			expectErr:  errFoo,
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

			expectErr: jwk.ErrKeyNotFound,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			source := jwk.NewSource(jwk.SourceConfig{
				Fetch: func(_ context.Context) ([]*jwa.JWK, error) {
					return testCase.fetcherResp, testCase.fetcherErr
				},
			})

			key, err := source.Get(t.Context(), testCase.kid)
			require.ErrorIs(t, err, testCase.expectErr)
			require.Equal(t, testCase.expect, key)
		})
	}
}

func TestSourceRefresh(t *testing.T) {
	t.Parallel()

	keys := []*jwa.JWK{
		newBullshitKey[string](t, `"number":1`).JWK,
		newBullshitKey[string](t, `"number":2`).JWK,
	}

	fetcher := func(_ context.Context) ([]*jwa.JWK, error) {
		// Copy the slice to prevent side effects.
		copied := make([]*jwa.JWK, len(keys))
		copy(copied, keys)

		return copied, nil
	}

	config := jwk.SourceConfig{Fetch: fetcher, CacheDuration: 100 * time.Millisecond}

	source := jwk.NewSource(config)

	fetchedKeys, err := source.List(t.Context())
	require.NoError(t, err)
	require.Equal(t, []*jwa.JWK{
		newBullshitKey[string](t, `"number":1`).JWK,
		newBullshitKey[string](t, `"number":2`).JWK,
	}, fetchedKeys)

	keys = []*jwa.JWK{
		newBullshitKey[string](t, `"number":3`).JWK,
		newBullshitKey[string](t, `"number":4`).JWK,
	}

	time.Sleep(10 * time.Millisecond)

	fetchedKeys, err = source.List(t.Context())
	require.NoError(t, err)
	require.Equal(t, []*jwa.JWK{
		newBullshitKey[string](t, `"number":1`).JWK,
		newBullshitKey[string](t, `"number":2`).JWK,
	}, fetchedKeys)

	time.Sleep(100 * time.Millisecond)

	fetchedKeys, err = source.List(t.Context())
	require.NoError(t, err)
	require.Equal(t, []*jwa.JWK{
		newBullshitKey[string](t, `"number":3`).JWK,
		newBullshitKey[string](t, `"number":4`).JWK,
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

	source := jwk.NewSource(config)

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

	source := jwk.NewSource(config)

	// A warm cache within CacheDuration serves without a second fetch.
	_, err := source.List(t.Context())
	require.NoError(t, err)

	_, err = source.List(t.Context())
	require.NoError(t, err)

	require.Equal(t, 1, fetchCount)
}
