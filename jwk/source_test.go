package jwk_test

import (
	"context"
	"errors"
	"strconv"
	"sync"
	"sync/atomic"
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

// Tests for RefreshOnUnknownKeyID: a key id absent from the cache forcing a bounded fetch, so a
// verifier finds a key the issuer has just rotated to instead of waiting out CacheDuration.

func TestSourceGetUnknownKeyIDDisabled(t *testing.T) {
	t.Parallel()

	var fetches atomic.Int64

	source := jwk.NewSource(jwk.SourceConfig{
		CacheDuration: time.Hour,
		Fetch: func(_ context.Context) ([]*jwa.JWK, error) {
			fetches.Add(1)

			return []*jwa.JWK{newBullshitKey[string](t, "kid-1").JWK}, nil
		},
	})

	_, err := source.Get(t.Context(), "kid-1")
	require.NoError(t, err)

	// The default must be untouched: an unknown id reports the miss against the cached set without
	// going upstream, however old that set is.
	_, err = source.Get(t.Context(), "rotated-kid")
	require.ErrorIs(t, err, jwk.ErrKeyNotFound)
	require.EqualValues(t, 1, fetches.Load())
}

func TestSourceGetUnknownKeyIDRefreshes(t *testing.T) {
	t.Parallel()

	var (
		fetches atomic.Int64
		rotated atomic.Bool
	)

	source := jwk.NewSource(jwk.SourceConfig{
		CacheDuration: time.Hour,
		// Long enough that the cache is nowhere near expiry, so any fetch after the first can only
		// have come from the unknown-key-id path.
		RefreshOnUnknownKeyID: true,
		UnknownKeyIDInterval:  time.Nanosecond,
		Fetch: func(_ context.Context) ([]*jwa.JWK, error) {
			fetches.Add(1)

			if rotated.Load() {
				return []*jwa.JWK{newBullshitKey[string](t, "kid-2").JWK}, nil
			}

			return []*jwa.JWK{newBullshitKey[string](t, "kid-1").JWK}, nil
		},
	})

	_, err := source.Get(t.Context(), "kid-1")
	require.NoError(t, err)
	require.EqualValues(t, 1, fetches.Load())

	// The issuer rotates. CacheDuration has not elapsed, so without this feature the new key stays
	// invisible for an hour.
	rotated.Store(true)

	key, err := source.Get(t.Context(), "kid-2")
	require.NoError(t, err)
	require.Equal(t, "kid-2", key.KID)
	require.EqualValues(t, 2, fetches.Load())
}

func TestSourceGetUnknownKeyIDRateLimited(t *testing.T) {
	t.Parallel()

	var fetches atomic.Int64

	source := jwk.NewSource(jwk.SourceConfig{
		CacheDuration:         time.Hour,
		RefreshOnUnknownKeyID: true,
		UnknownKeyIDInterval:  time.Hour,
		Fetch: func(_ context.Context) ([]*jwa.JWK, error) {
			fetches.Add(1)

			return []*jwa.JWK{newBullshitKey[string](t, "kid-1").JWK}, nil
		},
	})

	_, err := source.Get(t.Context(), "kid-1")
	require.NoError(t, err)
	require.EqualValues(t, 1, fetches.Load())

	// The trigger is attacker-controlled: whoever presents a token picks the key id. A flood of
	// distinct forged ids must not amplify into a flood of upstream calls.
	//
	// Nothing at all goes upstream here, because the bound is the cache's age rather than a count:
	// the set was just fetched, so no id is old enough to justify re-fetching. The amplification
	// factor is zero for as long as the interval holds, and one fetch per interval after that —
	// independent of how many distinct ids arrive.
	for i := range 500 {
		_, err = source.Get(t.Context(), "forged-"+strconv.Itoa(i))
		require.ErrorIs(t, err, jwk.ErrKeyNotFound)
	}

	require.EqualValues(t, 1, fetches.Load(), "500 distinct unknown key ids must cost no fetch")
}

func TestSourceGetUnknownKeyIDConcurrent(t *testing.T) {
	t.Parallel()

	var fetches atomic.Int64

	source := jwk.NewSource(jwk.SourceConfig{
		CacheDuration:         time.Hour,
		RefreshOnUnknownKeyID: true,
		UnknownKeyIDInterval:  time.Hour,
		Fetch: func(_ context.Context) ([]*jwa.JWK, error) {
			fetches.Add(1)

			return []*jwa.JWK{newBullshitKey[string](t, "kid-1").JWK}, nil
		},
	})

	_, err := source.Get(t.Context(), "kid-1")
	require.NoError(t, err)

	// Same bound under contention: the age is re-checked under the write lock, so goroutines that
	// queue behind one another find the cache young rather than each fetching in turn.
	var wg sync.WaitGroup

	for i := range 50 {
		wg.Add(1)

		go func() {
			defer wg.Done()

			_, _ = source.Get(t.Context(), "forged-"+strconv.Itoa(i))
		}()
	}

	wg.Wait()

	require.EqualValues(t, 1, fetches.Load())
}

func TestSourceGetUnknownKeyIDHonoursBackoff(t *testing.T) {
	t.Parallel()

	var fetches atomic.Int64

	errUpstream := errors.New("upstream down")

	source := jwk.NewSource(jwk.SourceConfig{
		CacheDuration:         time.Hour,
		RetryInterval:         time.Hour,
		RefreshOnUnknownKeyID: true,
		UnknownKeyIDInterval:  time.Nanosecond,
		Fetch: func(_ context.Context) ([]*jwa.JWK, error) {
			if fetches.Add(1) == 1 {
				return []*jwa.JWK{newBullshitKey[string](t, "kid-1").JWK}, nil
			}

			return nil, errUpstream
		},
	})

	_, err := source.Get(t.Context(), "kid-1")
	require.NoError(t, err)

	// The first unknown id reaches a broken upstream and records the failure.
	_, err = source.Get(t.Context(), "forged-1")
	require.ErrorIs(t, err, errUpstream)
	require.EqualValues(t, 2, fetches.Load())

	// An unknown key id must not be a way around the retry backoff — otherwise the negative caching
	// that protects a broken upstream is bypassed by the one input an attacker controls.
	_, err = source.Get(t.Context(), "forged-2")
	require.ErrorIs(t, err, errUpstream)
	require.EqualValues(t, 2, fetches.Load(), "the backoff must hold on the unknown-key-id path")
}
