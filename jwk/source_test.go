package jwk_test

import (
	"context"
	"errors"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
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
				newPlaceholderKey[string](t, "kid-1").JWK,
				newPlaceholderKey[string](t, "kid-2").JWK,
			},

			expect: []*jwa.JWK{
				newPlaceholderKey[string](t, "kid-1").JWK,
				newPlaceholderKey[string](t, "kid-2").JWK,
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
				newPlaceholderKey[string](t, "kid-1").JWK,
				newPlaceholderKey[string](t, "kid-2").JWK,
			},

			expect: newPlaceholderKey[string](t, "kid-1").JWK,
		},
		{
			name: "KID",

			fetcherResp: []*jwa.JWK{
				newPlaceholderKey[string](t, "kid-1").JWK,
				newPlaceholderKey[string](t, "kid-2").JWK,
			},

			kid: "kid-2",

			expect: newPlaceholderKey[string](t, "kid-2").JWK,
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
				newPlaceholderKey[string](t, "kid-1").JWK,
				newPlaceholderKey[string](t, "kid-2").JWK,
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
		newPlaceholderKey[string](t, `"number":1`).JWK,
		newPlaceholderKey[string](t, `"number":2`).JWK,
	}

	fetcher := func(_ context.Context) ([]*jwa.JWK, error) {
		// Copy the slice so a caller cannot mutate the fixture.
		copied := make([]*jwa.JWK, len(keys))
		copy(copied, keys)

		return copied, nil
	}

	config := jwk.SourceConfig{Fetch: fetcher, CacheDuration: 100 * time.Millisecond}

	source := jwk.NewSource(config)

	fetchedKeys, err := source.List(t.Context())
	require.NoError(t, err)
	require.Equal(t, []*jwa.JWK{
		newPlaceholderKey[string](t, `"number":1`).JWK,
		newPlaceholderKey[string](t, `"number":2`).JWK,
	}, fetchedKeys)

	keys = []*jwa.JWK{
		newPlaceholderKey[string](t, `"number":3`).JWK,
		newPlaceholderKey[string](t, `"number":4`).JWK,
	}

	time.Sleep(10 * time.Millisecond)

	fetchedKeys, err = source.List(t.Context())
	require.NoError(t, err)
	require.Equal(t, []*jwa.JWK{
		newPlaceholderKey[string](t, `"number":1`).JWK,
		newPlaceholderKey[string](t, `"number":2`).JWK,
	}, fetchedKeys)

	time.Sleep(100 * time.Millisecond)

	fetchedKeys, err = source.List(t.Context())
	require.NoError(t, err)
	require.Equal(t, []*jwa.JWK{
		newPlaceholderKey[string](t, `"number":3`).JWK,
		newPlaceholderKey[string](t, `"number":4`).JWK,
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

	// Two failing List calls: the second is served from the negative cache, so Fetch runs once.
	_, err := source.List(t.Context())
	require.ErrorIs(t, err, errFoo)

	_, err = source.List(t.Context())
	require.ErrorIs(t, err, errFoo)

	require.Equal(t, 1, fetchCount)
}

func TestSourceCaches(t *testing.T) {
	t.Parallel()

	fetchCount := 0
	key := newPlaceholderKey[string](t, "kid-1")
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

// Tests for StaleIfError run in a synctest bubble, whose fake clock makes the window boundaries exact.

func TestSourceStaleIfError(t *testing.T) {
	t.Parallel()

	errUpstream := errors.New("upstream down")
	key := newPlaceholderKey[string](t, "kid-1").JWK

	testCases := []struct {
		name string

		staleIfError time.Duration
		// elapsed is the cache age at which the upstream is called again, and fails.
		elapsed time.Duration

		expect    []*jwa.JWK
		expectErr error
	}{
		{
			name: "Success/WithinWindow",

			staleIfError: time.Hour,
			elapsed:      2*time.Hour - time.Nanosecond,

			expect: []*jwa.JWK{key},
		},
		{
			name: "Error/WindowElapsed",

			staleIfError: time.Hour,
			elapsed:      2 * time.Hour,

			expectErr: errUpstream,
		},
		{
			name: "Error/Disabled",

			elapsed: time.Hour,

			expectErr: errUpstream,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			synctest.Test(t, func(t *testing.T) {
				fetchCount := 0

				source := jwk.NewSource(jwk.SourceConfig{
					CacheDuration: time.Hour,
					StaleIfError:  testCase.staleIfError,
					Fetch: func(_ context.Context) ([]*jwa.JWK, error) {
						fetchCount++

						if fetchCount == 1 {
							return []*jwa.JWK{key}, nil
						}

						return nil, errUpstream
					},
				})

				_, err := source.List(t.Context())
				require.NoError(t, err)

				time.Sleep(testCase.elapsed)

				keys, err := source.List(t.Context())
				require.ErrorIs(t, err, testCase.expectErr)
				require.Equal(t, testCase.expect, keys)
				require.Equal(t, 2, fetchCount, "the upstream is tried before a stale set is served")
			})
		})
	}
}

func TestSourceStaleIfErrorNeverFetched(t *testing.T) {
	t.Parallel()

	errUpstream := errors.New("upstream down")

	source := jwk.NewSource(jwk.SourceConfig{
		CacheDuration: time.Hour,
		StaleIfError:  time.Hour,
		Fetch: func(_ context.Context) ([]*jwa.JWK, error) {
			return nil, errUpstream
		},
	})

	// A source that never fetched has no set to fall back on.
	_, err := source.Get(t.Context(), "")
	require.ErrorIs(t, err, errUpstream)
}

func TestSourceStaleIfErrorRecovers(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		errUpstream := errors.New("upstream down")

		var (
			fetchCount  int
			upstreamErr error
		)

		upstreamKID := "kid-1"

		source := jwk.NewSource(jwk.SourceConfig{
			CacheDuration: time.Hour,
			StaleIfError:  time.Hour,
			RetryInterval: time.Minute,
			Fetch: func(_ context.Context) ([]*jwa.JWK, error) {
				fetchCount++

				if upstreamErr != nil {
					return nil, upstreamErr
				}

				return []*jwa.JWK{newPlaceholderKey[string](t, upstreamKID).JWK}, nil
			},
		})

		_, err := source.Get(t.Context(), "kid-1")
		require.NoError(t, err)

		// The cache expires during an outage: the last fetched key stays in service.
		upstreamErr = errUpstream

		time.Sleep(time.Hour)

		key, err := source.Get(t.Context(), "kid-1")
		require.NoError(t, err)
		require.Equal(t, "kid-1", key.KID)
		require.Equal(t, 2, fetchCount)

		// The upstream recovers with a rotated key. The retry backoff still holds the next fetch off.
		upstreamErr = nil
		upstreamKID = "kid-2"

		time.Sleep(time.Minute - time.Nanosecond)

		key, err = source.Get(t.Context(), "")
		require.NoError(t, err)
		require.Equal(t, "kid-1", key.KID)
		require.Equal(t, 2, fetchCount, "the retry backoff holds while the stale set is served")

		time.Sleep(time.Nanosecond)

		key, err = source.Get(t.Context(), "")
		require.NoError(t, err)
		require.Equal(t, "kid-2", key.KID)
		require.Equal(t, 3, fetchCount)
	})
}

// Tests for RefreshOnUnknownKeyID: a key ID absent from the cache forces a bounded fetch, so a
// verifier finds a key the issuer has just rotated to without waiting out CacheDuration.

func TestSourceGetUnknownKeyIDDisabled(t *testing.T) {
	t.Parallel()

	var fetches atomic.Int64

	source := jwk.NewSource(jwk.SourceConfig{
		CacheDuration: time.Hour,
		Fetch: func(_ context.Context) ([]*jwa.JWK, error) {
			fetches.Add(1)

			return []*jwa.JWK{newPlaceholderKey[string](t, "kid-1").JWK}, nil
		},
	})

	_, err := source.Get(t.Context(), "kid-1")
	require.NoError(t, err)

	// By default an unknown ID reports the miss against the cached set, however old that set is.
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
		// have come from the unknown-key-ID path.
		RefreshOnUnknownKeyID: true,
		UnknownKeyIDInterval:  time.Nanosecond,
		Fetch: func(_ context.Context) ([]*jwa.JWK, error) {
			fetches.Add(1)

			if rotated.Load() {
				return []*jwa.JWK{newPlaceholderKey[string](t, "kid-2").JWK}, nil
			}

			return []*jwa.JWK{newPlaceholderKey[string](t, "kid-1").JWK}, nil
		},
	})

	_, err := source.Get(t.Context(), "kid-1")
	require.NoError(t, err)
	require.EqualValues(t, 1, fetches.Load())

	// The issuer rotates. CacheDuration has not elapsed, so only a forced fetch reveals the new key.
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

			return []*jwa.JWK{newPlaceholderKey[string](t, "kid-1").JWK}, nil
		},
	})

	_, err := source.Get(t.Context(), "kid-1")
	require.NoError(t, err)
	require.EqualValues(t, 1, fetches.Load())

	// The trigger is attacker-controlled: whoever presents a token picks the key ID. The bound is the
	// cache's age, so a flood of distinct forged IDs costs at most one upstream call per interval. It
	// costs none here, where the set was just fetched.
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

			return []*jwa.JWK{newPlaceholderKey[string](t, "kid-1").JWK}, nil
		},
	})

	_, err := source.Get(t.Context(), "kid-1")
	require.NoError(t, err)

	// Same bound under contention: the age is re-checked under the write lock, so goroutines queued
	// behind one another find the cache young.
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
				return []*jwa.JWK{newPlaceholderKey[string](t, "kid-1").JWK}, nil
			}

			return nil, errUpstream
		},
	})

	_, err := source.Get(t.Context(), "kid-1")
	require.NoError(t, err)

	// The first unknown ID reaches a broken upstream and records the failure.
	_, err = source.Get(t.Context(), "forged-1")
	require.ErrorIs(t, err, errUpstream)
	require.EqualValues(t, 2, fetches.Load())

	// An unknown key ID stays subject to the retry backoff, so the one attacker-controlled input
	// cannot bypass the negative caching that protects a broken upstream.
	_, err = source.Get(t.Context(), "forged-2")
	require.ErrorIs(t, err, errUpstream)
	require.EqualValues(t, 2, fetches.Load(), "the backoff must hold on the unknown-key-id path")
}

// Tests for the shared fetch: one Fetch call serves every caller of an expired cache, under a context
// no single caller can cancel. They run in a synctest bubble, where synctest.Wait returns once every
// goroutine is blocked, so each test knows when the callers wait on the fetch.

func TestSourceFetchShared(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		var fetches atomic.Int64

		release := make(chan struct{})
		key := newPlaceholderKey[string](t, "kid-1").JWK

		source := jwk.NewSource(jwk.SourceConfig{
			CacheDuration: time.Hour,
			Fetch: func(_ context.Context) ([]*jwa.JWK, error) {
				fetches.Add(1)
				<-release

				return []*jwa.JWK{key}, nil
			},
		})

		results := make(chan []*jwa.JWK, 10)

		for range cap(results) {
			go func() {
				keys, _ := source.List(t.Context())
				results <- keys
			}()
		}

		synctest.Wait()
		close(release)

		for range cap(results) {
			require.Equal(t, []*jwa.JWK{key}, <-results)
		}

		require.EqualValues(t, 1, fetches.Load())
	})
}

func TestSourceFetchOutlivesCaller(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		var (
			fetches  atomic.Int64
			fetchErr error
		)

		release := make(chan struct{})
		key := newPlaceholderKey[string](t, "kid-1").JWK

		source := jwk.NewSource(jwk.SourceConfig{
			CacheDuration: time.Hour,
			Fetch: func(ctx context.Context) ([]*jwa.JWK, error) {
				fetches.Add(1)
				<-release

				fetchErr = ctx.Err()

				return []*jwa.JWK{key}, nil
			},
		})

		ctx, cancel := context.WithCancel(t.Context())
		callerErr := make(chan error, 1)

		go func() {
			_, err := source.List(ctx)
			callerErr <- err
		}()

		// The caller that triggered the fetch gives up. It stops waiting at once.
		synctest.Wait()
		cancel()
		require.ErrorIs(t, <-callerErr, context.Canceled)

		// The fetch runs on and fills the cache for the next caller, with no failure to back off from.
		close(release)
		synctest.Wait()

		keys, err := source.List(t.Context())
		require.NoError(t, err)
		require.Equal(t, []*jwa.JWK{key}, keys)
		require.NoError(t, fetchErr, "the caller's cancellation must not reach Fetch")
		require.EqualValues(t, 1, fetches.Load())
	})
}

func TestSourceFetchTimeout(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name string

		fetchTimeout time.Duration

		expectElapsed time.Duration
	}{
		{
			name:          "Error/Configured",
			fetchTimeout:  time.Minute,
			expectElapsed: time.Minute,
		},
		{
			name:          "Error/Default",
			expectElapsed: jwk.DefaultFetchTimeout,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			synctest.Test(t, func(t *testing.T) {
				source := jwk.NewSource(jwk.SourceConfig{
					FetchTimeout: testCase.fetchTimeout,
					Fetch: func(ctx context.Context) ([]*jwa.JWK, error) {
						<-ctx.Done()

						return nil, ctx.Err()
					},
				})

				start := time.Now()

				_, err := source.List(t.Context())
				require.ErrorIs(t, err, context.DeadlineExceeded)
				require.Equal(t, testCase.expectElapsed, time.Since(start))
			})
		})
	}
}

func TestSourceFetchPanic(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		var fetches atomic.Int64

		source := jwk.NewSource(jwk.SourceConfig{
			CacheDuration: time.Hour,
			RetryInterval: time.Hour,
			Fetch: func(_ context.Context) ([]*jwa.JWK, error) {
				fetches.Add(1)

				panic("upstream client bug")
			},
		})

		// The panic surfaces as a fetch error, which the retry backoff then holds like any other.
		_, err := source.List(t.Context())
		require.ErrorContains(t, err, "upstream client bug")

		_, err = source.List(t.Context())
		require.ErrorContains(t, err, "upstream client bug")
		require.EqualValues(t, 1, fetches.Load())
	})
}

func TestSourceStaleWhileRevalidate(t *testing.T) {
	t.Parallel()

	oldKey := newPlaceholderKey[string](t, "kid-1").JWK
	newKey := newPlaceholderKey[string](t, "kid-2").JWK

	testCases := []struct {
		name string

		staleWhileRevalidate time.Duration
		// elapsed is the cache age at which the refreshing fetch starts.
		elapsed time.Duration

		// expectWait reports whether the caller waits for the fetch instead of reading the cached set.
		expectWait bool
	}{
		{
			name:                 "Success/WithinWindow",
			staleWhileRevalidate: time.Hour,
			elapsed:              2*time.Hour - time.Nanosecond,
		},
		{
			name:                 "Success/WindowElapsed",
			staleWhileRevalidate: time.Hour,
			elapsed:              2 * time.Hour,
			expectWait:           true,
		},
		{
			name:       "Success/Disabled",
			elapsed:    time.Hour,
			expectWait: true,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			synctest.Test(t, func(t *testing.T) {
				var fetches atomic.Int64

				release := make(chan struct{})

				source := jwk.NewSource(jwk.SourceConfig{
					CacheDuration:        time.Hour,
					StaleWhileRevalidate: testCase.staleWhileRevalidate,
					Fetch: func(_ context.Context) ([]*jwa.JWK, error) {
						if fetches.Add(1) == 1 {
							return []*jwa.JWK{oldKey}, nil
						}

						<-release

						return []*jwa.JWK{newKey}, nil
					},
				})

				_, err := source.List(t.Context())
				require.NoError(t, err)

				time.Sleep(testCase.elapsed)

				results := make(chan []*jwa.JWK, 1)

				go func() {
					keys, _ := source.List(t.Context())
					results <- keys
				}()

				synctest.Wait()

				if !testCase.expectWait {
					require.Equal(t, []*jwa.JWK{oldKey}, <-results, "the cached set serves while the fetch runs")
				}

				close(release)
				synctest.Wait()

				if testCase.expectWait {
					require.Equal(t, []*jwa.JWK{newKey}, <-results)
				}

				keys, err := source.List(t.Context())
				require.NoError(t, err)
				require.Equal(t, []*jwa.JWK{newKey}, keys)
				require.EqualValues(t, 2, fetches.Load())
			})
		})
	}
}

func TestSourceStaleWhileRevalidateFailure(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		var fetches atomic.Int64

		errUpstream := errors.New("upstream down")
		key := newPlaceholderKey[string](t, "kid-1").JWK

		source := jwk.NewSource(jwk.SourceConfig{
			CacheDuration:        time.Hour,
			StaleWhileRevalidate: time.Hour,
			Fetch: func(_ context.Context) ([]*jwa.JWK, error) {
				if fetches.Add(1) == 1 {
					return []*jwa.JWK{key}, nil
				}

				return nil, errUpstream
			},
		})

		_, err := source.List(t.Context())
		require.NoError(t, err)

		time.Sleep(time.Hour)

		keys, err := source.List(t.Context())
		require.NoError(t, err)
		require.Equal(t, []*jwa.JWK{key}, keys)

		// Once the refresh has failed, only StaleIfError keeps the set in service, and it is unset.
		synctest.Wait()

		_, err = source.List(t.Context())
		require.ErrorIs(t, err, errUpstream)
		require.EqualValues(t, 2, fetches.Load())
	})
}

func TestSourceGetUnknownKeyIDJoinsFetch(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		var fetches atomic.Int64

		release := make(chan struct{})

		source := jwk.NewSource(jwk.SourceConfig{
			CacheDuration:         time.Hour,
			StaleWhileRevalidate:  time.Hour,
			RefreshOnUnknownKeyID: true,
			UnknownKeyIDInterval:  time.Hour,
			Fetch: func(_ context.Context) ([]*jwa.JWK, error) {
				if fetches.Add(1) == 1 {
					return []*jwa.JWK{newPlaceholderKey[string](t, "kid-1").JWK}, nil
				}

				<-release

				return []*jwa.JWK{newPlaceholderKey[string](t, "kid-2").JWK}, nil
			},
		})

		_, err := source.Get(t.Context(), "kid-1")
		require.NoError(t, err)

		time.Sleep(time.Hour)

		// The expired cache still serves, so the refresh runs in the background. The unknown key ID
		// waits on that fetch rather than starting a second one.
		results := make(chan *jwa.JWK, 1)

		go func() {
			key, _ := source.Get(t.Context(), "kid-2")
			results <- key
		}()

		synctest.Wait()
		close(release)

		require.Equal(t, "kid-2", (<-results).KID)
		require.EqualValues(t, 2, fetches.Load())
	})
}
