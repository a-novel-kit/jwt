package jwk_test

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/a-novel-kit/jwt/v2/jwa"
	"github.com/a-novel-kit/jwt/v2/jwk"
)

// countingDecoder returns a decode function that maps a key to its KID, or fails with err when set,
// and the count of its calls.
func countingDecoder(t *testing.T, err error) (func(key *jwa.JWK) (string, error), *atomic.Int64) {
	t.Helper()

	var calls atomic.Int64

	return func(key *jwa.JWK) (string, error) {
		calls.Add(1)

		if err != nil {
			return "", err
		}

		return key.KID, nil
	}, &calls
}

func TestDecoder(t *testing.T) {
	t.Parallel()

	t.Run("Success/OncePerKeySet", func(t *testing.T) {
		t.Parallel()

		source := jwk.NewSource(jwk.SourceConfig{
			CacheDuration: time.Hour,
			Fetch: func(_ context.Context) ([]*jwa.JWK, error) {
				return []*jwa.JWK{
					newPlaceholderKey[string](t, "kid-1").JWK,
					newPlaceholderKey[string](t, "kid-2").JWK,
				}, nil
			},
		})

		keys, err := source.List(t.Context())
		require.NoError(t, err)

		decode, calls := countingDecoder(t, nil)
		decoder := jwk.NewDecoder(source, decode)

		for range 3 {
			for _, key := range keys {
				decoded, err := decoder.Decode(key)
				require.NoError(t, err)
				require.Equal(t, key.KID, decoded)
			}
		}

		require.EqualValues(t, 2, calls.Load())
	})

	t.Run("Success/RefreshDecodesAgain", func(t *testing.T) {
		t.Parallel()

		synctest.Test(t, func(t *testing.T) {
			source := jwk.NewSource(jwk.SourceConfig{
				CacheDuration: time.Hour,
				Fetch: func(_ context.Context) ([]*jwa.JWK, error) {
					return []*jwa.JWK{newPlaceholderKey[string](t, "kid-1").JWK}, nil
				},
			})

			decode, calls := countingDecoder(t, nil)
			decoder := jwk.NewDecoder(source, decode)

			oldKey, err := source.Get(t.Context(), "kid-1")
			require.NoError(t, err)

			_, err = decoder.Decode(oldKey)
			require.NoError(t, err)

			time.Sleep(time.Hour)

			newKey, err := source.Get(t.Context(), "kid-1")
			require.NoError(t, err)

			// The new set is decoded afresh, and a key of the replaced set is no longer stored.
			_, err = decoder.Decode(newKey)
			require.NoError(t, err)

			_, err = decoder.Decode(newKey)
			require.NoError(t, err)

			_, err = decoder.Decode(oldKey)
			require.NoError(t, err)

			require.EqualValues(t, 3, calls.Load())
		})
	})

	t.Run("Success/KeyOutsideSource", func(t *testing.T) {
		t.Parallel()

		source := jwk.NewSource(jwk.SourceConfig{
			CacheDuration: time.Hour,
			Fetch: func(_ context.Context) ([]*jwa.JWK, error) {
				return []*jwa.JWK{newPlaceholderKey[string](t, "kid-1").JWK}, nil
			},
		})

		_, err := source.List(t.Context())
		require.NoError(t, err)

		decode, calls := countingDecoder(t, nil)
		decoder := jwk.NewDecoder(source, decode)

		// An equal key that is not the one the source holds is decoded every time, and never stored.
		outside := newPlaceholderKey[string](t, "kid-1").JWK

		for range 3 {
			decoded, err := decoder.Decode(outside)
			require.NoError(t, err)
			require.Equal(t, "kid-1", decoded)
		}

		require.EqualValues(t, 3, calls.Load())
	})

	t.Run("Error/Stored", func(t *testing.T) {
		t.Parallel()

		errDecode := errors.New("decode failed")

		source := jwk.NewSource(jwk.SourceConfig{
			CacheDuration: time.Hour,
			Fetch: func(_ context.Context) ([]*jwa.JWK, error) {
				return []*jwa.JWK{newPlaceholderKey[string](t, "kid-1").JWK}, nil
			},
		})

		key, err := source.Get(t.Context(), "kid-1")
		require.NoError(t, err)

		decode, calls := countingDecoder(t, errDecode)
		decoder := jwk.NewDecoder(source, decode)

		// A key that fails to decode fails the same way until the next refresh, without a new attempt.
		for range 3 {
			_, err = decoder.Decode(key)
			require.ErrorIs(t, err, errDecode)
		}

		require.EqualValues(t, 1, calls.Load())
	})

	t.Run("Success/Concurrent", func(t *testing.T) {
		t.Parallel()

		source := jwk.NewSource(jwk.SourceConfig{
			CacheDuration: time.Hour,
			Fetch: func(_ context.Context) ([]*jwa.JWK, error) {
				return []*jwa.JWK{newPlaceholderKey[string](t, "kid-1").JWK}, nil
			},
		})

		key, err := source.Get(t.Context(), "kid-1")
		require.NoError(t, err)

		decode, _ := countingDecoder(t, nil)
		decoder := jwk.NewDecoder(source, decode)

		var wg sync.WaitGroup

		decoded := make([]string, 50)

		for i := range decoded {
			wg.Go(func() {
				decoded[i], _ = decoder.Decode(key)
			})
		}

		wg.Wait()

		for _, kid := range decoded {
			require.Equal(t, "kid-1", kid)
		}
	})
}
