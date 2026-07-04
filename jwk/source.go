package jwk

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/a-novel-kit/jwt/v2/jwa"
)

// ErrKeyNotFound is returned by [Source.Get] when no cached key matches the request.
var ErrKeyNotFound = errors.New("key not found")

// KeysFetcher retrieves the raw JSON Web Keys backing a [Source]. Keys must be returned in
// priority order, most important first, because [Source.Get] falls back to the first key when no
// ID is requested.
type KeysFetcher func(ctx context.Context) ([]*jwa.JWK, error)

// DefaultRetryInterval bounds how often a [Source] retries a failing Fetch when the config leaves
// RetryInterval unset, so a broken upstream is not called on every request.
const DefaultRetryInterval = 30 * time.Second

// SourceConfig configures a [Source].
type SourceConfig struct {
	// CacheDuration is how long fetched keys are held before the next fetch.
	CacheDuration time.Duration
	// Fetch retrieves the current keys. It runs against whatever the caller wires in — often a
	// remote JWK Set endpoint — so preventing SSRF is the caller's responsibility: pin the host (or
	// an allowlist), require HTTPS with verified certificates, and set timeouts inside Fetch.
	Fetch KeysFetcher
	// RetryInterval bounds how often a failing Fetch is retried (negative caching), so a broken
	// upstream is not hit on every request. Non-positive selects DefaultRetryInterval.
	RetryInterval time.Duration
}

// A Source fetches and caches the raw JSON Web Keys used to sign or verify tokens, looked up by ID.
//
// It is algorithm-agnostic: one Source serves keys of every family a JWK Set holds, and the signer
// or verifier that consumes it decodes the key material it needs and skips the rest. A mixed set
// (RSA, EC, HMAC, …) therefore needs a single Source rather than one per key type, which is what
// lets a recipient verify tokens across an algorithm rotation through one endpoint.
//
// It refreshes lazily once the cached set is older than CacheDuration, and is safe for concurrent
// use.
type Source struct {
	config SourceConfig

	cached      []*jwa.JWK
	lastCached  time.Time
	lastFailure time.Time
	lastErr     error

	mu *sync.RWMutex
}

// NewSource builds a [Source] from a config. The Source serves raw keys; decoding happens in the
// signer or verifier that consumes it.
func NewSource(config SourceConfig) *Source {
	return &Source{
		config: config,
		cached: nil,
		mu:     new(sync.RWMutex),
	}
}

// fresh reports whether the cache is populated and still within CacheDuration, under a read lock so
// concurrent readers of a warm cache never serialize behind the write lock.
func (source *Source) fresh() bool {
	source.mu.RLock()
	defer source.mu.RUnlock()

	return source.cached != nil && time.Since(source.lastCached) < source.config.CacheDuration
}

func (source *Source) refresh(ctx context.Context) error {
	if source.fresh() {
		return nil
	}

	source.mu.Lock()
	defer source.mu.Unlock()

	// Another goroutine may have refreshed while we waited for the write lock.
	if source.cached != nil && time.Since(source.lastCached) < source.config.CacheDuration {
		return nil
	}

	// Negative caching: after a failure, don't call Fetch again until RetryInterval has elapsed, so
	// a broken upstream isn't hit on every request (a thundering-herd / amplification DoS).
	retry := source.config.RetryInterval
	if retry <= 0 {
		retry = DefaultRetryInterval
	}

	// Measure the backoff from when a failure is observed, not when the attempt starts: a Fetch that
	// itself takes longer than retry would otherwise let the next caller re-fetch immediately.
	if source.lastErr != nil && time.Since(source.lastFailure) < retry {
		return source.lastErr
	}

	keys, err := source.config.Fetch(ctx)
	if err != nil {
		source.lastErr = fmt.Errorf("(Source.refresh) fetch keys: %w", err)
		source.lastFailure = time.Now()

		return source.lastErr
	}

	// Keep the cache non-nil on success so an empty key set is still treated as fresh rather than
	// re-fetched on every request.
	if keys == nil {
		keys = []*jwa.JWK{}
	}

	source.cached = keys
	source.lastCached = time.Now()
	source.lastErr = nil

	return nil
}

// List returns every cached key, refreshing the cache first when it has expired.
func (source *Source) List(ctx context.Context) ([]*jwa.JWK, error) {
	err := source.refresh(ctx)
	if err != nil {
		return nil, fmt.Errorf("(Source.List) refresh keys: %w", err)
	}

	source.mu.RLock()
	defer source.mu.RUnlock()

	return source.cached, nil
}

// Get returns the key with the given ID. An empty kid returns the first (highest-priority) key. It
// returns ErrKeyNotFound when the source is empty or no key matches.
func (source *Source) Get(ctx context.Context, kid string) (*jwa.JWK, error) {
	list, err := source.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("(Source.Get) list keys: %w", err)
	}

	if len(list) == 0 {
		return nil, fmt.Errorf("(Source.Get) %w", ErrKeyNotFound)
	}

	if kid == "" {
		return list[0], nil
	}

	for _, key := range list {
		if key.KID == kid {
			return key, nil
		}
	}

	return nil, fmt.Errorf("(Source.Get) %w", ErrKeyNotFound)
}
