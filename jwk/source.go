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

// KeyParser decodes a raw JSON Web Key into a typed [Key].
type KeyParser[K any] func(ctx context.Context, jwk *jwa.JWK) (*Key[K], error)

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

// A Source fetches, caches, and parses the keys used to sign or verify tokens. It refreshes lazily
// once the cached set is older than CacheDuration, and is safe for concurrent use.
type Source[K any] struct {
	config SourceConfig
	parser KeyParser[K]

	cached      []*Key[K]
	lastCached  time.Time
	lastFailure time.Time
	lastErr     error

	mu *sync.RWMutex
}

// fresh reports whether the cache is populated and still within CacheDuration, under a read lock so
// concurrent readers of a warm cache never serialize behind the write lock.
func (source *Source[K]) fresh() bool {
	source.mu.RLock()
	defer source.mu.RUnlock()

	return source.cached != nil && time.Since(source.lastCached) < source.config.CacheDuration
}

func (source *Source[K]) refresh(ctx context.Context) error {
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

	parsedKeys := make([]*Key[K], len(keys))

	for i, key := range keys {
		parsed, parseErr := source.parser(ctx, key)
		if parseErr != nil {
			source.lastErr = fmt.Errorf("(Source.refresh) parse key: %w", parseErr)
			source.lastFailure = time.Now()

			return source.lastErr
		}

		parsedKeys[i] = parsed
	}

	source.cached = parsedKeys
	source.lastCached = time.Now()
	source.lastErr = nil

	return nil
}

// List returns every cached key, refreshing the cache first when it has expired.
func (source *Source[K]) List(ctx context.Context) ([]*Key[K], error) {
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
func (source *Source[K]) Get(ctx context.Context, kid string) (*Key[K], error) {
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

// NewGenericSource builds a [Source] from a config and a parser. The algorithm-specific
// constructors, such as [NewRSAPublicSource], wrap this with a preset-bound parser.
func NewGenericSource[K any](config SourceConfig, parser KeyParser[K]) *Source[K] {
	return &Source[K]{
		config:     config,
		parser:     parser,
		cached:     nil,
		lastCached: time.Time{},
		mu:         new(sync.RWMutex),
	}
}
