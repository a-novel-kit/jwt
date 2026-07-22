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

// DefaultUnknownKeyIDInterval bounds how often an unknown key id may force a fetch when
// RefreshOnUnknownKeyID is set and UnknownKeyIDInterval is not.
const DefaultUnknownKeyIDInterval = 10 * time.Second

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
	// RefreshOnUnknownKeyID lets a key id absent from the cache force a fetch, so a verifier picks
	// up a key the issuer has just rotated to without waiting out CacheDuration.
	//
	// Off by default because the trigger is attacker-controlled: whoever can present a token chooses
	// the key id. UnknownKeyIDInterval is what makes it safe to turn on.
	RefreshOnUnknownKeyID bool
	// UnknownKeyIDInterval is the minimum age the cache must have before an unknown key id may force
	// a fetch. Non-positive selects DefaultUnknownKeyIDInterval. Ignored unless
	// RefreshOnUnknownKeyID is set.
	//
	// The age check is the whole rate limit, and it holds regardless of input: a forced fetch resets
	// the cache age, so every subsequent unknown id within the interval finds the cache too young.
	// A flood of distinct forged key ids therefore costs at most one upstream call per interval.
	//
	// The cost is latency: a genuinely new key id arriving just after a forced fetch waits up to one
	// interval, still far shorter than the CacheDuration window this closes.
	UnknownKeyIDInterval time.Duration
}

// A Source fetches and caches the raw JSON Web Keys used to sign or verify tokens, looked up by ID.
//
// It is algorithm-agnostic: one Source serves a mixed set (RSA, EC, HMAC, …), and the signer or
// verifier that consumes it decodes the key material it needs and skips the rest. That is what lets
// a recipient verify tokens across an algorithm rotation through one endpoint.
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

// NewSource builds a [Source] from a config.
func NewSource(config SourceConfig) *Source {
	return &Source{
		config: config,
		cached: nil,
		mu:     new(sync.RWMutex),
	}
}

// List returns every cached key, refreshing the cache first when it has expired.
func (source *Source) List(ctx context.Context) ([]*jwa.JWK, error) {
	err := source.refresh(ctx)
	if err != nil {
		return nil, fmt.Errorf("(Source.List) refresh keys: %w", err)
	}

	source.mu.RLock()
	defer source.mu.RUnlock()

	// Return a copy so a caller that reorders or appends to the result cannot mutate the shared
	// cache other goroutines read.
	out := make([]*jwa.JWK, len(source.cached))
	copy(out, source.cached)

	return out, nil
}

// Get returns the key with the given ID. An empty kid returns the first (highest-priority) key. It
// returns ErrKeyNotFound when the source is empty or no key matches.
//
// With RefreshOnUnknownKeyID set, a named kid absent from the cache forces one bounded fetch before
// the miss is reported, so a key the issuer has just rotated to is found without waiting out
// CacheDuration. See UnknownKeyIDInterval for the bound.
func (source *Source) Get(ctx context.Context, kid string) (*jwa.JWK, error) {
	err := source.refresh(ctx)
	if err != nil {
		return nil, fmt.Errorf("(Source.Get) refresh keys: %w", err)
	}

	key, found := source.lookup(kid)
	if found {
		return key, nil
	}

	// An empty kid asks for whichever key ranks first, so a miss means the set is empty; there is no
	// stale id to recover from.
	if kid == "" || !source.config.RefreshOnUnknownKeyID {
		return nil, fmt.Errorf("(Source.Get) %w", ErrKeyNotFound)
	}

	refreshed, err := source.refreshForUnknownKeyID(ctx)
	if err != nil {
		return nil, fmt.Errorf("(Source.Get) refresh keys: %w", err)
	}

	if refreshed {
		key, found = source.lookup(kid)
		if found {
			return key, nil
		}
	}

	return nil, fmt.Errorf("(Source.Get) %w", ErrKeyNotFound)
}

// lookup resolves kid against the cache under the read lock, reporting whether it matched. An empty
// kid resolves to the first (highest-priority) key. It hands back the cached pointer, which keeps it
// cheap on the signing and key-embedding hot paths.
func (source *Source) lookup(kid string) (*jwa.JWK, bool) {
	source.mu.RLock()
	defer source.mu.RUnlock()

	if len(source.cached) == 0 {
		return nil, false
	}

	if kid == "" {
		return source.cached[0], true
	}

	for _, key := range source.cached {
		if key.KID == kid {
			return key, true
		}
	}

	return nil, false
}

// refreshForUnknownKeyID fetches when the cache is at least UnknownKeyIDInterval old, reporting
// whether it did.
func (source *Source) refreshForUnknownKeyID(ctx context.Context) (bool, error) {
	interval := source.config.UnknownKeyIDInterval
	if interval <= 0 {
		interval = DefaultUnknownKeyIDInterval
	}

	source.mu.Lock()
	defer source.mu.Unlock()

	// Re-checked under the write lock, which collapses a burst of unknown ids queued behind one
	// another into a single call.
	if time.Since(source.lastCached) < interval {
		return false, nil
	}

	err := source.fetchLocked(ctx)
	if err != nil {
		return false, err
	}

	return true, nil
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

	return source.fetchLocked(ctx)
}

// fetchLocked replaces the cache from Fetch. The caller must hold the write lock.
//
// Both refresh paths go through it, so the failure backoff applies whichever one reached it and an
// unknown key id stays subject to the negative caching that protects a broken upstream.
func (source *Source) fetchLocked(ctx context.Context) error {
	retry := source.config.RetryInterval
	if retry <= 0 {
		retry = DefaultRetryInterval
	}

	// The backoff runs from when the failure was observed, so a Fetch slower than retry still holds
	// the next caller off for a full interval.
	if source.lastErr != nil && time.Since(source.lastFailure) < retry {
		return source.lastErr
	}

	keys, err := source.config.Fetch(ctx)
	if err != nil {
		source.lastErr = fmt.Errorf("(Source.fetch) fetch keys: %w", err)
		source.lastFailure = time.Now()

		return source.lastErr
	}

	// Copy the returned slice before caching so a Fetch that reuses or later mutates its backing
	// array cannot corrupt the cache. make(...) also keeps the cache non-nil for an empty result, so
	// an empty key set still reads as fresh.
	cached := make([]*jwa.JWK, len(keys))
	copy(cached, keys)

	source.cached = cached
	source.lastCached = time.Now()
	source.lastErr = nil

	return nil
}
