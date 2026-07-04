package jwk

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/a-novel-kit/jwt/jwa"
)

// ErrKeyNotFound is returned by [Source.Get] when no cached key matches the request.
var ErrKeyNotFound = errors.New("key not found")

// KeysFetcher retrieves the raw JSON Web Keys backing a [Source]. Keys must be returned in
// priority order, most important first, because [Source.Get] falls back to the first key when no
// ID is requested.
type KeysFetcher func(ctx context.Context) ([]*jwa.JWK, error)

// KeyParser decodes a raw JSON Web Key into a typed [Key].
type KeyParser[K any] func(ctx context.Context, jwk *jwa.JWK) (*Key[K], error)

// SourceConfig configures a [Source].
type SourceConfig struct {
	// CacheDuration is how long fetched keys are held before the next fetch.
	CacheDuration time.Duration
	// Fetch retrieves the current keys.
	Fetch KeysFetcher
}

// A Source fetches, caches, and parses the keys used to sign or verify tokens. It refreshes lazily
// once the cached set is older than CacheDuration, and is safe for concurrent use.
type Source[K any] struct {
	config SourceConfig
	parser KeyParser[K]

	cached     []*Key[K]
	lastCached time.Time

	mu *sync.RWMutex
}

func (source *Source[K]) refresh(ctx context.Context) error {
	source.mu.Lock()
	defer source.mu.Unlock()

	if time.Since(source.lastCached) < source.config.CacheDuration {
		return nil
	}

	keys, err := source.config.Fetch(ctx)
	if err != nil {
		return fmt.Errorf("(Source.refresh) fetch keys: %w", err)
	}

	parsedKeys := make([]*Key[K], len(keys))

	for i, key := range keys {
		parsed, err := source.parser(ctx, key)
		if err != nil {
			return fmt.Errorf("(Source.refresh) parse key: %w", err)
		}

		parsedKeys[i] = parsed
	}

	source.cached = parsedKeys
	source.lastCached = time.Now()

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
