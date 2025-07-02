package jwk

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/a-novel-kit/jwt/jwa"
)

var ErrKeyNotFound = errors.New("key not found")

// KeysFetcher is a function that fetches keys from a source. The keys MUST be sorted by priority, with top-most keys
// being the most important.
type KeysFetcher func(ctx context.Context) ([]*jwa.JWK, error)

// KeyParser decodes keys from a source into a consumable format.
type KeyParser[K any] func(ctx context.Context, jwk *jwa.JWK) (*Key[K], error)

type SourceConfig struct {
	// How long keys are cached before being refreshed.
	CacheDuration time.Duration
	// Method used to refresh keys.
	Fetch KeysFetcher
}

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

// List every key available.
func (source *Source[K]) List(ctx context.Context) ([]*Key[K], error) {
	err := source.refresh(ctx)
	if err != nil {
		return nil, fmt.Errorf("(Source.List) refresh keys: %w", err)
	}

	source.mu.RLock()
	defer source.mu.RUnlock()

	return source.cached, nil
}

// Get a key using a specific ID. If the KID parameter is empty, the first key available will be returned.
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

func NewGenericSource[K any](config SourceConfig, parser KeyParser[K]) *Source[K] {
	return &Source[K]{
		config:     config,
		parser:     parser,
		cached:     nil,
		lastCached: time.Time{},
		mu:         new(sync.RWMutex),
	}
}
