package jwk

import (
	"sync"

	"github.com/a-novel-kit/jwt/v2/jwa"
)

// A Decoder decodes the raw keys of one [Source] into native keys of type K. It decodes each key once
// per fetched key set and serves the stored result afterwards, errors included. A plugin that
// resolves its key on every call thus skips the repeated parsing and validation, such as the scalar
// multiplication that checks an EC or Ed25519 private key. A refresh drops the stored results with
// the key set they came from.
//
// A key outside the Source's current set is decoded on every call and never stored. A Decoder is
// safe for concurrent use.
type Decoder[K any] struct {
	source *Source
	decode func(key *jwa.JWK) (K, error)

	mu         sync.Mutex
	generation uint64
	results    map[*jwa.JWK]decodeResult[K]
}

// decodeResult is the outcome of one decode, stored by a [Decoder].
type decodeResult[K any] struct {
	key K
	err error
}

// NewDecoder returns a [Decoder] for the keys of source. decode must depend on the key alone, since
// the Decoder serves its first result for a key until the next refresh.
func NewDecoder[K any](source *Source, decode func(key *jwa.JWK) (K, error)) *Decoder[K] {
	return &Decoder[K]{
		source:  source,
		decode:  decode,
		results: map[*jwa.JWK]decodeResult[K]{},
	}
}

// Decode returns what decode returns for key. A key of the Source's current set is decoded on its
// first call only.
func (decoder *Decoder[K]) Decode(key *jwa.JWK) (K, error) {
	generation, current := decoder.source.generationOf(key)
	if !current {
		return decoder.decode(key)
	}

	result, found := decoder.load(generation, key)
	if !found {
		result.key, result.err = decoder.decode(key)
		decoder.store(generation, key, result)
	}

	return result.key, result.err
}

// load returns the result stored for key. Reaching a newer key set first drops the results of the
// older one, which frees their decoded keys.
func (decoder *Decoder[K]) load(generation uint64, key *jwa.JWK) (decodeResult[K], bool) {
	decoder.mu.Lock()
	defer decoder.mu.Unlock()

	if generation > decoder.generation {
		decoder.generation = generation
		decoder.results = map[*jwa.JWK]decodeResult[K]{}
	}

	result, found := decoder.results[key]

	return result, found
}

// store keeps result for key, unless a newer key set replaced the one it was decoded from.
func (decoder *Decoder[K]) store(generation uint64, key *jwa.JWK, result decodeResult[K]) {
	decoder.mu.Lock()
	defer decoder.mu.Unlock()

	if generation == decoder.generation {
		decoder.results[key] = result
	}
}
