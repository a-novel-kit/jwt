package jwp

import (
	"context"
	"fmt"

	"github.com/a-novel-kit/jwt/v2/jwa"
	"github.com/a-novel-kit/jwt/v2/jwk"
)

// An EmbedKeyConfig configures how an [EmbedKey] advertises the signing key in a token's header: by
// identifier, by URL, or by embedding the key itself.
type EmbedKeyConfig[K any] struct {
	// Key source resolved at signing time. When set, it supersedes Key.
	Source *jwk.Source[K]
	// JSON Web Key to embed directly. Ignored when Source is set.
	Key *jwa.JWK
	// Identifier of the key. With a Source set, it selects which key to fetch. Left empty, it is
	// filled from the resolved key.
	KID string
	// JWK Set URL recorded in the header's "jku" field, telling recipients where to fetch the key.
	URL string
	// Embed writes the full key into the header. When false, only the identifier is written, to
	// keep the token small.
	Embed bool
}

// An EmbedKey records the signing key in a token's header so recipients can locate it, as a
// [jwt.ProducerStaticPlugin]. Build one with [NewEmbedKey].
type EmbedKey[K any] struct {
	config EmbedKeyConfig[K]
}

// Header writes the key's identifier, URL, and — when configured — the key itself into the token
// header.
func (plugin *EmbedKey[K]) Header(ctx context.Context, header *jwa.JWH) (*jwa.JWH, error) {
	key := plugin.config.Key
	kid := plugin.config.KID

	if plugin.config.Source != nil {
		sourceKey, err := plugin.config.Source.Get(ctx, plugin.config.KID)
		if err != nil {
			return nil, fmt.Errorf("(EmbedKey.Header) get key: %w", err)
		}

		key = sourceKey.JWK
	}

	if kid == "" && key != nil {
		kid = key.KID
	}

	header.KID = kid
	header.JKU = plugin.config.URL

	if plugin.config.Embed && key != nil {
		header.JWK = key
	}

	return header, nil
}

// NewEmbedKey returns an [EmbedKey] that advertises the signing key in the token header. Use it as a
// [jwt.ProducerStaticPlugin].
func NewEmbedKey[K any](config EmbedKeyConfig[K]) *EmbedKey[K] {
	return &EmbedKey[K]{config: config}
}
