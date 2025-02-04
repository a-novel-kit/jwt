package jwp

import (
	"context"
	"fmt"

	"github.com/a-novel-kit/jwt/jwa"
	"github.com/a-novel-kit/jwt/jwk"
)

type EmbedKeyConfig[K any] struct {
	// Source to get the key from. Optional, overrides Key if set.
	Source *jwk.Source[K]
	// JSON Web Key to embed. This is optional, and is overridden by Source if set.
	Key *jwa.JWK
	// ID of the key. If a Source is set, it will be used to retrieve the specific key.
	// If not provided, this parameter is automatically set using Key or Source, if present.
	KID string
	// URL to retrieve the key from. Optional.
	URL string
	// Embed the key. By default, only the KID is provided to save space. If this parameter is used, and a key is
	// provided, it will be fully embedded in the header.
	Embed bool
}

type EmbedKey[K any] struct {
	config EmbedKeyConfig[K]
}

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

// NewEmbedKey is a plugin that embeds a key in the header of a token. You can use this as a jwt.ProducerStaticPlugin.
func NewEmbedKey[K any](config EmbedKeyConfig[K]) *EmbedKey[K] {
	return &EmbedKey[K]{config: config}
}
