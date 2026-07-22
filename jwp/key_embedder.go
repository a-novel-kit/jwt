package jwp

import (
	"context"
	"fmt"

	"github.com/a-novel-kit/jwt/v2/jwa"
	"github.com/a-novel-kit/jwt/v2/jwk"
)

// An EmbedKeyConfig configures how an [EmbedKey] advertises the signing key in a token's header: by
// identifier, by URL, or by embedding the key itself.
type EmbedKeyConfig struct {
	// Source of keys resolved at signing time. When set, it supersedes Key.
	Source *jwk.Source
	// JSON Web Key to embed directly. Ignored when Source is set.
	Key *jwa.JWK
	// Identifier of the key. With a Source set, it selects which key to fetch. Left empty, it is
	// filled from the resolved key.
	KID string
	// JWK Set URL recorded in the header's "jku" field, telling recipients where to fetch the key.
	URL string
	// Embed writes the key itself into the header. When false, only the identifier is written, to
	// keep the token small.
	//
	// The key must be a public one. A header travels inside the token, so embedding a key that
	// carries private material hands the signing key to every recipient; Header refuses it with
	// [jwk.ErrPrivateKeyMaterial]. Source resolves the signing key, private half included, so pass
	// [jwk.Public] over it — a symmetric key cannot be embedded at all.
	Embed bool
}

// An EmbedKey records the signing key in a token's header so recipients can locate it, as a
// [jwt.ProducerStaticPlugin]. Build one with [NewEmbedKey].
type EmbedKey struct {
	config EmbedKeyConfig
}

// NewEmbedKey returns an [EmbedKey] that advertises the signing key in the token header. Use it as a
// [jwt.ProducerStaticPlugin].
func NewEmbedKey(config EmbedKeyConfig) *EmbedKey {
	return &EmbedKey{config: config}
}

// Header writes the key's identifier, URL, and — when configured — the key itself into the token
// header.
func (plugin *EmbedKey) Header(ctx context.Context, header *jwa.JWH) (*jwa.JWH, error) {
	key := plugin.config.Key
	kid := plugin.config.KID

	if plugin.config.Source != nil {
		sourceKey, err := plugin.config.Source.Get(ctx, plugin.config.KID)
		if err != nil {
			return nil, fmt.Errorf("(EmbedKey.Header) get key: %w", err)
		}

		key = sourceKey
	}

	if kid == "" && key != nil {
		kid = key.KID
	}

	header.KID = kid
	header.JKU = plugin.config.URL

	if plugin.config.Embed && key != nil {
		// The header ships inside the token, so a key with private material here
		// hands the signing key to every recipient of every token. Source
		// resolves signing keys, which is exactly where that key comes from.
		private, err := jwk.HasPrivateMaterial(key)
		if err != nil {
			return nil, fmt.Errorf("(EmbedKey.Header) inspect key: %w", err)
		}

		if private {
			return nil, fmt.Errorf("(EmbedKey.Header) refusing to embed %s key %q: %w",
				key.KTY, kid, jwk.ErrPrivateKeyMaterial)
		}

		header.JWK = key
	}

	return header, nil
}
