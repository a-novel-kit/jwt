package jws

import (
	"context"
	"errors"
	"fmt"

	"github.com/a-novel-kit/jwt"
	"github.com/a-novel-kit/jwt/jwa"
	"github.com/a-novel-kit/jwt/jwk"
)

// verifyFromSource tries each key the source lists, honoring a KID hint, until one verifies the
// token or every candidate fails with a signature mismatch. newVerifier builds a single-key
// verifier for a resolved key. It centralizes the loop the Sourced*Verifier types all shared.
func verifyFromSource[K any](
	ctx context.Context,
	source *jwk.Source[K],
	header *jwa.JWH,
	rawToken string,
	newVerifier func(key K) jwt.RecipientPlugin,
) ([]byte, error) {
	keys, err := source.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("(verifyFromSource) list keys: %w", err)
	}

	for _, key := range keys {
		// A token that names a KID can only match that key; skip the rest.
		if header.KID != "" && key.KID != header.KID {
			continue
		}

		payload, err := newVerifier(key.Key()).Transform(ctx, header, rawToken)
		if err == nil {
			return payload, nil
		}

		if !errors.Is(err, ErrInvalidSignature) {
			return nil, fmt.Errorf("(verifyFromSource) %w", err)
		}
	}

	return nil, fmt.Errorf("(verifyFromSource) %w", ErrInvalidSignature)
}
