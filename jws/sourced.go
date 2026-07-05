package jws

import (
	"context"
	"errors"
	"fmt"

	"github.com/a-novel-kit/jwt/v2"
	"github.com/a-novel-kit/jwt/v2/jwa"
	"github.com/a-novel-kit/jwt/v2/jwk"
)

// keyDecoder turns a raw JSON Web Key into the native key type a sourced plugin needs. It returns an
// error when the key belongs to a different algorithm family; verifyFromSource and signFromSource
// use that error to skip the keys a mixed source holds for other algorithms.
type keyDecoder[K any] func(key *jwa.JWK) (K, error)

// verifyFromSource tries each key the source lists, honoring a KID hint, until one verifies the
// token or every candidate fails. decode turns a raw key into this verifier's native type (erroring
// on keys from another family, which are skipped); newVerifier builds a single-key verifier. It
// centralizes the loop the Sourced*Verifier types all share.
func verifyFromSource[K any](
	ctx context.Context,
	source *jwk.Source,
	header *jwa.JWH,
	rawToken string,
	decode keyDecoder[K],
	newVerifier func(key K) jwt.RecipientPlugin,
) ([]byte, error) {
	keys, err := source.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("(verifyFromSource) list keys: %w", err)
	}

	for _, candidate := range keys {
		// A token that names a KID can only match that key; skip the rest.
		if header.KID != "" && candidate.KID != header.KID {
			continue
		}

		key, decodeErr := decode(candidate)
		if decodeErr != nil {
			// A key of another algorithm family is not this verifier's to use — skip it. But a key of
			// the right family that fails to decode (malformed material) is a real error to surface,
			// not one to mask as an invalid signature.
			if errors.Is(decodeErr, jwk.ErrJWKMismatch) {
				continue
			}

			return nil, fmt.Errorf("(verifyFromSource) decode key: %w", decodeErr)
		}

		payload, verifyErr := newVerifier(key).Transform(ctx, header, rawToken)
		if verifyErr == nil {
			return payload, nil
		}

		if !errors.Is(verifyErr, ErrInvalidSignature) {
			return nil, fmt.Errorf("(verifyFromSource) %w", verifyErr)
		}
	}

	return nil, fmt.Errorf("(verifyFromSource) %w", ErrInvalidSignature)
}

// signFromSource resolves the key a sourced signer should use: the one matching kid, or — when kid
// is empty — the first key that decodes to this signer's family (skipping other families a mixed
// source holds). It returns the decoded key and the resolved key's ID so the signer can stamp the
// header. Selection never consults anything the token header carries beyond an explicit kid, so the
// signer stays pinned to its own algorithm.
func signFromSource[K any](
	ctx context.Context,
	source *jwk.Source,
	kid string,
	decode keyDecoder[K],
) (K, string, error) {
	var zero K

	if kid != "" {
		candidate, err := source.Get(ctx, kid)
		if err != nil {
			return zero, "", fmt.Errorf("(signFromSource) %w", err)
		}

		key, err := decode(candidate)
		if err != nil {
			return zero, "", fmt.Errorf("(signFromSource) %w", err)
		}

		return key, candidate.KID, nil
	}

	keys, err := source.List(ctx)
	if err != nil {
		return zero, "", fmt.Errorf("(signFromSource) %w", err)
	}

	for _, candidate := range keys {
		key, decodeErr := decode(candidate)
		if decodeErr != nil {
			// Skip keys of another family, but surface a malformed key of this family rather than
			// silently falling back to a lower-priority one — keys are listed in priority order.
			if errors.Is(decodeErr, jwk.ErrJWKMismatch) {
				continue
			}

			return zero, "", fmt.Errorf("(signFromSource) decode key: %w", decodeErr)
		}

		return key, candidate.KID, nil
	}

	return zero, "", fmt.Errorf("(signFromSource) %w", jwk.ErrKeyNotFound)
}
