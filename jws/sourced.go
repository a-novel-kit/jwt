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
// token or every candidate fails. decode turns a raw key into this verifier's native type, erroring
// on keys from another family, which are skipped; newVerifier builds a single-key verifier.
func verifyFromSource[K any](
	ctx context.Context,
	source *jwk.Source,
	header *jwa.JWH,
	rawToken string,
	decode keyDecoder[K],
	newVerifier func(key K) jwt.RecipientPlugin,
) ([]byte, error) {
	// try verifies the token with candidate. A nil payload and a nil error means the candidate was
	// not this verifier's to use, or did not verify — either way, keep looking.
	try := func(candidate *jwa.JWK) ([]byte, error) {
		key, decodeErr := decode(candidate)
		if decodeErr != nil {
			// Skip a key of another algorithm family. A key of this family that fails to decode is
			// malformed material, and surfaces as an error of its own.
			if errors.Is(decodeErr, jwk.ErrJWKMismatch) {
				return nil, nil
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

		return nil, nil
	}

	keys, err := source.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("(verifyFromSource) list keys: %w", err)
	}

	named := false

	for _, candidate := range keys {
		// A token that names a KID can only match that key; skip the rest.
		if header.KID != "" && candidate.KID != header.KID {
			continue
		}

		named = true

		payload, tryErr := try(candidate)
		if tryErr != nil {
			return nil, tryErr
		}

		if payload != nil {
			return payload, nil
		}
	}

	if header.KID == "" || named {
		return nil, fmt.Errorf("(verifyFromSource) %w", ErrInvalidSignature)
	}

	// The token names a key id the cached set does not hold, which is how a rotation looks from here,
	// so ask the source for the id directly. The source decides whether to go upstream; with
	// RefreshOnUnknownKeyID unset this is a cache scan that changes nothing.
	candidate, err := source.Get(ctx, header.KID)
	if err != nil {
		// Still unknown after the source has had its say, so the signature is unverifiable.
		if errors.Is(err, jwk.ErrKeyNotFound) {
			return nil, fmt.Errorf("(verifyFromSource) %w", ErrInvalidSignature)
		}

		return nil, fmt.Errorf("(verifyFromSource) get key: %w", err)
	}

	payload, err := try(candidate)
	if err != nil {
		return nil, err
	}

	if payload != nil {
		return payload, nil
	}

	return nil, fmt.Errorf("(verifyFromSource) %w", ErrInvalidSignature)
}

// signFromSource resolves the key a sourced signer should use: the one matching kid, or — when kid
// is empty — the first key that decodes to this signer's family. It returns the decoded key and the
// resolved key's ID so the signer can stamp the header. Selection consults nothing in the token
// header beyond an explicit kid, so the signer stays pinned to its own algorithm.
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
			// Skip keys of another family. Keys are listed in priority order, and the first match is the
			// one to sign with. A malformed key of this family is an error.
			if errors.Is(decodeErr, jwk.ErrJWKMismatch) {
				continue
			}

			return zero, "", fmt.Errorf("(signFromSource) decode key: %w", decodeErr)
		}

		return key, candidate.KID, nil
	}

	return zero, "", fmt.Errorf("(signFromSource) %w", jwk.ErrKeyNotFound)
}
