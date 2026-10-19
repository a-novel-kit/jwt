package jws

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/a-novel-kit/jwt/v2"
	"github.com/a-novel-kit/jwt/v2/jwa"
	"github.com/a-novel-kit/jwt/v2/jwk"
)

// keyDecoder turns a raw JSON Web Key into the native key type a sourced plugin needs. It returns
// jwk.ErrJWKMismatch for a key of another algorithm family, which verifyFromSource and
// signFromSource skip in a mixed source.
type keyDecoder[K any] func(key *jwa.JWK) (K, error)

// permitting wraps decode so it refuses, as a key of another family, any key whose "key_ops" lack op.
// The Consume functions accept a key labeled for either half of a pair and return whatever material
// it carries, so a private key labeled for verification still decodes. The operation is checked
// here, where it is performed.
func permitting[K any](op jwa.KeyOp, decode keyDecoder[K]) keyDecoder[K] {
	return func(key *jwa.JWK) (K, error) {
		if !slices.Contains(key.KeyOps, op) {
			var zero K

			return zero, fmt.Errorf("%w: key_ops do not permit %s", jwk.ErrJWKMismatch, op)
		}

		return decode(key)
	}
}

// verifyFromSource tries the keys that may have signed the token until one verifies it. decode
// turns a raw key into this verifier's native type and rejects a key of another family with
// jwk.ErrJWKMismatch, which the loop skips. newVerifier builds a single-key verifier.
func verifyFromSource[K any](
	ctx context.Context,
	source *jwk.Source,
	header *jwa.JWH,
	rawToken string,
	decode keyDecoder[K],
	newVerifier func(key K) jwt.RecipientPlugin,
) ([]byte, error) {
	candidates, err := verificationCandidates(ctx, source, header.KID)
	if err != nil {
		return nil, fmt.Errorf("(verifyFromSource) %w", err)
	}

	decode = permitting(jwa.KeyOpVerify, decode)

	for _, candidate := range candidates {
		key, err := decode(candidate)
		if errors.Is(err, jwk.ErrJWKMismatch) {
			continue
		}

		// A key of this family that fails to decode is malformed material.
		if err != nil {
			return nil, fmt.Errorf("(verifyFromSource) decode key: %w", err)
		}

		payload, err := newVerifier(key).Transform(ctx, header, rawToken)
		if err == nil {
			return payload, nil
		}

		if !errors.Is(err, ErrInvalidSignature) {
			return nil, fmt.Errorf("(verifyFromSource) %w", err)
		}
	}

	return nil, fmt.Errorf("(verifyFromSource) %w", ErrInvalidSignature)
}

// verificationCandidates returns the keys that may have signed a token naming kid: every key the
// source lists when kid is empty, and the listed keys with that ID otherwise.
//
// A kid missing from the listed set is how a rotation looks from here, so the source is asked for it
// directly. The source decides whether to go upstream. With RefreshOnUnknownKeyID unset, the lookup
// scans the cache and finds no candidate.
func verificationCandidates(ctx context.Context, source *jwk.Source, kid string) ([]*jwa.JWK, error) {
	keys, err := source.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("list keys: %w", err)
	}

	if kid == "" {
		return keys, nil
	}

	named := slices.DeleteFunc(keys, func(key *jwa.JWK) bool { return key.KID != kid })
	if len(named) > 0 {
		return named, nil
	}

	key, err := source.Get(ctx, kid)
	if errors.Is(err, jwk.ErrKeyNotFound) {
		return nil, nil
	}

	if err != nil {
		return nil, fmt.Errorf("get key: %w", err)
	}

	return []*jwa.JWK{key}, nil
}

// signFromSource resolves the key a sourced signer should use: the one matching kid, or the first key
// that decodes to this signer's family when kid is empty. It returns the decoded key and the
// resolved key's ID so the signer can stamp the header. Selection consults nothing in the token
// header beyond an explicit kid, so the signer stays pinned to its own algorithm.
func signFromSource[K any](
	ctx context.Context,
	source *jwk.Source,
	kid string,
	decode keyDecoder[K],
) (K, string, error) {
	var zero K

	decode = permitting(jwa.KeyOpSign, decode)

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
