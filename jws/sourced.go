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

// A sourcedSigner signs with the key a [jwk.Source] holds for the token, resolved at each call, so
// the signer follows key rotation. The exported Sourced*Signer types embed a pointer to it, each
// with the decoder of its family and the single-key signer newSigner builds. The pointer keeps those
// types comparable.
type sourcedSigner[K any] struct {
	source    *jwk.Source
	keys      *jwk.Decoder[K]
	newSigner func(key K) jwt.ProducerPlugin
}

// newSourcedSigner returns a sourcedSigner drawing keys from source through decode, restricted to
// keys whose "key_ops" permit signing.
func newSourcedSigner[K any](
	source *jwk.Source, decode keyDecoder[K], newSigner func(key K) jwt.ProducerPlugin,
) *sourcedSigner[K] {
	return &sourcedSigner[K]{
		source:    source,
		keys:      jwk.NewDecoder(source, permitting(jwa.KeyOpSign, decode)),
		newSigner: newSigner,
	}
}

// Header resolves the signing key and stamps its ID into a header that names none, so recipients
// can select the key for verification.
func (signer *sourcedSigner[K]) Header(ctx context.Context, header *jwa.JWH) (*jwa.JWH, error) {
	key, kid, err := signFromSource(ctx, signer.source, header.KID, signer.keys.Decode)
	if err != nil {
		return nil, err
	}

	if header.KID == "" {
		header.KID = kid
	}

	return signer.newSigner(key).Header(ctx, header)
}

// Transform signs the token with the key its header names, or the first key of the family.
func (signer *sourcedSigner[K]) Transform(ctx context.Context, header *jwa.JWH, rawToken string) (string, error) {
	key, _, err := signFromSource(ctx, signer.source, header.KID, signer.keys.Decode)
	if err != nil {
		return "", err
	}

	return signer.newSigner(key).Transform(ctx, header, rawToken)
}

// A sourcedVerifier verifies with the keys a [jwk.Source] holds, resolved at each call. When the
// token names a KID, it tries only that key. Otherwise it tries every key of its family. The
// exported Sourced*Verifier types embed a pointer to it, each with the decoder of its family and the
// single-key verifier newVerifier builds. The pointer keeps those types comparable.
type sourcedVerifier[K any] struct {
	source      *jwk.Source
	keys        *jwk.Decoder[K]
	newVerifier func(key K) jwt.RecipientPlugin
}

// newSourcedVerifier returns a sourcedVerifier drawing keys from source through decode, restricted
// to keys whose "key_ops" permit verification.
func newSourcedVerifier[K any](
	source *jwk.Source, decode keyDecoder[K], newVerifier func(key K) jwt.RecipientPlugin,
) *sourcedVerifier[K] {
	return &sourcedVerifier[K]{
		source:      source,
		keys:        jwk.NewDecoder(source, permitting(jwa.KeyOpVerify, decode)),
		newVerifier: newVerifier,
	}
}

// Transform returns the payload once a candidate key verifies the token.
func (verifier *sourcedVerifier[K]) Transform(ctx context.Context, header *jwa.JWH, rawToken string) ([]byte, error) {
	return verifyFromSource(ctx, verifier.source, header, rawToken, verifier.keys.Decode, verifier.newVerifier)
}

// keyPair is the signature of the jwk Consume functions, bound to a preset where they take one.
type keyPair[Priv, Pub any] func(key *jwa.JWK) (*jwk.Key[Priv], *jwk.Key[Pub], error)

// privateHalf decodes a raw JSON Web Key into the private key a signer needs. A key that carries
// only the public half belongs to verifiers, so it is skipped as a key of another family.
func privateHalf[Priv, Pub any](consume keyPair[Priv, Pub]) keyDecoder[Priv] {
	return func(key *jwa.JWK) (Priv, error) {
		var zero Priv

		privateKey, _, err := consume(key)
		if err != nil {
			return zero, err
		}

		if privateKey == nil {
			return zero, fmt.Errorf("%w: key holds no private material", jwk.ErrJWKMismatch)
		}

		return privateKey.Key(), nil
	}
}

// publicHalf decodes a raw JSON Web Key into the public key a verifier needs. A source exposing
// private material is misconfigured, so such a key is skipped as one of another family.
func publicHalf[Priv, Pub any](consume keyPair[Priv, Pub]) keyDecoder[Pub] {
	return func(key *jwa.JWK) (Pub, error) {
		var zero Pub

		privateKey, publicKey, err := consume(key)
		if err != nil {
			return zero, err
		}

		if privateKey != nil {
			return zero, fmt.Errorf("%w: source exposes a private key", jwk.ErrJWKMismatch)
		}

		return publicKey.Key(), nil
	}
}

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
// turns a raw key into this verifier's native type. It rejects a key of another family, or one not
// permitted to verify, with jwk.ErrJWKMismatch, which the loop skips. newVerifier builds a single-key
// verifier.
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
// that decodes to this signer's family when kid is empty. decode rejects a key not permitted to sign
// as one of another family. It returns the decoded key and the
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
