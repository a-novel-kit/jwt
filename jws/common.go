package jws

import (
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/a-novel-kit/jwt/v2"
	"github.com/a-novel-kit/jwt/v2/jwa"
)

// ErrInvalidSignature is returned by a verifier when a token's signature does not match its header
// and payload, or when the signature is malformed. A source-backed verifier also returns it once no
// candidate key accepts the token. It matches [jwt.ErrTokenRejected].
var ErrInvalidSignature = fmt.Errorf("%w: invalid signature", jwt.ErrTokenRejected)

// ErrUnsupportedAlgorithm is returned when a preset names an algorithm the plugin cannot map to a
// signing scheme, such as an RSA plugin given an algorithm that is neither RS* nor PS*.
var ErrUnsupportedAlgorithm = errors.New("unsupported algorithm")

// signHeader sets alg on a header that names no algorithm yet. keyErr is the signer's key check: a
// signer refuses to label a token it cannot sign.
func signHeader(header *jwa.JWH, alg jwa.Alg, keyErr error) (*jwa.JWH, error) {
	if !header.Alg.Empty() {
		return nil, fmt.Errorf("%w: alg field already set", jwt.ErrConflictingHeader)
	}

	if keyErr != nil {
		return nil, keyErr
	}

	header.Alg = alg

	return header, nil
}

// signToken appends to the "header.payload" signing input the base64url signature sign computes,
// which gives the JWS Compact Serialization of RFC 7515 §7.1. keyErr is the signer's key check: a
// sourced signer resolves its key again here without going back through Header, so this check gates
// every signature.
func signToken(rawToken string, keyErr error, sign func(signingInput []byte) ([]byte, error)) (string, error) {
	if keyErr != nil {
		return "", keyErr
	}

	// The decoder checks the shape only: the token is already the "header.payload" signing input.
	_, err := (&jwt.RawTokenDecoder{}).Decode(rawToken)
	if err != nil {
		return "", fmt.Errorf("split token: %w", err)
	}

	signature, err := sign([]byte(rawToken))
	if err != nil {
		return "", err
	}

	return rawToken + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

// verifyToken checks a compact JWS and returns its decoded payload. A token under another algorithm
// than alg fails with [jwt.ErrMismatchRecipientPlugin], so the recipient tries its next plugin.
// keyErr is the verifier's key check, and verify checks the decoded signature over the signing
// input, failing with [ErrInvalidSignature] when it does not match.
func verifyToken(
	header *jwa.JWH, alg jwa.Alg, keyErr error, rawToken string,
	verify func(signingInput, signature []byte) error,
) ([]byte, error) {
	if header.Alg != alg {
		return nil, fmt.Errorf(
			"%w: invalid algorithm %s, expected %s", jwt.ErrMismatchRecipientPlugin, header.Alg, alg,
		)
	}

	if keyErr != nil {
		return nil, keyErr
	}

	token, err := (&jwt.SignedTokenDecoder{}).Decode(rawToken)
	if err != nil {
		return nil, fmt.Errorf("split token: %w", err)
	}

	// The signing input is the token up to the dot before its signature.
	signingInput := []byte(rawToken[:len(rawToken)-len(token.Signature)-1])

	signature, err := base64.RawURLEncoding.DecodeString(token.Signature)
	if err != nil {
		return nil, fmt.Errorf("%w: decode signature: %w", jwt.ErrUnsupportedTokenFormat, err)
	}

	err = verify(signingInput, signature)
	if err != nil {
		return nil, err
	}

	payload, err := base64.RawURLEncoding.DecodeString(token.Payload)
	if err != nil {
		return nil, fmt.Errorf("%w: decode payload: %w", jwt.ErrUnsupportedTokenFormat, err)
	}

	return payload, nil
}
