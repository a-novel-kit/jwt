package jws

import (
	"crypto/rsa"
	"errors"
	"fmt"

	"github.com/a-novel-kit/jwt/v2"
)

// ErrInvalidSignature is returned by a verifier when a token's signature does not match its header
// and payload, or when the signature is malformed. A source-backed verifier also returns it once no
// candidate key accepts the token.
var ErrInvalidSignature = errors.New("invalid signature")

// ErrUnsupportedAlgorithm is returned when a preset names an algorithm the plugin cannot map to a
// signing scheme — for example an RSA plugin given an algorithm that is neither RS* nor PS*.
var ErrUnsupportedAlgorithm = errors.New("unsupported algorithm")

// minRSAKeyBits is the smallest RSA modulus the RS* and PS* algorithms accept, per RFC 7518 §3.3
// and §3.5 ("A key of size 2048 bits or larger MUST be used"). Enforced at both sign and verify.
const minRSAKeyBits = 2048

// checkRSAPublicKey fails closed unless key is a usable RSA public key: non-nil, with a positive
// modulus of at least minRSAKeyBits. It rejects nil, non-positive (BitLen reads the absolute value,
// so a negative modulus would otherwise pass), and sub-floor moduli, so no invalid key reaches
// crypto/rsa where the failure would be later and less clear.
func checkRSAPublicKey(key *rsa.PublicKey) error {
	if key == nil || key.N == nil || key.N.Sign() <= 0 {
		return fmt.Errorf("%w: RSA key has no valid modulus", jwt.ErrInvalidSecretKey)
	}

	if key.N.BitLen() < minRSAKeyBits {
		return fmt.Errorf(
			"%w: RSA key is %d bits, need at least %d",
			jwt.ErrInvalidSecretKey, key.N.BitLen(), minRSAKeyBits,
		)
	}

	return nil
}

// checkRSAPrivateKey applies checkRSAPublicKey to a private key's public half, rejecting a nil key
// first so the dereference is safe.
func checkRSAPrivateKey(key *rsa.PrivateKey) error {
	if key == nil {
		return fmt.Errorf("%w: nil RSA key", jwt.ErrInvalidSecretKey)
	}

	return checkRSAPublicKey(&key.PublicKey)
}
