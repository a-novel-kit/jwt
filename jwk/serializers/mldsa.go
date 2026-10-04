package serializers

import (
	"crypto/mldsa"
	"encoding/base64"
	"errors"
	"fmt"
)

// An MLDSAPayload wraps an ML-DSA key in the members of an Algorithm Key Pair (AKP) JSON Web Key.
// The key's "alg" names its parameter set, so the payload carries no curve or size of its own.
//
// https://datatracker.ietf.org/doc/html/rfc9964#section-3
type MLDSAPayload struct {
	// Pub is the base64url-encoded FIPS 204 public key.
	Pub string `json:"pub"`

	// Priv is the base64url-encoded 32-byte seed the private key expands from, set only for private
	// keys.
	Priv string `json:"priv,omitempty"`
}

// ErrInvalidMLDSAKey is returned when a decoded ML-DSA key has the wrong size for its parameter set,
// or when its private and public halves do not belong together.
var ErrInvalidMLDSAKey = errors.New("invalid ML-DSA key")

// DecodeMLDSA decodes the ML-DSA key from its AKP members, under the parameter set the key's "alg"
// names.
func DecodeMLDSA(src *MLDSAPayload, params mldsa.Parameters) (*mldsa.PrivateKey, *mldsa.PublicKey, error) {
	pub, err := base64.RawURLEncoding.DecodeString(src.Pub)
	if err != nil {
		return nil, nil, fmt.Errorf("decode ml-dsa public key: %w", err)
	}

	publicKey, err := mldsa.NewPublicKey(params, pub)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w", ErrInvalidMLDSAKey, err)
	}

	if src.Priv == "" {
		return nil, publicKey, nil
	}

	seed, err := base64.RawURLEncoding.DecodeString(src.Priv)
	if err != nil {
		return nil, nil, fmt.Errorf("decode ml-dsa private key: %w", err)
	}

	// RFC 9964 §7.3 requires the seed length check.
	if len(seed) != mldsa.PrivateKeySize {
		return nil, nil, fmt.Errorf("%w: seed is %d bytes, need %d", ErrInvalidMLDSAKey, len(seed), mldsa.PrivateKeySize)
	}

	privateKey, err := mldsa.NewPrivateKey(params, seed)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w", ErrInvalidMLDSAKey, err)
	}

	// RFC 9964 §7.4: a "pub" that does not match "priv" yields signatures that never verify against it.
	if !privateKey.PublicKey().Equal(publicKey) {
		return nil, nil, fmt.Errorf("%w: private key does not match public key", ErrInvalidMLDSAKey)
	}

	return privateKey, publicKey, nil
}

// EncodeMLDSA returns the AKP members of an ML-DSA key.
func EncodeMLDSA[Key *mldsa.PublicKey | *mldsa.PrivateKey](key Key) *MLDSAPayload {
	if publicKey, ok := any(key).(*mldsa.PublicKey); ok {
		return &MLDSAPayload{Pub: base64.RawURLEncoding.EncodeToString(publicKey.Bytes())}
	}

	privateKey := any(key).(*mldsa.PrivateKey)

	return &MLDSAPayload{
		Pub:  base64.RawURLEncoding.EncodeToString(privateKey.PublicKey().Bytes()),
		Priv: base64.RawURLEncoding.EncodeToString(privateKey.Bytes()),
	}
}
