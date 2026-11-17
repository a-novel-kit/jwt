package jwk

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	"github.com/google/uuid"

	"github.com/a-novel-kit/jwt/v2/jwa"
	"github.com/a-novel-kit/jwt/v2/jwk/serializers"
)

// ErrJWKMismatch is returned when a JSON Web Key does not match the preset it is parsed against, such
// as a key bound to another algorithm.
var ErrJWKMismatch = errors.New("jwk and key mismatch")

// A Key pairs a JSON Web Key with its decoded native representation of type K, such as an
// *rsa.PrivateKey or a raw byte slice. The embedded [jwa.JWK] carries the serialized form.
type Key[K any] struct {
	*jwa.JWK

	parsed K
}

// Key returns the decoded native key.
func (key *Key[K]) Key() K {
	return key.parsed
}

// NewKey pairs an already-decoded key with its JSON Web Key form.
func NewKey[K any](jwk *jwa.JWK, parsed K) *Key[K] {
	return &Key[K]{jwk, parsed}
}

// signatureHeader returns the common parameters of the signature key half that performs op:
// jwa.KeyOpSign for a private key, jwa.KeyOpVerify for a public one. A Generate function stamps
// them with a key ID, and the matching Consume function requires them.
func signatureHeader(kty jwa.KTY, alg jwa.Alg, op jwa.KeyOp) jwa.JWKCommon {
	return jwa.JWKCommon{
		KTY:    kty,
		Use:    jwa.UseSig,
		KeyOps: jwa.KeyOps{op},
		Alg:    alg,
	}
}

// newOctKey generates a random secret of keySize bytes and serializes it as an "oct" JSON Web Key
// under header, stamped with a fresh key ID.
func newOctKey(header jwa.JWKCommon, keySize int) (*Key[[]byte], error) {
	key := make([]byte, keySize)
	_, _ = rand.Read(key) // never fails: it crashes the program instead

	payload, err := json.Marshal(serializers.EncodeOct(key))
	if err != nil {
		return nil, fmt.Errorf("serialize payload: %w", err)
	}

	// The header's key_ops come from an exported preset, so the key gets its own copy.
	header.KID, header.KeyOps = uuid.NewString(), slices.Clone(header.KeyOps)

	return NewKey(&jwa.JWK{JWKCommon: header, Payload: payload}, key), nil
}

// consumeOct parses an "oct" JSON Web Key into its secret, once its parameters match header.
func consumeOct(source *jwa.JWK, header jwa.JWKCommon) (*Key[[]byte], error) {
	if !source.MatchPreset(header) {
		return nil, ErrJWKMismatch
	}

	var payload serializers.OctPayload

	err := json.Unmarshal(source.Payload, &payload)
	if err != nil {
		return nil, fmt.Errorf("unmarshal payload: %w", err)
	}

	decoded, err := serializers.DecodeOct(&payload)
	if err != nil {
		return nil, fmt.Errorf("decode payload: %w", err)
	}

	return NewKey(source, decoded), nil
}

// newKeyPair serializes the two halves of a generated key pair, each from its encoded payload and
// under its header. Both halves share one fresh key ID, so a verifier finds the public half under the
// ID of the private half that signed.
func newKeyPair[Priv, Pub any](
	privateKey Priv, privatePayload any, privateHeader jwa.JWKCommon,
	publicKey Pub, publicPayload any, publicHeader jwa.JWKCommon,
) (*Key[Priv], *Key[Pub], error) {
	privateSerialized, err := json.Marshal(privatePayload)
	if err != nil {
		return nil, nil, fmt.Errorf("serialize private key: %w", err)
	}

	publicSerialized, err := json.Marshal(publicPayload)
	if err != nil {
		return nil, nil, fmt.Errorf("serialize public key: %w", err)
	}

	kid := uuid.NewString()
	privateHeader.KID, publicHeader.KID = kid, kid

	// The headers' key_ops come from an exported preset, so each key gets its own copy.
	privateHeader.KeyOps = slices.Clone(privateHeader.KeyOps)
	publicHeader.KeyOps = slices.Clone(publicHeader.KeyOps)

	return NewKey(&jwa.JWK{JWKCommon: privateHeader, Payload: privateSerialized}, privateKey),
		NewKey(&jwa.JWK{JWKCommon: publicHeader, Payload: publicSerialized}, publicKey),
		nil
}

// asymmetricPrivateKey lists the native private keys of the asymmetric families. Each one is nil when
// a key carries only its public half.
type asymmetricPrivateKey interface {
	*ecdsa.PrivateKey | ed25519.PrivateKey | *ecdh.PrivateKey | *rsa.PrivateKey | *mldsa.PrivateKey
}

// consumeKeyPair parses source into the halves of a key pair, once its parameters match the private
// or the public header. decode turns the payload members P into native keys. The private half is nil
// when source carries only the public one.
func consumeKeyPair[P any, Priv asymmetricPrivateKey, Pub any](
	source *jwa.JWK, privateHeader, publicHeader jwa.JWKCommon, decode func(*P) (Priv, Pub, error),
) (*Key[Priv], *Key[Pub], error) {
	if !source.MatchPreset(privateHeader) && !source.MatchPreset(publicHeader) {
		return nil, nil, ErrJWKMismatch
	}

	var payload P

	err := json.Unmarshal(source.Payload, &payload)
	if err != nil {
		return nil, nil, fmt.Errorf("unmarshal payload: %w", err)
	}

	decodedPrivate, decodedPublic, err := decode(&payload)
	if err != nil {
		return nil, nil, fmt.Errorf("decode payload: %w", err)
	}

	var privateKey *Key[Priv]

	if decodedPrivate != nil {
		privateKey = NewKey(source, decodedPrivate)
	}

	return privateKey, NewKey(source, decodedPublic), nil
}
