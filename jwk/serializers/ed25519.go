package serializers

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/a-novel-kit/jwt/v2/jwa"
)

// An EDPayload wraps an EdDSA key in a JWKCommon format.
type EDPayload struct {
	// Crv is the JWK curve identifier. Only "Ed25519" is supported: the standard library does not implement the
	// Ed448 variant, so any other value makes DecodeED return an error. Plug in your own decoder if you need Ed448.
	//
	// https://github.com/golang/go/issues/29390
	Crv string `json:"crv"`
	// X is the base64url-encoded public key.
	X string `json:"x"`

	// D is the base64url-encoded private key, set only for private keys. It holds the 32-byte private
	// key of RFC 8032, which the standard library calls the seed.
	//
	// https://datatracker.ietf.org/doc/html/rfc8037#section-2
	D string `json:"d,omitempty"`
}

// ErrInvalidEDKey is returned when a decoded EdDSA key does not have the size Ed25519 requires, or when
// its private and public halves do not belong together.
var ErrInvalidEDKey = errors.New("invalid EdDSA key")

// DecodeED decodes the EdDSA key from a JWKCommon format.
//
// Besides the 32-byte private key RFC 8037 specifies, "d" may hold the 64-byte seed-and-public-key
// form of ed25519.PrivateKey, so keys serialized from that form keep loading.
func DecodeED(src *EDPayload) (ed25519.PrivateKey, ed25519.PublicKey, error) {
	if src.Crv != jwa.CrvEd25519 {
		return nil, nil, ErrUnsupportedCurve
	}

	publicKey, err := base64.RawURLEncoding.DecodeString(src.X)
	if err != nil {
		return nil, nil, fmt.Errorf("decode eddsa public key: %w", err)
	}

	if len(publicKey) != ed25519.PublicKeySize {
		return nil, nil, fmt.Errorf("%w: invalid public key size", ErrInvalidEDKey)
	}

	edPubKey := ed25519.PublicKey(publicKey)

	if src.D == "" {
		return nil, edPubKey, nil
	}

	privateKey, err := base64.RawURLEncoding.DecodeString(src.D)
	if err != nil {
		return nil, nil, fmt.Errorf("decode eddsa private key: %w", err)
	}

	if len(privateKey) != ed25519.SeedSize && len(privateKey) != ed25519.PrivateKeySize {
		return nil, nil, fmt.Errorf("%w: invalid private key size", ErrInvalidEDKey)
	}

	edPrivKey := ed25519.NewKeyFromSeed(privateKey[:ed25519.SeedSize])

	// A signature made with a private key that does not match "x" never verifies against it.
	if !edPubKey.Equal(edPrivKey.Public()) {
		return nil, nil, fmt.Errorf("%w: private key does not match public key", ErrInvalidEDKey)
	}

	return edPrivKey, edPubKey, nil
}

// EncodeED returns the JWKCommon representation of an EdDSA key.
func EncodeED[Key ed25519.PublicKey | ed25519.PrivateKey](key Key) *EDPayload {
	pubKey, ok := any(key).(ed25519.PublicKey)
	if ok {
		encodedPub := base64.RawURLEncoding.EncodeToString(pubKey)

		return &EDPayload{
			Crv: jwa.CrvEd25519,
			X:   encodedPub,
		}
	}

	privKey := any(key).(ed25519.PrivateKey)

	encodedPub := base64.RawURLEncoding.EncodeToString(privKey.Public().(ed25519.PublicKey))
	encodedPriv := base64.RawURLEncoding.EncodeToString(privKey.Seed())

	return &EDPayload{
		Crv: jwa.CrvEd25519,
		X:   encodedPub,
		D:   encodedPriv,
	}
}
