package jwk

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"

	"github.com/a-novel-kit/jwt/v2/jwa"
	"github.com/a-novel-kit/jwt/v2/jwk/serializers"
)

// GenerateED25519 generates a new Ed25519 key pair.
//
// Call Key on either result for the native key, or marshal it into a JSON Web Key with json.Marshal.
func GenerateED25519() (*Key[ed25519.PrivateKey], *Key[ed25519.PublicKey], error) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate key pair: %w", err)
	}

	private, public, err := newKeyPair(
		privateKey, serializers.EncodeED(privateKey), signatureHeader(jwa.KTYOKP, jwa.Ed25519, jwa.KeyOpSign),
		publicKey, serializers.EncodeED(publicKey), signatureHeader(jwa.KTYOKP, jwa.Ed25519, jwa.KeyOpVerify),
	)
	if err != nil {
		return nil, nil, err
	}

	return private, public, nil
}

// ConsumeED25519 parses a JSON Web Key into an Ed25519 signature key pair. When the key holds only
// a public key, the returned private key is nil. A key labeled with the deprecated "EdDSA" algorithm
// is accepted as well.
//
// It returns ErrJWKMismatch when the key does not represent an Ed25519 key.
func ConsumeED25519(source *jwa.JWK) (*Key[ed25519.PrivateKey], *Key[ed25519.PublicKey], error) {
	// RFC 9864 keeps a key labeled with the deprecated "EdDSA" valid as an Ed25519 key, so the expected
	// headers take that label from such a key.
	alg := jwa.Ed25519
	if source.Alg == jwa.EdDSA { //nolint:staticcheck // The deprecated label stays accepted.
		alg = source.Alg
	}

	privateKey, publicKey, err := consumeKeyPair(
		source,
		signatureHeader(jwa.KTYOKP, alg, jwa.KeyOpSign),
		signatureHeader(jwa.KTYOKP, alg, jwa.KeyOpVerify),
		serializers.DecodeED,
	)
	if err != nil {
		return nil, nil, err
	}

	return privateKey, publicKey, nil
}
