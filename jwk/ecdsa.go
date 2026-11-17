package jwk

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"

	"github.com/a-novel-kit/jwt/v2/jwa"
	"github.com/a-novel-kit/jwt/v2/jwk/serializers"
)

// An ECDSAPreset describes how to generate or match an ECDSA JSON Web Key.
type ECDSAPreset struct {
	// Alg is the signature algorithm the key is bound to.
	Alg jwa.Alg
	// Curve is the elliptic curve the key lives on, the one Alg requires.
	Curve elliptic.Curve
}

var (
	// ES256 generates or matches a P-256 key for ECDSA with SHA-256.
	ES256 = ECDSAPreset{
		Alg:   jwa.ES256,
		Curve: elliptic.P256(),
	}
	// ES384 generates or matches a P-384 key for ECDSA with SHA-384.
	ES384 = ECDSAPreset{
		Alg:   jwa.ES384,
		Curve: elliptic.P384(),
	}
	// ES512 generates or matches a P-521 key for ECDSA with SHA-512.
	ES512 = ECDSAPreset{
		Alg:   jwa.ES512,
		Curve: elliptic.P521(),
	}
)

// GenerateECDSA generates a new ECDSA key pair.
//
// Call Key on either result for the native key, or marshal it into a JSON Web Key with json.Marshal.
//
// Pass one of the ECDSA presets, such as [ES256].
func GenerateECDSA(preset ECDSAPreset) (*Key[*ecdsa.PrivateKey], *Key[*ecdsa.PublicKey], error) {
	privateKey, err := ecdsa.GenerateKey(preset.Curve, rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate private key: %w", err)
	}

	publicKey := &privateKey.PublicKey

	privatePayload, err := serializers.EncodeEC(privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("encode private key: %w", err)
	}

	publicPayload, err := serializers.EncodeEC(publicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("encode public key: %w", err)
	}

	private, public, err := newKeyPair(
		privateKey, privatePayload, signatureHeader(jwa.KTYEC, preset.Alg, jwa.KeyOpSign),
		publicKey, publicPayload, signatureHeader(jwa.KTYEC, preset.Alg, jwa.KeyOpVerify),
	)
	if err != nil {
		return nil, nil, err
	}

	return private, public, nil
}

// ConsumeECDSA parses a JSON Web Key into an ECDSA signature key pair. When the key holds only a
// public key, the returned private key is nil.
//
// It returns ErrJWKMismatch when the key does not match the preset. Pass the same preset used to
// generate the key; see [GenerateECDSA] for the available presets.
func ConsumeECDSA(source *jwa.JWK, preset ECDSAPreset) (*Key[*ecdsa.PrivateKey], *Key[*ecdsa.PublicKey], error) {
	privateKey, publicKey, err := consumeKeyPair(
		source,
		signatureHeader(jwa.KTYEC, preset.Alg, jwa.KeyOpSign),
		signatureHeader(jwa.KTYEC, preset.Alg, jwa.KeyOpVerify),
		serializers.DecodeEC,
	)
	if err != nil {
		return nil, nil, err
	}

	// RFC 7518 §3.4 binds each algorithm to one curve, such as ES256 to P-256. The curve lives in the
	// payload, where the preset match cannot see it, so it is checked here.
	if curve := publicKey.Key().Curve; curve != preset.Curve {
		return nil, nil, fmt.Errorf(
			"%w: key is on %s, preset %s requires %s",
			ErrJWKMismatch, curveName(curve), preset.Alg, curveName(preset.Curve),
		)
	}

	return privateKey, publicKey, nil
}

// curveName reports a curve's standard name for an error message. A hand-built preset that names
// no curve reads as "unknown".
func curveName(curve elliptic.Curve) string {
	if curve == nil {
		return "unknown"
	}

	return curve.Params().Name
}
