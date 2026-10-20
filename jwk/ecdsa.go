package jwk

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"

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
		return nil, nil, fmt.Errorf("(GenerateECDSA) generate private key: %w", err)
	}

	publicKey := &privateKey.PublicKey

	privatePayload, err := serializers.EncodeEC(privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("(GenerateECDSA) encode private key: %w", err)
	}

	publicPayload, err := serializers.EncodeEC(publicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("(GenerateECDSA) encode public key: %w", err)
	}

	privateSerialized, err := json.Marshal(privatePayload)
	if err != nil {
		return nil, nil, fmt.Errorf("(GenerateECDSA) serialize private key: %w", err)
	}

	publicSerialized, err := json.Marshal(publicPayload)
	if err != nil {
		return nil, nil, fmt.Errorf("(GenerateECDSA) serialize public key: %w", err)
	}

	kid := uuid.NewString()
	privateHeader := signatureHeader(jwa.KTYEC, preset.Alg, jwa.KeyOpSign)
	publicHeader := signatureHeader(jwa.KTYEC, preset.Alg, jwa.KeyOpVerify)
	privateHeader.KID, publicHeader.KID = kid, kid

	return NewKey(&jwa.JWK{JWKCommon: privateHeader, Payload: privateSerialized}, privateKey),
		NewKey(&jwa.JWK{JWKCommon: publicHeader, Payload: publicSerialized}, publicKey),
		nil
}

// ConsumeECDSA parses a JSON Web Key into an ECDSA signature key pair. When the key holds only a
// public key, the returned private key is nil.
//
// It returns ErrJWKMismatch when the key does not match the preset. Pass the same preset used to
// generate the key; see [GenerateECDSA] for the available presets.
func ConsumeECDSA(source *jwa.JWK, preset ECDSAPreset) (*Key[*ecdsa.PrivateKey], *Key[*ecdsa.PublicKey], error) {
	matchPrivate := source.MatchPreset(signatureHeader(jwa.KTYEC, preset.Alg, jwa.KeyOpSign))
	matchPublic := source.MatchPreset(signatureHeader(jwa.KTYEC, preset.Alg, jwa.KeyOpVerify))

	if !matchPrivate && !matchPublic {
		return nil, nil, fmt.Errorf("(ConsumeECDSA) %w", ErrJWKMismatch)
	}

	var ecPayload serializers.ECPayload

	err := json.Unmarshal(source.Payload, &ecPayload)
	if err != nil {
		return nil, nil, fmt.Errorf("(ConsumeECDSA) unmarshal payload: %w", err)
	}

	decodedPrivate, decodedPublic, err := serializers.DecodeEC(&ecPayload)
	if err != nil {
		return nil, nil, fmt.Errorf("(ConsumeECDSA) decode payload: %w", err)
	}

	// RFC 7518 §3.4 binds each algorithm to one curve, such as ES256 to P-256. The curve lives in the
	// payload, where MatchPreset above cannot see it, so it is checked here.
	if decodedPublic.Curve != preset.Curve {
		return nil, nil, fmt.Errorf(
			"(ConsumeECDSA) %w: key is on %s, preset %s requires %s",
			ErrJWKMismatch, curveName(decodedPublic.Curve), preset.Alg, curveName(preset.Curve),
		)
	}

	var privateKey *Key[*ecdsa.PrivateKey]

	if decodedPrivate != nil {
		privateKey = NewKey(source, decodedPrivate)
	}

	return privateKey, NewKey(source, decodedPublic), nil
}

// curveName reports a curve's standard name for an error message. A hand-built preset that names
// no curve reads as "unknown".
func curveName(curve elliptic.Curve) string {
	if curve == nil {
		return "unknown"
	}

	return curve.Params().Name
}
