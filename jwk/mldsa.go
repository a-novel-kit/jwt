package jwk

import (
	"crypto/mldsa"
	"fmt"

	"github.com/a-novel-kit/jwt/v2/jwa"
	"github.com/a-novel-kit/jwt/v2/jwk/serializers"
)

// An MLDSAPreset describes how to generate an ML-DSA JSON Web Key.
type MLDSAPreset struct {
	// Alg is the signature algorithm the key is bound to.
	Alg jwa.Alg
	// Params is the FIPS 204 parameter set the key uses.
	Params mldsa.Parameters
}

var (
	// MLDSA44 generates an ML-DSA-44 key, the parameter set FIPS 204 recommends for most
	// applications.
	MLDSA44 = MLDSAPreset{
		Alg:    jwa.MLDSA44,
		Params: mldsa.MLDSA44(),
	}
	// MLDSA65 generates an ML-DSA-65 key.
	MLDSA65 = MLDSAPreset{
		Alg:    jwa.MLDSA65,
		Params: mldsa.MLDSA65(),
	}
	// MLDSA87 generates an ML-DSA-87 key.
	MLDSA87 = MLDSAPreset{
		Alg:    jwa.MLDSA87,
		Params: mldsa.MLDSA87(),
	}
)

// GenerateMLDSA generates a new ML-DSA key pair, serialized as an Algorithm Key Pair (AKP) JSON Web
// Key whose private member is the 32-byte seed (RFC 9964).
//
// Call Key on either result for the native key, or marshal it into a JSON Web Key with json.Marshal.
//
// Pass one of the ML-DSA presets, such as [MLDSA44].
func GenerateMLDSA(preset MLDSAPreset) (*Key[*mldsa.PrivateKey], *Key[*mldsa.PublicKey], error) {
	privateKey, err := mldsa.GenerateKey(preset.Params)
	if err != nil {
		return nil, nil, fmt.Errorf("(GenerateMLDSA) generate key pair: %w", err)
	}

	publicKey := privateKey.PublicKey()

	private, public, err := newKeyPair(
		privateKey, serializers.EncodeMLDSA(privateKey), signatureHeader(jwa.KTYAKP, preset.Alg, jwa.KeyOpSign),
		publicKey, serializers.EncodeMLDSA(publicKey), signatureHeader(jwa.KTYAKP, preset.Alg, jwa.KeyOpVerify),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("(GenerateMLDSA) %w", err)
	}

	return private, public, nil
}

// ConsumeMLDSA parses a JSON Web Key into an ML-DSA signature key pair. The key's "alg" selects the
// parameter set. When the key holds only a public key, the returned private key is nil.
//
// It returns ErrJWKMismatch when the key does not represent an ML-DSA key.
func ConsumeMLDSA(source *jwa.JWK) (*Key[*mldsa.PrivateKey], *Key[*mldsa.PublicKey], error) {
	var params mldsa.Parameters

	switch source.Alg {
	case jwa.MLDSA44:
		params = MLDSA44.Params
	case jwa.MLDSA65:
		params = MLDSA65.Params
	case jwa.MLDSA87:
		params = MLDSA87.Params
	default:
		return nil, nil, fmt.Errorf("(ConsumeMLDSA) %w: %q is not an ML-DSA algorithm", ErrJWKMismatch, source.Alg)
	}

	privateKey, publicKey, err := consumeKeyPair(
		source,
		signatureHeader(jwa.KTYAKP, source.Alg, jwa.KeyOpSign),
		signatureHeader(jwa.KTYAKP, source.Alg, jwa.KeyOpVerify),
		func(payload *serializers.MLDSAPayload) (*mldsa.PrivateKey, *mldsa.PublicKey, error) {
			return serializers.DecodeMLDSA(payload, params)
		},
	)
	if err != nil {
		return nil, nil, fmt.Errorf("(ConsumeMLDSA) %w", err)
	}

	return privateKey, publicKey, nil
}
