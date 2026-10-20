package jwk

import (
	"crypto/mldsa"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"

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

	privateSerialized, err := json.Marshal(serializers.EncodeMLDSA(privateKey))
	if err != nil {
		return nil, nil, fmt.Errorf("(GenerateMLDSA) serialize private key: %w", err)
	}

	publicSerialized, err := json.Marshal(serializers.EncodeMLDSA(publicKey))
	if err != nil {
		return nil, nil, fmt.Errorf("(GenerateMLDSA) serialize public key: %w", err)
	}

	kid := uuid.NewString()
	privateHeader := signatureHeader(jwa.KTYAKP, preset.Alg, jwa.KeyOpSign)
	publicHeader := signatureHeader(jwa.KTYAKP, preset.Alg, jwa.KeyOpVerify)
	privateHeader.KID, publicHeader.KID = kid, kid

	return NewKey(&jwa.JWK{JWKCommon: privateHeader, Payload: privateSerialized}, privateKey),
		NewKey(&jwa.JWK{JWKCommon: publicHeader, Payload: publicSerialized}, publicKey),
		nil
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

	matchPrivate := source.MatchPreset(signatureHeader(jwa.KTYAKP, source.Alg, jwa.KeyOpSign))
	matchPublic := source.MatchPreset(signatureHeader(jwa.KTYAKP, source.Alg, jwa.KeyOpVerify))

	if !matchPrivate && !matchPublic {
		return nil, nil, fmt.Errorf("(ConsumeMLDSA) %w", ErrJWKMismatch)
	}

	var payload serializers.MLDSAPayload

	err := json.Unmarshal(source.Payload, &payload)
	if err != nil {
		return nil, nil, fmt.Errorf("(ConsumeMLDSA) unmarshal payload: %w", err)
	}

	decodedPrivate, decodedPublic, err := serializers.DecodeMLDSA(&payload, params)
	if err != nil {
		return nil, nil, fmt.Errorf("(ConsumeMLDSA) decode payload: %w", err)
	}

	var privateKey *Key[*mldsa.PrivateKey]

	if decodedPrivate != nil {
		privateKey = NewKey(source, decodedPrivate)
	}

	return privateKey, NewKey(source, decodedPublic), nil
}
