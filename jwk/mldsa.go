package jwk

import (
	"crypto/mldsa"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"

	"github.com/a-novel-kit/jwt/v2/jwa"
	"github.com/a-novel-kit/jwt/v2/jwk/serializers"
)

// An MLDSAPreset describes how to generate an ML-DSA JSON Web Key: the algorithm it is bound to and
// the FIPS 204 parameter set its keys use.
type MLDSAPreset struct {
	Alg    jwa.Alg
	Params mldsa.Parameters
}

// Post-quantum signature algorithms. FIPS 204 recommends [MLDSA44] for most applications.
var (
	MLDSA44 = MLDSAPreset{
		Alg:    jwa.MLDSA44,
		Params: mldsa.MLDSA44(),
	}
	MLDSA65 = MLDSAPreset{
		Alg:    jwa.MLDSA65,
		Params: mldsa.MLDSA65(),
	}
	MLDSA87 = MLDSAPreset{
		Alg:    jwa.MLDSA87,
		Params: mldsa.MLDSA87(),
	}
)

// GenerateMLDSA generates a new ML-DSA key pair, serialized as an Algorithm Key Pair (AKP) JSON Web
// Key whose private member is the 32-byte seed (RFC 9964).
//
// Retrieve a raw key with res.Key(), or marshal either result into a JSON Web Key with json.Marshal.
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

	privateJSONKey := &jwa.JWK{
		JWKCommon: jwa.JWKCommon{
			KTY:    jwa.KTYAKP,
			Use:    jwa.UseSig,
			KeyOps: jwa.KeyOps{jwa.KeyOpSign},
			Alg:    preset.Alg,
			KID:    kid,
		},
		Payload: privateSerialized,
	}
	publicJSONKey := &jwa.JWK{
		JWKCommon: jwa.JWKCommon{
			KTY:    jwa.KTYAKP,
			Use:    jwa.UseSig,
			KeyOps: jwa.KeyOps{jwa.KeyOpVerify},
			Alg:    preset.Alg,
			KID:    kid,
		},
		Payload: publicSerialized,
	}

	return NewKey(privateJSONKey, privateKey), NewKey(publicJSONKey, publicKey), nil
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

	matchPrivate := source.MatchPreset(jwa.JWKCommon{
		KTY:    jwa.KTYAKP,
		Use:    jwa.UseSig,
		KeyOps: jwa.KeyOps{jwa.KeyOpSign},
		Alg:    source.Alg,
	})
	matchPublic := source.MatchPreset(jwa.JWKCommon{
		KTY:    jwa.KTYAKP,
		Use:    jwa.UseSig,
		KeyOps: jwa.KeyOps{jwa.KeyOpVerify},
		Alg:    source.Alg,
	})

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
