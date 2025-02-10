package jwk

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"

	"github.com/a-novel-kit/jwt/jwa"
	"github.com/a-novel-kit/jwt/jwk/serializers"
)

type RSAPreset struct {
	Alg           jwa.Alg
	Use           jwa.Use
	PrivateKeyOps []jwa.KeyOp
	PublicKeyOps  []jwa.KeyOp
	KeySize       int
}

// Signature algorithms.
var (
	RS256 = RSAPreset{
		Alg:           jwa.RS256,
		Use:           jwa.UseSig,
		PrivateKeyOps: []jwa.KeyOp{jwa.KeyOpSign},
		PublicKeyOps:  []jwa.KeyOp{jwa.KeyOpVerify},
		// The signature size (in bytes, before re-encoding as text) is the key size (in bit), divided by 8 and rounded up
		// to the next integer.
		//
		// ⌈2048/8⌉=256 bytes.
		//
		// https://crypto.stackexchange.com/a/95882
		KeySize: 2048,
	}
	RS384 = RSAPreset{
		Alg:           jwa.RS384,
		Use:           jwa.UseSig,
		PrivateKeyOps: []jwa.KeyOp{jwa.KeyOpSign},
		PublicKeyOps:  []jwa.KeyOp{jwa.KeyOpVerify},
		// The signature size (in bytes, before re-encoding as text) is the key size (in bit), divided by 8 and rounded up
		// to the next integer.
		//
		// ⌈3072/8⌉=384 bytes.
		//
		// https://crypto.stackexchange.com/a/95882
		KeySize: 3072,
	}
	RS512 = RSAPreset{
		Alg:           jwa.RS512,
		Use:           jwa.UseSig,
		PrivateKeyOps: []jwa.KeyOp{jwa.KeyOpSign},
		PublicKeyOps:  []jwa.KeyOp{jwa.KeyOpVerify},
		// The signature size (in bytes, before re-encoding as text) is the key size (in bit), divided by 8 and rounded up
		// to the next integer.
		//
		// ⌈4096/8⌉=512 bytes.
		//
		// https://crypto.stackexchange.com/a/95882
		KeySize: 4096,
	}

	PS256 = RSAPreset{
		Alg:           jwa.PS256,
		Use:           jwa.UseSig,
		PrivateKeyOps: []jwa.KeyOp{jwa.KeyOpSign},
		PublicKeyOps:  []jwa.KeyOp{jwa.KeyOpVerify},
		// The signature size (in bytes, before re-encoding as text) is the key size (in bit), divided by 8 and rounded up
		// to the next integer.
		//
		// ⌈4096/8⌉=512 bytes.
		//
		// https://crypto.stackexchange.com/a/95882
		KeySize: 2048,
	}
	PS384 = RSAPreset{
		Alg:           jwa.PS384,
		Use:           jwa.UseSig,
		PrivateKeyOps: []jwa.KeyOp{jwa.KeyOpSign},
		PublicKeyOps:  []jwa.KeyOp{jwa.KeyOpVerify},
		// The signature size (in bytes, before re-encoding as text) is the key size (in bit), divided by 8 and rounded up
		// to the next integer.
		//
		// ⌈3072/8⌉=384 bytes.
		//
		// https://crypto.stackexchange.com/a/95882
		KeySize: 3072,
	}
	PS512 = RSAPreset{
		Alg:           jwa.PS512,
		Use:           jwa.UseSig,
		PrivateKeyOps: []jwa.KeyOp{jwa.KeyOpSign},
		PublicKeyOps:  []jwa.KeyOp{jwa.KeyOpVerify},
		// The signature size (in bytes, before re-encoding as text) is the key size (in bit), divided by 8 and rounded up
		// to the next integer.
		//
		// ⌈4096/8⌉=512 bytes.
		//
		// https://crypto.stackexchange.com/a/95882
		KeySize: 4096,
	}
)

// Key management algorithms.
var (
	RSAOAEP = RSAPreset{
		Alg:           jwa.RSAOAEP,
		Use:           jwa.UseEnc,
		PrivateKeyOps: []jwa.KeyOp{jwa.KeyOpEncrypt},
		PublicKeyOps:  []jwa.KeyOp{jwa.KeyOpDecrypt},
		KeySize:       4096,
	}
	RSAOAEP256 = RSAPreset{
		Alg:           jwa.RSAOAEP256,
		Use:           jwa.UseEnc,
		PrivateKeyOps: []jwa.KeyOp{jwa.KeyOpEncrypt},
		PublicKeyOps:  []jwa.KeyOp{jwa.KeyOpDecrypt},
		KeySize:       4096,
	}
)

// GenerateRSA generates a new RSA public/private key pair.
//
// You can either retrieve the secret key directly (using res.Key()), or marshal the result into a JSON Web Key,
// using json.Marshal.
//
// Available presets for signature algorithms are:
//   - RS256
//   - RS384
//   - RS512
//   - PS256
//   - PS384
//   - PS512
//
// Available presets for key management algorithms are:
//   - RSAOAEP
//   - RSAOAEP256
func GenerateRSA(preset RSAPreset) (*Key[*rsa.PrivateKey], *Key[*rsa.PublicKey], error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, preset.KeySize)
	if err != nil {
		return nil, nil, fmt.Errorf("(GenerateRSA) generate private key: %w", err)
	}

	publicKey := &privateKey.PublicKey

	privatePayload := serializers.EncodeRSA(privateKey)
	publicPayload := serializers.EncodeRSA(publicKey)

	kid := uuid.NewString()

	privateHeader := jwa.JWKCommon{
		KTY:    jwa.KTYRSA,
		Use:    preset.Use,
		KeyOps: preset.PrivateKeyOps,
		Alg:    preset.Alg,
		KID:    kid,
	}
	publicHeader := jwa.JWKCommon{
		KTY:    jwa.KTYRSA,
		Use:    preset.Use,
		KeyOps: preset.PublicKeyOps,
		Alg:    preset.Alg,
		KID:    kid,
	}

	privateSerialized, err := json.Marshal(privatePayload)
	if err != nil {
		return nil, nil, fmt.Errorf("(GenerateRSA) serialize private key: %w", err)
	}

	publicSerialized, err := json.Marshal(publicPayload)
	if err != nil {
		return nil, nil, fmt.Errorf("(GenerateRSA) serialize public key: %w", err)
	}

	privateJSONKey := &jwa.JWK{
		JWKCommon: privateHeader,
		Payload:   privateSerialized,
	}
	publicJSONKey := &jwa.JWK{
		JWKCommon: publicHeader,
		Payload:   publicSerialized,
	}

	return &Key[*rsa.PrivateKey]{privateJSONKey, privateKey}, &Key[*rsa.PublicKey]{publicJSONKey, publicKey}, nil
}

// ConsumeRSA consumes a JSON Web Key and returns the secret key for RSA signature and encryption algorithms.
//
// If the JSON Web Key does not represent the RSA key described by the preset, ErrJWKMismatch is returned.
//
// If the key represents a public key only, the private key will be nil.
//
// Available presets for signature algorithms are:
//   - RS256
//   - RS384
//   - RS512
//   - PS256
//   - PS384
//   - PS512
//
// Available presets for key management algorithms are:
//   - RSAOAEP
//   - RSAOAEP256
func ConsumeRSA(source *jwa.JWK, preset RSAPreset) (*Key[*rsa.PrivateKey], *Key[*rsa.PublicKey], error) {
	matchPrivate := source.MatchPreset(jwa.JWKCommon{
		KTY:    jwa.KTYRSA,
		Use:    preset.Use,
		KeyOps: preset.PrivateKeyOps,
		Alg:    preset.Alg,
	})
	matchPublic := source.MatchPreset(jwa.JWKCommon{
		KTY:    jwa.KTYRSA,
		Use:    preset.Use,
		KeyOps: preset.PublicKeyOps,
		Alg:    preset.Alg,
	})

	if !matchPrivate && !matchPublic {
		return nil, nil, fmt.Errorf("(ConsumeRSA) %w", ErrJWKMismatch)
	}

	var rsaPayload serializers.RSAPayload
	if err := json.Unmarshal(source.Payload, &rsaPayload); err != nil {
		return nil, nil, fmt.Errorf("(ConsumeRSA) unmarshal payload: %w", err)
	}

	decodedPrivate, decodedPublic, err := serializers.DecodeRSA(&rsaPayload)
	if err != nil {
		return nil, nil, fmt.Errorf("(ConsumeRSA) decode payload: %w", err)
	}

	var (
		privateKey *Key[*rsa.PrivateKey]
		publicKey  *Key[*rsa.PublicKey]
	)

	if decodedPrivate != nil {
		privateKey = NewKey[*rsa.PrivateKey](source, decodedPrivate)
	}

	if decodedPublic != nil {
		publicKey = NewKey[*rsa.PublicKey](source, decodedPublic)
	}

	return privateKey, publicKey, nil
}

func NewRSAPublicSource(config SourceConfig, preset RSAPreset) *Source[*rsa.PublicKey] {
	parser := func(_ context.Context, jwk *jwa.JWK) (*Key[*rsa.PublicKey], error) {
		privateKey, publicKey, err := ConsumeRSA(jwk, preset)
		if privateKey != nil {
			return nil, fmt.Errorf("(NewRSAPublicSource) %w: source is providing private keys", ErrJWKMismatch)
		}

		return publicKey, err
	}

	return NewGenericSource[*rsa.PublicKey](config, parser)
}

func NewRSAPrivateSource(config SourceConfig, preset RSAPreset) *Source[*rsa.PrivateKey] {
	parser := func(_ context.Context, jwk *jwa.JWK) (*Key[*rsa.PrivateKey], error) {
		privateKey, _, err := ConsumeRSA(jwk, preset)
		if privateKey == nil {
			return nil, fmt.Errorf("(NewRSAPrivateSource) %w: source is providing public keys", ErrJWKMismatch)
		}

		return privateKey, err
	}

	return NewGenericSource[*rsa.PrivateKey](config, parser)
}
