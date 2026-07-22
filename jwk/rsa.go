package jwk

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"

	"github.com/a-novel-kit/jwt/v2/jwa"
	"github.com/a-novel-kit/jwt/v2/jwk/serializers"
)

// An RSAPreset describes how to generate or match an RSA JSON Web Key: the algorithm it is bound
// to, whether the key is used for signatures or key management, the operations allowed on each
// half of the pair, and the modulus size in bits.
//
// A modulus of n bits signs into ⌈n/8⌉ bytes, which is what pairs the 2048-, 3072-, and 4096-bit
// signature presets with the SHA-256, SHA-384, and SHA-512 variants.
type RSAPreset struct {
	Alg           jwa.Alg
	Use           jwa.Use
	PrivateKeyOps jwa.KeyOps
	PublicKeyOps  jwa.KeyOps
	KeySize       int
}

// Signature algorithms.
var (
	RS256 = RSAPreset{
		Alg:           jwa.RS256,
		Use:           jwa.UseSig,
		PrivateKeyOps: jwa.KeyOps{jwa.KeyOpSign},
		PublicKeyOps:  jwa.KeyOps{jwa.KeyOpVerify},
		KeySize:       2048,
	}
	RS384 = RSAPreset{
		Alg:           jwa.RS384,
		Use:           jwa.UseSig,
		PrivateKeyOps: jwa.KeyOps{jwa.KeyOpSign},
		PublicKeyOps:  jwa.KeyOps{jwa.KeyOpVerify},
		KeySize:       3072,
	}
	RS512 = RSAPreset{
		Alg:           jwa.RS512,
		Use:           jwa.UseSig,
		PrivateKeyOps: jwa.KeyOps{jwa.KeyOpSign},
		PublicKeyOps:  jwa.KeyOps{jwa.KeyOpVerify},
		KeySize:       4096,
	}

	PS256 = RSAPreset{
		Alg:           jwa.PS256,
		Use:           jwa.UseSig,
		PrivateKeyOps: jwa.KeyOps{jwa.KeyOpSign},
		PublicKeyOps:  jwa.KeyOps{jwa.KeyOpVerify},
		KeySize:       2048,
	}
	PS384 = RSAPreset{
		Alg:           jwa.PS384,
		Use:           jwa.UseSig,
		PrivateKeyOps: jwa.KeyOps{jwa.KeyOpSign},
		PublicKeyOps:  jwa.KeyOps{jwa.KeyOpVerify},
		KeySize:       3072,
	}
	PS512 = RSAPreset{
		Alg:           jwa.PS512,
		Use:           jwa.UseSig,
		PrivateKeyOps: jwa.KeyOps{jwa.KeyOpSign},
		PublicKeyOps:  jwa.KeyOps{jwa.KeyOpVerify},
		KeySize:       4096,
	}
)

// Key management algorithms.
var (
	RSAOAEP = RSAPreset{
		Alg:           jwa.RSAOAEP,
		Use:           jwa.UseEnc,
		PrivateKeyOps: jwa.KeyOps{jwa.KeyOpEncrypt},
		PublicKeyOps:  jwa.KeyOps{jwa.KeyOpDecrypt},
		KeySize:       4096,
	}
	RSAOAEP256 = RSAPreset{
		Alg:           jwa.RSAOAEP256,
		Use:           jwa.UseEnc,
		PrivateKeyOps: jwa.KeyOps{jwa.KeyOpEncrypt},
		PublicKeyOps:  jwa.KeyOps{jwa.KeyOpDecrypt},
		KeySize:       4096,
	}
)

// GenerateRSA generates a new RSA public/private key pair.
//
// Retrieve a raw key with res.Key(), or marshal either result into a JSON Web Key with json.Marshal.
//
// Pass one of the RSA presets: the signature presets, such as [RS256], or the key-management
// presets, such as [RSAOAEP].
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

// ConsumeRSA parses a JSON Web Key into an RSA key pair for signature or key-management
// algorithms. When the key holds only a public key, the returned private key is nil.
//
// It returns ErrJWKMismatch when the key does not match the preset. Pass the same preset used to
// generate the key; see [GenerateRSA] for the available presets.
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

	err := json.Unmarshal(source.Payload, &rsaPayload)
	if err != nil {
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
