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

// An RSAPreset describes how to generate or match an RSA JSON Web Key.
type RSAPreset struct {
	// Alg is the algorithm the key is bound to.
	Alg jwa.Alg
	// Use says whether the key serves signatures or key management.
	Use jwa.Use
	// PrivateKeyOps are the operations the private half permits.
	PrivateKeyOps jwa.KeyOps
	// PublicKeyOps are the operations the public half permits.
	PublicKeyOps jwa.KeyOps
	// KeySize is the modulus size of a generated key, in bits.
	KeySize int
}

var (
	// RS256 generates or matches a 2048-bit key for RSASSA-PKCS1-v1_5 with SHA-256.
	RS256 = RSAPreset{
		Alg:           jwa.RS256,
		Use:           jwa.UseSig,
		PrivateKeyOps: jwa.KeyOps{jwa.KeyOpSign},
		PublicKeyOps:  jwa.KeyOps{jwa.KeyOpVerify},
		KeySize:       2048,
	}
	// RS384 generates or matches a 3072-bit key for RSASSA-PKCS1-v1_5 with SHA-384.
	RS384 = RSAPreset{
		Alg:           jwa.RS384,
		Use:           jwa.UseSig,
		PrivateKeyOps: jwa.KeyOps{jwa.KeyOpSign},
		PublicKeyOps:  jwa.KeyOps{jwa.KeyOpVerify},
		KeySize:       3072,
	}
	// RS512 generates or matches a 4096-bit key for RSASSA-PKCS1-v1_5 with SHA-512.
	RS512 = RSAPreset{
		Alg:           jwa.RS512,
		Use:           jwa.UseSig,
		PrivateKeyOps: jwa.KeyOps{jwa.KeyOpSign},
		PublicKeyOps:  jwa.KeyOps{jwa.KeyOpVerify},
		KeySize:       4096,
	}

	// PS256 generates or matches a 2048-bit key for RSASSA-PSS with SHA-256.
	PS256 = RSAPreset{
		Alg:           jwa.PS256,
		Use:           jwa.UseSig,
		PrivateKeyOps: jwa.KeyOps{jwa.KeyOpSign},
		PublicKeyOps:  jwa.KeyOps{jwa.KeyOpVerify},
		KeySize:       2048,
	}
	// PS384 generates or matches a 3072-bit key for RSASSA-PSS with SHA-384.
	PS384 = RSAPreset{
		Alg:           jwa.PS384,
		Use:           jwa.UseSig,
		PrivateKeyOps: jwa.KeyOps{jwa.KeyOpSign},
		PublicKeyOps:  jwa.KeyOps{jwa.KeyOpVerify},
		KeySize:       3072,
	}
	// PS512 generates or matches a 4096-bit key for RSASSA-PSS with SHA-512.
	PS512 = RSAPreset{
		Alg:           jwa.PS512,
		Use:           jwa.UseSig,
		PrivateKeyOps: jwa.KeyOps{jwa.KeyOpSign},
		PublicKeyOps:  jwa.KeyOps{jwa.KeyOpVerify},
		KeySize:       4096,
	}
)

var (
	// RSAOAEP generates or matches a 4096-bit key for RSAES-OAEP with SHA-1.
	RSAOAEP = RSAPreset{
		Alg:           jwa.RSAOAEP,
		Use:           jwa.UseEnc,
		PrivateKeyOps: jwa.KeyOps{jwa.KeyOpUnwrapKey},
		PublicKeyOps:  jwa.KeyOps{jwa.KeyOpWrapKey},
		KeySize:       4096,
	}
	// RSAOAEP256 generates or matches a 4096-bit key for RSAES-OAEP with SHA-256.
	RSAOAEP256 = RSAPreset{
		Alg:           jwa.RSAOAEP256,
		Use:           jwa.UseEnc,
		PrivateKeyOps: jwa.KeyOps{jwa.KeyOpUnwrapKey},
		PublicKeyOps:  jwa.KeyOps{jwa.KeyOpWrapKey},
		KeySize:       4096,
	}
)

// GenerateRSA generates a new RSA public/private key pair.
//
// Call Key on either result for the native key, or marshal it into a JSON Web Key with json.Marshal.
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

	privateSerialized, err := json.Marshal(privatePayload)
	if err != nil {
		return nil, nil, fmt.Errorf("(GenerateRSA) serialize private key: %w", err)
	}

	publicSerialized, err := json.Marshal(publicPayload)
	if err != nil {
		return nil, nil, fmt.Errorf("(GenerateRSA) serialize public key: %w", err)
	}

	kid := uuid.NewString()
	privateHeader := rsaHeader(preset, preset.PrivateKeyOps)
	publicHeader := rsaHeader(preset, preset.PublicKeyOps)
	privateHeader.KID, publicHeader.KID = kid, kid

	return NewKey(&jwa.JWK{JWKCommon: privateHeader, Payload: privateSerialized}, privateKey),
		NewKey(&jwa.JWK{JWKCommon: publicHeader, Payload: publicSerialized}, publicKey),
		nil
}

// ConsumeRSA parses a JSON Web Key into an RSA key pair for signature or key-management
// algorithms. When the key holds only a public key, the returned private key is nil.
//
// It returns ErrJWKMismatch when the key does not match the preset. Pass the same preset used to
// generate the key; see [GenerateRSA] for the available presets.
func ConsumeRSA(source *jwa.JWK, preset RSAPreset) (*Key[*rsa.PrivateKey], *Key[*rsa.PublicKey], error) {
	matchPrivate := source.MatchPreset(rsaHeader(preset, preset.PrivateKeyOps))
	matchPublic := source.MatchPreset(rsaHeader(preset, preset.PublicKeyOps))

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

	var privateKey *Key[*rsa.PrivateKey]

	if decodedPrivate != nil {
		privateKey = NewKey(source, decodedPrivate)
	}

	return privateKey, NewKey(source, decodedPublic), nil
}

// rsaHeader returns the common parameters of the RSA key half that permits keyOps under preset.
// GenerateRSA stamps them with a key ID, and ConsumeRSA requires them.
func rsaHeader(preset RSAPreset, keyOps jwa.KeyOps) jwa.JWKCommon {
	return jwa.JWKCommon{
		KTY:    jwa.KTYRSA,
		Use:    preset.Use,
		KeyOps: keyOps,
		Alg:    preset.Alg,
	}
}
