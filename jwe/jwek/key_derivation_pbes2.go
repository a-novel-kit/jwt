package jwek

import (
	"context"
	"crypto"
	"crypto/aes"
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"golang.org/x/crypto/pbkdf2"

	"github.com/a-novel-kit/jwt"
	"github.com/a-novel-kit/jwt/jwa"
	"github.com/a-novel-kit/jwt/jwe/internal"
)

type PBES2KeyAgrKWPreset struct {
	Alg     jwa.Alg
	Hash    crypto.Hash
	KeySize int
}

var (
	PBES2A128KW = PBES2KeyAgrKWPreset{
		Alg:     jwa.PBES2HS256A128KW,
		Hash:    crypto.SHA256,
		KeySize: 16,
	}
	PBES2A192KW = PBES2KeyAgrKWPreset{
		Alg:     jwa.PBES2HS384A192KW,
		Hash:    crypto.SHA384,
		KeySize: 24,
	}
	PBES2A256KW = PBES2KeyAgrKWPreset{
		Alg:     jwa.PBES2HS512A256KW,
		Hash:    crypto.SHA512,
		KeySize: 32,
	}
)

type PBES2KeyAgrKWManagerConfig struct {
	// The iteration count adds computational expense, ideally compounded by
	// the possible range of keys introduced by the salt. A minimum
	// iteration count of 1000 is RECOMMENDED.
	Iterations int
	// The salt size is the size of the salt in bytes. It is RECOMMENDED to
	// use a salt size of 128 bits or more.
	SaltSize int

	// CEK will be encrypted using the Secret.
	CEK []byte
	// Secret used to encrypt the CEK. The recipient will need to know this in order to decrypt the token.
	Secret string
}

type PBES2KeyAgrKWConfig struct {
	config PBES2KeyAgrKWManagerConfig

	alg     jwa.Alg
	hash    crypto.Hash
	keySize int
}

func (manager *PBES2KeyAgrKWConfig) SetHeader(_ context.Context, header *jwa.JWH) (*jwa.JWH, error) {
	if !header.Alg.Empty() {
		return nil, fmt.Errorf("(PBES2KeyAgrKWConfig.SetHeader) %w: alg field already set", jwt.ErrConflictingHeader)
	}

	// Generate a random salt.
	salt := make([]byte, manager.config.SaltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("(PBES2KeyAgrKWConfig.SetHeader) generate salt: %w", err)
	}

	header.JWHPBES2 = jwa.JWHPBES2{
		P2S: base64.RawURLEncoding.EncodeToString(salt),
		P2C: manager.config.Iterations,
	}
	// Might get changed by the actual encryption algorithm. This is an indication that key derivation was set
	// using ECDH, so the algorithm can properly check for compatibility.
	header.Alg = manager.alg

	return header, nil
}

func (manager *PBES2KeyAgrKWConfig) ComputeCEK(_ context.Context, _ *jwa.JWH) ([]byte, error) {
	return manager.config.CEK, nil
}

func (manager *PBES2KeyAgrKWConfig) EncryptCEK(_ context.Context, header *jwa.JWH, cek []byte) ([]byte, error) {
	wrapKey := pbkdf2.Key(
		[]byte(manager.config.Secret),
		[]byte(header.P2S),
		header.P2C,
		manager.keySize,
		manager.hash.New,
	)

	block, err := aes.NewCipher(wrapKey)
	if err != nil {
		return nil, fmt.Errorf("(PBES2KeyAgrKWConfig.EncryptCEK) create cipher: %w", err)
	}

	wrapped, err := internal.KeyWrap(block, cek)
	if err != nil {
		return nil, fmt.Errorf("(PBES2KeyAgrKWConfig.EncryptCEK) wrap key: %w", err)
	}

	return wrapped, nil
}

// NewPBES2KeyAgrKWManager creates a new jwe.CEKManager for a key derived using PBES2.
//
// Use any of the PBES2KeyAgrKWPreset constants to set the algorithm and key length.
//   - PBES2A128KW: PBES2 using HMAC with SHA-256 and a key size of 128 bits
//   - PBES2A192KW: PBES2 using HMAC with SHA-384 and a key size of 192 bits
//   - PBES2A256KW: PBES2 using HMAC with SHA-512 and a key size of 256 bits
func NewPBES2KeyAgrKWManager(config *PBES2KeyAgrKWManagerConfig, preset PBES2KeyAgrKWPreset) *PBES2KeyAgrKWConfig {
	return &PBES2KeyAgrKWConfig{
		config:  *config,
		alg:     preset.Alg,
		hash:    preset.Hash,
		keySize: preset.KeySize,
	}
}

type PBES2KeyAgrKWDecoderConfig struct {
	// Secret used to decrypt the CEK.
	Secret string
}

type PBES2KeyAgrKWDecoder struct {
	config PBES2KeyAgrKWDecoderConfig

	alg     jwa.Alg
	hash    crypto.Hash
	keySize int
}

func (decoder *PBES2KeyAgrKWDecoder) ComputeCEK(_ context.Context, header *jwa.JWH, encKey []byte) ([]byte, error) {
	if header.Alg != decoder.alg {
		return nil, fmt.Errorf(
			"(PBES2KeyAgrKWDecoder.ComputeCEK) %w: invalid algorithm %s, expected %s",
			jwt.ErrMismatchRecipientPlugin, header.Alg, decoder.alg,
		)
	}

	if len(encKey) == 0 {
		return nil, fmt.Errorf(
			"(PBES2KeyAgrKWDecoder.ComputeCEK) %w: missing enc key",
			jwt.ErrUnsupportedTokenFormat,
		)
	}

	wrapKey := pbkdf2.Key(
		[]byte(decoder.config.Secret),
		[]byte(header.P2S),
		header.P2C,
		decoder.keySize,
		decoder.hash.New,
	)

	block, err := aes.NewCipher(wrapKey)
	if err != nil {
		return nil, fmt.Errorf("(PBES2KeyAgrKWDecoder.ComputeCEK) create cipher: %w", err)
	}

	cek, err := internal.KeyUnwrap(block, encKey)
	if err != nil {
		return nil, fmt.Errorf("(PBES2KeyAgrKWDecoder.ComputeCEK) unwrap key: %w", err)
	}

	return cek, nil
}

// NewPBES2KeyAgrKWDecoder creates a new jwe.CEKDecoder for a key derived using PBES2.
//
// Use any of the PBES2KeyAgrKWPreset constants to set the algorithm and key length.
//   - PBES2A128KW: PBES2 using HMAC with SHA-256 and a key size of 128 bits
//   - PBES2A192KW: PBES2 using HMAC with SHA-384 and a key size of 192 bits
//   - PBES2A256KW: PBES2 using HMAC with SHA-512 and a key size of 256 bits
func NewPBES2KeyAgrKWDecoder(config *PBES2KeyAgrKWDecoderConfig, preset PBES2KeyAgrKWPreset) *PBES2KeyAgrKWDecoder {
	return &PBES2KeyAgrKWDecoder{
		config:  *config,
		alg:     preset.Alg,
		hash:    preset.Hash,
		keySize: preset.KeySize,
	}
}
