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

// PBES2KeyEncKWPreset pairs a JWA algorithm identifier with the hash and key size
// used to derive the wrap key from the password. Use one of the predefined presets
// rather than building one by hand.
type PBES2KeyEncKWPreset struct {
	Alg     jwa.Alg
	Hash    crypto.Hash
	KeySize int
}

// The PBES2 presets, one per supported hash and key size.
var (
	PBES2A128KW = PBES2KeyEncKWPreset{
		Alg:     jwa.PBES2HS256A128KW,
		Hash:    crypto.SHA256,
		KeySize: 16,
	}
	PBES2A192KW = PBES2KeyEncKWPreset{
		Alg:     jwa.PBES2HS384A192KW,
		Hash:    crypto.SHA384,
		KeySize: 24,
	}
	PBES2A256KW = PBES2KeyEncKWPreset{
		Alg:     jwa.PBES2HS512A256KW,
		Hash:    crypto.SHA512,
		KeySize: 32,
	}
)

// PBES2KeyEncKWManagerConfig holds the inputs for NewPBES2KeyEncKWManager.
type PBES2KeyEncKWManagerConfig struct {
	// Iterations is the PBKDF2 iteration count. A higher count raises the cost of
	// a brute-force attack on the password; a minimum of 1000 is recommended.
	Iterations int
	// SaltSize is the salt length in bytes. A salt of 128 bits or more is
	// recommended.
	SaltSize int

	// CEK is the content encryption key, encrypted under the wrap key derived from
	// Secret.
	CEK []byte
	// Secret is the password the wrap key is derived from. The recipient must know
	// it to decrypt the token.
	Secret string
}

// PBES2KeyEncKWConfig implements jwe.CEKManager: it derives a wrap key from a
// password with PBES2 (PBKDF2) and wraps the content encryption key with AES Key
// Wrap.
type PBES2KeyEncKWConfig struct {
	config PBES2KeyEncKWManagerConfig

	alg     jwa.Alg
	hash    crypto.Hash
	keySize int
}

// NewPBES2KeyEncKWManager creates a jwe.CEKManager that derives a wrap key from a
// password with PBES2 and wraps the content encryption key with AES Key Wrap. The
// preset selects the algorithm, hash, and key size; use one of the
// PBES2KeyEncKWPreset values (for example PBES2A128KW).
//
// https://datatracker.ietf.org/doc/html/rfc7518#section-4.8
func NewPBES2KeyEncKWManager(config *PBES2KeyEncKWManagerConfig, preset PBES2KeyEncKWPreset) *PBES2KeyEncKWConfig {
	return &PBES2KeyEncKWConfig{
		config:  *config,
		alg:     preset.Alg,
		hash:    preset.Hash,
		keySize: preset.KeySize,
	}
}

func (manager *PBES2KeyEncKWConfig) SetHeader(_ context.Context, header *jwa.JWH) (*jwa.JWH, error) {
	if !header.Alg.Empty() {
		return nil, fmt.Errorf("(PBES2KeyEncKWConfig.SetHeader) %w: alg field already set", jwt.ErrConflictingHeader)
	}

	// A fresh salt per token widens the key space so the same password never
	// derives the same wrap key twice. It travels in the header for the recipient.
	salt := make([]byte, manager.config.SaltSize)

	_, err := rand.Read(salt)
	if err != nil {
		return nil, fmt.Errorf("(PBES2KeyEncKWConfig.SetHeader) generate salt: %w", err)
	}

	header.JWHPBES2 = jwa.JWHPBES2{
		P2S: base64.RawURLEncoding.EncodeToString(salt),
		P2C: manager.config.Iterations,
	}
	header.Alg = manager.alg

	return header, nil
}

func (manager *PBES2KeyEncKWConfig) ComputeCEK(_ context.Context, _ *jwa.JWH) ([]byte, error) {
	return manager.config.CEK, nil
}

func (manager *PBES2KeyEncKWConfig) EncryptCEK(_ context.Context, header *jwa.JWH, cek []byte) ([]byte, error) {
	wrapKey := pbkdf2.Key(
		[]byte(manager.config.Secret),
		[]byte(header.P2S),
		header.P2C,
		manager.keySize,
		manager.hash.New,
	)

	block, err := aes.NewCipher(wrapKey)
	if err != nil {
		return nil, fmt.Errorf("(PBES2KeyEncKWConfig.EncryptCEK) create cipher: %w", err)
	}

	wrapped, err := internal.KeyWrap(block, cek)
	if err != nil {
		return nil, fmt.Errorf("(PBES2KeyEncKWConfig.EncryptCEK) wrap key: %w", err)
	}

	return wrapped, nil
}

// PBES2KeyEncKWDecoderConfig holds the password used to re-derive the wrap key and
// decrypt the content encryption key.
type PBES2KeyEncKWDecoderConfig struct {
	// Secret is the password the wrap key is derived from; it must match the one
	// used to encrypt the token.
	Secret string
}

// PBES2KeyEncKWDecoder implements jwe.CEKDecoder: it re-derives the wrap key from
// the password and unwraps the content encryption key with AES Key Wrap.
type PBES2KeyEncKWDecoder struct {
	config PBES2KeyEncKWDecoderConfig

	alg     jwa.Alg
	hash    crypto.Hash
	keySize int
}

// NewPBES2KeyEncKWDecoder creates a jwe.CEKDecoder that re-derives the wrap key
// from a password with PBES2 and unwraps the content encryption key with AES Key
// Wrap. The preset must match the one used to encrypt the token; use one of the
// PBES2KeyEncKWPreset values (for example PBES2A128KW).
//
// https://datatracker.ietf.org/doc/html/rfc7518#section-4.8
func NewPBES2KeyEncKWDecoder(config *PBES2KeyEncKWDecoderConfig, preset PBES2KeyEncKWPreset) *PBES2KeyEncKWDecoder {
	return &PBES2KeyEncKWDecoder{
		config:  *config,
		alg:     preset.Alg,
		hash:    preset.Hash,
		keySize: preset.KeySize,
	}
}

func (decoder *PBES2KeyEncKWDecoder) ComputeCEK(_ context.Context, header *jwa.JWH, encKey []byte) ([]byte, error) {
	if header.Alg != decoder.alg {
		return nil, fmt.Errorf(
			"(PBES2KeyEncKWDecoder.ComputeCEK) %w: invalid algorithm %s, expected %s",
			jwt.ErrMismatchRecipientPlugin, header.Alg, decoder.alg,
		)
	}

	if len(encKey) == 0 {
		return nil, fmt.Errorf(
			"(PBES2KeyEncKWDecoder.ComputeCEK) %w: missing enc key",
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
		return nil, fmt.Errorf("(PBES2KeyEncKWDecoder.ComputeCEK) create cipher: %w", err)
	}

	cek, err := internal.KeyUnwrap(block, encKey)
	if err != nil {
		return nil, fmt.Errorf("(PBES2KeyEncKWDecoder.ComputeCEK) unwrap key: %w", err)
	}

	return cek, nil
}
