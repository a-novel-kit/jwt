package jwek

import (
	"context"
	"crypto"
	"crypto/aes"
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"golang.org/x/crypto/pbkdf2"

	"github.com/a-novel-kit/jwt/v2"
	"github.com/a-novel-kit/jwt/v2/jwa"
	"github.com/a-novel-kit/jwt/v2/jwe/internal"
)

// PBES2KeyEncKWPreset pairs a JWA algorithm identifier with the hash and key size
// used to derive the wrap key from the password. Use one of the predefined presets.
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

// DefaultPBES2Iterations is the PBKDF2 iteration count used when the config leaves Iterations
// unset. RFC 7518 §4.8.1.2 recommends a minimum of 1000; this is well above it.
const DefaultPBES2Iterations = 310_000

// DefaultPBES2SaltSize is the salt length in bytes used when the config leaves SaltSize unset. RFC
// 7518 §4.8.1.1 recommends 128 bits or more.
const DefaultPBES2SaltSize = 16

// PBES2KeyEncKWManagerConfig holds the inputs for NewPBES2KeyEncKWManager.
type PBES2KeyEncKWManagerConfig struct {
	// Iterations is the PBKDF2 iteration count. A higher count raises the cost of
	// a brute-force attack on the password; a minimum of 1000 is recommended.
	// Non-positive selects DefaultPBES2Iterations.
	Iterations int
	// SaltSize is the salt length in bytes. A salt of 128 bits or more is
	// recommended. Non-positive selects DefaultPBES2SaltSize.
	SaltSize int

	// CEK is the content encryption key, encrypted under the wrap key derived from
	// Secret.
	CEK []byte
	// Secret is the password the wrap key is derived from. The recipient must know
	// it to decrypt the token.
	Secret string
}

// PBES2KeyEncKWManager implements jwe.CEKManager: it derives a wrap key from a
// password with PBES2 (PBKDF2) and wraps the content encryption key with AES Key
// Wrap.
type PBES2KeyEncKWManager struct {
	config PBES2KeyEncKWManagerConfig

	alg        jwa.Alg
	hash       crypto.Hash
	keySize    int
	iterations int
	saltSize   int
}

// NewPBES2KeyEncKWManager creates a jwe.CEKManager that derives a wrap key from a
// password with PBES2 and wraps the content encryption key with AES Key Wrap. The
// preset selects the algorithm, hash, and key size; use one of the
// PBES2KeyEncKWPreset values (for example PBES2A128KW).
//
// https://datatracker.ietf.org/doc/html/rfc7518#section-4.8
func NewPBES2KeyEncKWManager(config *PBES2KeyEncKWManagerConfig, preset PBES2KeyEncKWPreset) *PBES2KeyEncKWManager {
	iterations := config.Iterations
	if iterations <= 0 {
		iterations = DefaultPBES2Iterations
	}

	saltSize := config.SaltSize
	if saltSize <= 0 {
		saltSize = DefaultPBES2SaltSize
	}

	return &PBES2KeyEncKWManager{
		config:     *config,
		alg:        preset.Alg,
		hash:       preset.Hash,
		keySize:    preset.KeySize,
		iterations: iterations,
		saltSize:   saltSize,
	}
}

// pbes2Salt builds the PBKDF2 salt RFC 7518 §4.8.1.1 mandates: UTF8(Alg), a zero octet, then the
// Salt Input — the base64url-DECODED p2s, not the text that travels in the header.
//
// Binding the algorithm into the salt is what keeps one password reused across two PBES2 algorithms
// from deriving related wrap keys.
//
// https://datatracker.ietf.org/doc/html/rfc7518#section-4.8.1.1
func pbes2Salt(alg jwa.Alg, p2s string) ([]byte, error) {
	saltInput, err := base64.RawURLEncoding.DecodeString(p2s)
	if err != nil {
		return nil, fmt.Errorf("decode p2s: %w", err)
	}

	salt := make([]byte, 0, len(alg)+1+len(saltInput))
	salt = append(salt, alg...)
	salt = append(salt, 0)
	salt = append(salt, saltInput...)

	return salt, nil
}

func (manager *PBES2KeyEncKWManager) SetHeader(_ context.Context, header *jwa.JWH) (*jwa.JWH, error) {
	if !header.Alg.Empty() {
		return nil, fmt.Errorf("(PBES2KeyEncKWManager.SetHeader) %w: alg field already set", jwt.ErrConflictingHeader)
	}

	// A fresh salt per token widens the key space, so one password never derives the
	// same wrap key twice. It travels in the header for the recipient.
	salt := make([]byte, manager.saltSize)

	_, err := rand.Read(salt)
	if err != nil {
		return nil, fmt.Errorf("(PBES2KeyEncKWManager.SetHeader) generate salt: %w", err)
	}

	header.JWHPBES2 = jwa.JWHPBES2{
		P2S: base64.RawURLEncoding.EncodeToString(salt),
		P2C: manager.iterations,
	}
	header.Alg = manager.alg

	return header, nil
}

func (manager *PBES2KeyEncKWManager) ComputeCEK(_ context.Context, _ *jwa.JWH) ([]byte, error) {
	return manager.config.CEK, nil
}

func (manager *PBES2KeyEncKWManager) EncryptCEK(_ context.Context, header *jwa.JWH, cek []byte) ([]byte, error) {
	salt, err := pbes2Salt(header.Alg, header.P2S)
	if err != nil {
		return nil, fmt.Errorf("(PBES2KeyEncKWManager.EncryptCEK) build salt: %w", err)
	}

	wrapKey := pbkdf2.Key(
		[]byte(manager.config.Secret),
		salt,
		header.P2C,
		manager.keySize,
		manager.hash.New,
	)

	block, err := aes.NewCipher(wrapKey)
	if err != nil {
		return nil, fmt.Errorf("(PBES2KeyEncKWManager.EncryptCEK) create cipher: %w", err)
	}

	wrapped, err := internal.KeyWrap(block, cek)
	if err != nil {
		return nil, fmt.Errorf("(PBES2KeyEncKWManager.EncryptCEK) wrap key: %w", err)
	}

	return wrapped, nil
}

// DefaultMaxPBES2Iterations caps the PBKDF2 iteration count (p2c) a decoder will run when the
// config leaves MaxIterations unset. p2c is attacker-controlled in the token header, so an
// unbounded value is a CPU-exhaustion vector.
const DefaultMaxPBES2Iterations = 1_000_000

// PBES2KeyEncKWDecoderConfig holds the password used to re-derive the wrap key and
// decrypt the content encryption key.
type PBES2KeyEncKWDecoderConfig struct {
	// Secret is the password the wrap key is derived from; it must match the one
	// used to encrypt the token.
	Secret string

	// MaxIterations caps the token's p2c iteration count. Non-positive selects DefaultMaxPBES2Iterations.
	MaxIterations int
}

// PBES2KeyEncKWDecoder implements jwe.CEKDecoder: it re-derives the wrap key from
// the password and unwraps the content encryption key with AES Key Wrap.
type PBES2KeyEncKWDecoder struct {
	config PBES2KeyEncKWDecoderConfig

	alg           jwa.Alg
	hash          crypto.Hash
	keySize       int
	maxIterations int
}

// NewPBES2KeyEncKWDecoder creates a jwe.CEKDecoder that re-derives the wrap key
// from a password with PBES2 and unwraps the content encryption key with AES Key
// Wrap. The preset must match the one used to encrypt the token; use one of the
// PBES2KeyEncKWPreset values (for example PBES2A128KW).
//
// https://datatracker.ietf.org/doc/html/rfc7518#section-4.8
func NewPBES2KeyEncKWDecoder(config *PBES2KeyEncKWDecoderConfig, preset PBES2KeyEncKWPreset) *PBES2KeyEncKWDecoder {
	maxIterations := config.MaxIterations
	if maxIterations <= 0 {
		maxIterations = DefaultMaxPBES2Iterations
	}

	return &PBES2KeyEncKWDecoder{
		config:        *config,
		alg:           preset.Alg,
		hash:          preset.Hash,
		keySize:       preset.KeySize,
		maxIterations: maxIterations,
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

	// Bound the attacker-controlled p2c before PBKDF2 runs; a small token could otherwise pin a core
	// for billions of iterations.
	if header.P2C <= 0 || header.P2C > decoder.maxIterations {
		return nil, fmt.Errorf(
			"(PBES2KeyEncKWDecoder.ComputeCEK) %w: p2c %d out of range (1..%d)",
			jwt.ErrUnsupportedTokenFormat, header.P2C, decoder.maxIterations,
		)
	}

	salt, err := pbes2Salt(header.Alg, header.P2S)
	if err != nil {
		return nil, fmt.Errorf("(PBES2KeyEncKWDecoder.ComputeCEK) build salt: %w", err)
	}

	wrapKey := pbkdf2.Key(
		[]byte(decoder.config.Secret),
		salt,
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
