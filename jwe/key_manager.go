package jwe

import (
	"context"

	"github.com/a-novel-kit/jwt/v2/jwa"
)

// CEKManager supplies the content encryption key (CEK) to an encryption plugin and
// decides how it reaches the recipient. Implementations vary by key-management scheme:
// direct shared key, key wrapping, or key agreement.
//
// Key management runs per token. ComputeCEK and EncryptCEK may record per-token
// parameters in the header, such as an ephemeral key or a wrapping IV, so an
// encryption plugin encodes the protected header only after both have run.
type CEKManager interface {
	// SetHeader adds the header fields known before the token is encrypted, such as
	// the algorithm.
	SetHeader(ctx context.Context, header *jwa.JWH) (modifiedHeader *jwa.JWH, err error)
	// ComputeCEK returns the key used to encrypt the token payload.
	ComputeCEK(ctx context.Context, header *jwa.JWH) (cek []byte, err error)
	// EncryptCEK returns the CEK in the form embedded in the token, empty when the
	// recipient derives the key itself and nothing is transmitted.
	EncryptCEK(ctx context.Context, header *jwa.JWH, cek []byte) (encrypted []byte, err error)
}

// CEKDecoder is the decryption counterpart of CEKManager: it recovers the content
// encryption key from the header and the transmitted key material.
type CEKDecoder interface {
	// ComputeCEK returns the key used to decrypt the payload, given the encrypted key
	// carried in the token (empty when none was transmitted).
	ComputeCEK(ctx context.Context, header *jwa.JWH, encKey []byte) (cek []byte, err error)
}
