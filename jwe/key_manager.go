package jwe

import (
	"context"

	"github.com/a-novel-kit/jwt/jwa"
)

type CEKManager interface {
	SetHeader(ctx context.Context, header *jwa.JWH) (modifiedHeader *jwa.JWH, err error)
	ComputeCEK(ctx context.Context, header *jwa.JWH) (cek []byte, err error)
	EncryptCEK(ctx context.Context, header *jwa.JWH, cek []byte) (encrypted []byte, err error)
}

type CEKDecoder interface {
	ComputeCEK(ctx context.Context, header *jwa.JWH, encKey []byte) (cek []byte, err error)
}
