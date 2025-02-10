package jwe_test

import (
	"context"
	"errors"

	"github.com/a-novel-kit/jwt/jwa"
)

var errFoo = errors.New("foo error")

type fakeCEKManager struct {
	cek       []byte
	encrypted []byte
}

func (f *fakeCEKManager) SetHeader(_ context.Context, header *jwa.JWH) (*jwa.JWH, error) {
	return header, nil
}

func (f *fakeCEKManager) ComputeCEK(_ context.Context, _ *jwa.JWH) ([]byte, error) {
	return f.cek, nil
}

func (f *fakeCEKManager) EncryptCEK(_ context.Context, _ *jwa.JWH, _ []byte) ([]byte, error) {
	return f.encrypted, nil
}

type fakeCEKDecoder struct {
	cek       []byte
	encrypted []byte
}

func (f *fakeCEKDecoder) ComputeCEK(_ context.Context, _ *jwa.JWH, encKey []byte) ([]byte, error) {
	if string(encKey) != string(f.encrypted) {
		return nil, errFoo
	}

	return f.cek, nil
}
