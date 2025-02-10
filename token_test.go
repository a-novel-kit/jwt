package jwt_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/a-novel-kit/jwt"
)

func TestRawToken(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name string

		value string

		expect *jwt.RawToken
	}{
		{
			name:   "Success",
			value:  "header.payload",
			expect: &jwt.RawToken{Header: "header", Payload: "payload"},
		},
		{
			name:  "Reject",
			value: "header.payload.signature",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			token, err := jwt.DecodeToken(testCase.value, &jwt.RawTokenDecoder{})

			if testCase.expect == nil {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, testCase.expect, token)
				require.Equal(t, testCase.value, token.String())
			}
		})
	}
}

func TestSignedToken(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name string

		value string

		expect *jwt.SignedToken
	}{
		{
			name:   "Success",
			value:  "header.payload.signature",
			expect: &jwt.SignedToken{Header: "header", Payload: "payload", Signature: "signature"},
		},
		{
			name:  "Reject",
			value: "header.payload",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			token, err := jwt.DecodeToken(testCase.value, &jwt.SignedTokenDecoder{})

			if testCase.expect == nil {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, testCase.expect, token)
				require.Equal(t, testCase.value, token.String())
			}
		})
	}
}

func TestEncryptedToken(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name string

		value string

		expect *jwt.EncryptedToken
	}{
		{
			name:   "Success",
			value:  "header.enc.iv.cipherText.tag",
			expect: &jwt.EncryptedToken{Header: "header", EncKey: "enc", IV: "iv", CipherText: "cipherText", Tag: "tag"},
		},
		{
			name:  "Reject",
			value: "header.payload",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			token, err := jwt.DecodeToken(testCase.value, &jwt.EncryptedTokenDecoder{})

			if testCase.expect == nil {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, testCase.expect, token)
				require.Equal(t, testCase.value, token.String())
			}
		})
	}
}
