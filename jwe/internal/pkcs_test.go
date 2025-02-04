package internal_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/a-novel-kit/jwt/jwe/internal"
)

func TestPKCS7Padding(t *testing.T) {
	testCases := []struct {
		name string

		ciphertext []byte
		blockSize  int

		expected []byte
	}{
		{
			name: "padding",

			ciphertext: []byte("test"),
			blockSize:  8,

			expected: []byte("test\x04\x04\x04\x04"),
		},
		{
			name: "no padding",

			ciphertext: []byte("test"),
			blockSize:  4,

			// There is always a padding.
			expected: []byte("test\x04\x04\x04\x04"),
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			result := internal.PKCS7Padding(testCase.ciphertext, testCase.blockSize)
			require.Equal(t, testCase.expected, result)
		})
	}
}

func TestPKCS7UnPadding(t *testing.T) {
	testCases := []struct {
		name string

		plaintText []byte

		expected []byte
	}{
		{
			name: "padding",

			plaintText: []byte("test\x04\x04\x04\x04"),

			expected: []byte("test"),
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			result := internal.PKCS7UnPadding(testCase.plaintText)
			require.Equal(t, testCase.expected, result)
		})
	}
}
