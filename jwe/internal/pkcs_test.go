package internal_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/a-novel-kit/jwt/jwe/internal"
)

func TestPKCS7Padding(t *testing.T) {
	t.Parallel()

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
			t.Parallel()

			result := internal.PKCS7Padding(testCase.ciphertext, testCase.blockSize)
			require.Equal(t, testCase.expected, result)
		})
	}
}

func TestPKCS7UnPadding(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name string

		plaintText []byte

		expected  []byte
		expectErr bool
	}{
		{
			name: "padding",

			plaintText: []byte("test\x04\x04\x04\x04"),

			expected: []byte("test"),
		},
		{
			name: "empty",

			plaintText: []byte{},

			expectErr: true,
		},
		{
			name: "padding too large",

			plaintText: []byte("test\xff"),

			expectErr: true,
		},
		{
			name: "inconsistent padding",

			plaintText: []byte("test\x02\x04"),

			expectErr: true,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			result, err := internal.PKCS7UnPadding(testCase.plaintText)

			if testCase.expectErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, testCase.expected, result)
			}
		})
	}
}
