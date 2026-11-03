package internal

import (
	"errors"
	"fmt"
)

// PKCS7Padding returns plainText followed by PKCS#7 padding, up to a whole multiple of blockSize. A
// full block is added when the input is already aligned, so the padding is always removable. The
// result is a new slice: plainText is left untouched.
func PKCS7Padding(plainText []byte, blockSize int) []byte {
	padding := blockSize - len(plainText)%blockSize

	padded := make([]byte, len(plainText)+padding)
	copy(padded, plainText)

	for i := len(plainText); i < len(padded); i++ {
		padded[i] = byte(padding)
	}

	return padded
}

// PKCS7UnPadding strips the PKCS#7 padding that PKCS7Padding added, returning the original
// plaintext. It validates the pad length and every pad byte, returning an error for an
// out-of-range or inconsistent length.
func PKCS7UnPadding(plainText []byte) ([]byte, error) {
	length := len(plainText)
	if length == 0 {
		return nil, errors.New("pkcs7: empty input")
	}

	unpadding := int(plainText[length-1])
	if unpadding == 0 || unpadding > length {
		return nil, fmt.Errorf("pkcs7: invalid padding length %d", unpadding)
	}

	for _, b := range plainText[length-unpadding:] {
		if int(b) != unpadding {
			return nil, errors.New("pkcs7: inconsistent padding")
		}
	}

	return plainText[:length-unpadding], nil
}
