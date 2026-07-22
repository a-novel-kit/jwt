package internal

import (
	"bytes"
	"errors"
	"fmt"
)

// PKCS7Padding appends PKCS#7 padding to bring ciphertext up to a whole multiple of blockSize. A
// full block is added when the input is already aligned, so the padding is always removable.
func PKCS7Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)

	return append(ciphertext, padtext...)
}

// PKCS7UnPadding strips the PKCS#7 padding that PKCS7Padding added, returning the original
// plaintext. It validates the pad length and every pad byte, returning an error for an
// out-of-range or inconsistent length.
func PKCS7UnPadding(plaintText []byte) ([]byte, error) {
	length := len(plaintText)
	if length == 0 {
		return nil, errors.New("pkcs7: empty input")
	}

	unpadding := int(plaintText[length-1])
	if unpadding == 0 || unpadding > length {
		return nil, fmt.Errorf("pkcs7: invalid padding length %d", unpadding)
	}

	for _, b := range plaintText[length-unpadding:] {
		if int(b) != unpadding {
			return nil, errors.New("pkcs7: inconsistent padding")
		}
	}

	return plaintText[:length-unpadding], nil
}
