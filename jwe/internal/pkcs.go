package internal

import (
	"bytes"
)

// PKCS7Padding appends PKCS#7 padding to bring ciphertext up to a whole multiple of blockSize. A
// full block is added when the input is already aligned, so the padding is always removable.
func PKCS7Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)

	return append(ciphertext, padtext...)
}

// PKCS7UnPadding strips the PKCS#7 padding that PKCS7Padding added, returning the original plaintext.
func PKCS7UnPadding(plaintText []byte) []byte {
	length := len(plaintText)
	unpadding := int(plaintText[length-1])

	return plaintText[:(length - unpadding)]
}
