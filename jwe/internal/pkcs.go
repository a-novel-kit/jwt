package internal

import (
	"bytes"
)

// https://stackoverflow.com/a/41595640/9021186

// PKCS7Padding pads the given ciphertext to the nearest multiple of the block size.
func PKCS7Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

// PKCS7UnPadding removes the padding from the given ciphertext.
func PKCS7UnPadding(plaintText []byte) []byte {
	length := len(plaintText)
	unpadding := int(plaintText[length-1])
	return plaintText[:(length - unpadding)]
}
