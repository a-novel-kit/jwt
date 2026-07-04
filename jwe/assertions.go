package jwe

import "github.com/a-novel-kit/jwt/v2"

// Compile-time checks that the content-encryption plugins satisfy the producer/recipient contracts.
var (
	_ jwt.ProducerPlugin = (*AESCBCEncryption)(nil)
	_ jwt.ProducerPlugin = (*AESGCMEncryption)(nil)

	_ jwt.RecipientPlugin = (*AESCBCDecryption)(nil)
	_ jwt.RecipientPlugin = (*AESGCMDecryption)(nil)
)
