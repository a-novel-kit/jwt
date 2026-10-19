// Package jwe encrypts and decrypts JSON Web Encryption tokens (RFC 7516) as producer and recipient
// plugins.
//
// The AES-CBC-HMAC and AES-GCM plugins encrypt the payload under a content encryption key. A
// [CEKManager] supplies that key at encryption and a [CEKDecoder] recovers it at decryption. The
// jwek package implements both for each key management algorithm. The HPKE plugins encrypt the
// payload directly to the recipient's key and need neither.
package jwe
