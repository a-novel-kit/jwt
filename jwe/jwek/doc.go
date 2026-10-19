// Package jwek implements the JWE key management algorithms (RFC 7518 §4) as [jwe.CEKManager] and
// [jwe.CEKDecoder] pairs. Each pair decides how a token's content encryption key reaches the
// recipient: used directly, wrapped under a shared or password-derived key, agreed through ECDH-ES,
// or encrypted to the recipient's public key.
package jwek
