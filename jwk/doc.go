// Package jwk generates and consumes JSON Web Keys (RFC 7517) for the jwt toolkit.
//
// Each supported algorithm family exposes a matching pair of helpers. A Generate function mints
// fresh key material and returns it as a typed [Key], and a Consume function parses an external JSON
// Web Key back into that typed key. A [Source] fetches and caches raw keys, so signers and verifiers
// can look them up by ID and follow key rotation.
//
// A Generate function sets both "use" and "key_ops" on every key, and a Consume function refuses a
// key that lacks either, although RFC 7517 §4.3 says the two SHOULD NOT be used together. The two
// halves of a signature or RSA key pair share one key ID, so "key_ops" tells them apart, and the
// sourced signers and verifiers of package jws pick their key by it. "use" serves JWK Set
// consumers that select a key by its purpose (RFC 7517 §4.2). Both members always agree, as §4.3
// requires when both appear.
package jwk
