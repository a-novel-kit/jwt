// Package jwk generates and consumes JSON Web Keys (RFC 7517) for the jwt toolkit.
//
// Each supported algorithm family exposes a matching pair of helpers. A Generate function mints
// fresh key material and returns it as a typed [Key], and a Consume function parses an external JSON
// Web Key back into that typed key. A [Source] fetches and caches raw keys, so signers and verifiers
// can look them up by ID and follow key rotation.
package jwk
