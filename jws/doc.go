// Package jws signs and verifies JSON Web Signatures (RFC 7515) as producer and recipient plugins.
//
// Each algorithm family has a signer and a verifier built from a key and a preset. Their sourced
// variants resolve keys from a [jwk.Source] at each call instead, so they follow key rotation.
package jws
