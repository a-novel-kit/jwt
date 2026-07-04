package jws

import "github.com/a-novel-kit/jwt/v2"

// Compile-time checks that every signer and verifier satisfies the plugin contract it is wired in
// as. A signature drift is then caught at build time rather than at a call site (or, worse, only
// once a caller tries to use it — as happened for a CEK manager before these guards existed).
var (
	_ jwt.ProducerPlugin = (*HMACSigner)(nil)
	_ jwt.ProducerPlugin = (*SourceHMACSigner)(nil)
	_ jwt.ProducerPlugin = (*RSASigner)(nil)
	_ jwt.ProducerPlugin = (*SourcedRSASigner)(nil)
	_ jwt.ProducerPlugin = (*ECDSASigner)(nil)
	_ jwt.ProducerPlugin = (*SourcedECDSASigner)(nil)
	_ jwt.ProducerPlugin = (*ED25519Signer)(nil)
	_ jwt.ProducerPlugin = (*SourcedED25519Signer)(nil)
	_ jwt.ProducerPlugin = (*RSAPSSSigner)(nil)
	_ jwt.ProducerPlugin = (*SourcedRSAPSSSigner)(nil)

	_ jwt.RecipientPlugin = (*HMACVerifier)(nil)
	_ jwt.RecipientPlugin = (*SourceHMACVerifier)(nil)
	_ jwt.RecipientPlugin = (*RSAVerifier)(nil)
	_ jwt.RecipientPlugin = (*SourcedRSAVerifier)(nil)
	_ jwt.RecipientPlugin = (*ECDSAVerifier)(nil)
	_ jwt.RecipientPlugin = (*SourcedECDSAVerifier)(nil)
	_ jwt.RecipientPlugin = (*ED25519Verifier)(nil)
	_ jwt.RecipientPlugin = (*SourcedED25519Verifier)(nil)
	_ jwt.RecipientPlugin = (*RSAPSSVerifier)(nil)
	_ jwt.RecipientPlugin = (*SourcedRSAPSSVerifier)(nil)
	_ jwt.RecipientPlugin = (*InsecureVerifier)(nil)
)
