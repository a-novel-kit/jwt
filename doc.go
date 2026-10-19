// Package jwt issues and consumes JSON Web Tokens (RFC 7519) in compact serialization.
//
// A [Producer] builds a token's header and claims, then runs producer plugins that sign or encrypt
// it. A [Recipient] decodes a token's header, runs recipient plugins until one verifies or decrypts
// the token, then deserializes its claims. The jws and jwe packages provide those plugins, and the
// jwk package the keys they use.
package jwt
