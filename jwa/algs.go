// Package jwa defines the JOSE data types shared across the jwt toolkit: the
// algorithm, key, header, and claim structures of the JSON Web Signature,
// Encryption, Key, and Token specifications (RFC 7515-7519, RFC 8037, RFC 9864,
// RFC 9964).
//
// The package holds only the wire types and their registered constant values.
// It carries no cryptographic logic; the serialization and signing packages
// build on these types.
package jwa

// Alg identifies a cryptographic algorithm named in a JOSE header's "alg"
// parameter, covering both JWS signing and JWE key management.
type Alg string

func (alg Alg) String() string {
	return string(alg)
}

// None is the "alg" value of an unsecured token, one carrying no signature.
const None Alg = "none"

// Empty reports whether no signing algorithm is applied: the value is unset or
// explicitly None.
func (alg Alg) Empty() bool {
	return alg == "" || alg == None
}

// JWS signing algorithms registered by RFC 7518.
// https://datatracker.ietf.org/doc/html/rfc7518#section-3.1
const (
	// HS256 signs with HMAC using SHA-256.
	HS256 Alg = "HS256"
	// HS384 signs with HMAC using SHA-384.
	HS384 Alg = "HS384"
	// HS512 signs with HMAC using SHA-512.
	HS512 Alg = "HS512"

	// RS256 signs with RSASSA-PKCS1-v1_5 using SHA-256.
	RS256 Alg = "RS256"
	// RS384 signs with RSASSA-PKCS1-v1_5 using SHA-384.
	RS384 Alg = "RS384"
	// RS512 signs with RSASSA-PKCS1-v1_5 using SHA-512.
	RS512 Alg = "RS512"

	// ES256 signs with ECDSA using P-256 and SHA-256.
	ES256 Alg = "ES256"
	// ES384 signs with ECDSA using P-384 and SHA-384.
	ES384 Alg = "ES384"
	// ES512 signs with ECDSA using P-521 and SHA-512.
	ES512 Alg = "ES512"

	// PS256 signs with RSASSA-PSS using SHA-256 and MGF1 with SHA-256.
	PS256 Alg = "PS256"
	// PS384 signs with RSASSA-PSS using SHA-384 and MGF1 with SHA-384.
	PS384 Alg = "PS384"
	// PS512 signs with RSASSA-PSS using SHA-512 and MGF1 with SHA-512.
	PS512 Alg = "PS512"

	// EdDSA signs with the Edwards-curve Digital Signature Algorithm, on the curve
	// the key names.
	//
	// Deprecated: RFC 9864 replaces this polymorphic identifier with the
	// fully-specified [Ed25519]. Recipients still accept it, so tokens and keys
	// that carry it keep verifying.
	EdDSA Alg = "EdDSA"
)

// JWS signing algorithms registered by RFC 9864, each bound to one curve.
// https://datatracker.ietf.org/doc/html/rfc9864#section-2.2
const (
	// Ed25519 signs with EdDSA on the Ed25519 curve.
	Ed25519 Alg = "Ed25519"
)

// JWS signing algorithms registered by RFC 9964: the post-quantum ML-DSA scheme of
// FIPS 204, at three security levels.
// https://datatracker.ietf.org/doc/html/rfc9964#section-5
const (
	// MLDSA44 signs with ML-DSA-44, NIST security category 2.
	MLDSA44 Alg = "ML-DSA-44"
	// MLDSA65 signs with ML-DSA-65, NIST security category 3.
	MLDSA65 Alg = "ML-DSA-65"
	// MLDSA87 signs with ML-DSA-87, NIST security category 5.
	MLDSA87 Alg = "ML-DSA-87"
)

// JWE key management algorithms registered by RFC 7518.
// https://datatracker.ietf.org/doc/html/rfc7518#section-4.1
const (
	// RSAOAEP wraps the content encryption key with RSAES OAEP using default parameters.
	RSAOAEP Alg = "RSA-OAEP"
	// RSAOAEP256 wraps the content encryption key with RSAES OAEP using SHA-256 and MGF1 with SHA-256.
	RSAOAEP256 Alg = "RSA-OAEP-256"

	// A128KW wraps the content encryption key with AES Key Wrap using a 128-bit key.
	A128KW Alg = "A128KW"
	// A192KW wraps the content encryption key with AES Key Wrap using a 192-bit key.
	A192KW Alg = "A192KW"
	// A256KW wraps the content encryption key with AES Key Wrap using a 256-bit key.
	A256KW Alg = "A256KW"

	// DIR uses a shared symmetric key directly as the content encryption key.
	DIR Alg = "dir"

	// ECDHES derives the content encryption key with Elliptic Curve Diffie-Hellman
	// Ephemeral Static key agreement and Concat KDF.
	ECDHES Alg = "ECDH-ES"

	// ECDHESA128KW derives a key with ECDH-ES and Concat KDF, then wraps the CEK with A128KW.
	ECDHESA128KW Alg = "ECDH-ES+A128KW"
	// ECDHESA192KW derives a key with ECDH-ES and Concat KDF, then wraps the CEK with A192KW.
	ECDHESA192KW Alg = "ECDH-ES+A192KW"
	// ECDHESA256KW derives a key with ECDH-ES and Concat KDF, then wraps the CEK with A256KW.
	ECDHESA256KW Alg = "ECDH-ES+A256KW"

	// A128GCMKW wraps the content encryption key with AES GCM using a 128-bit key.
	A128GCMKW Alg = "A128GCMKW"
	// A192GCMKW wraps the content encryption key with AES GCM using a 192-bit key.
	A192GCMKW Alg = "A192GCMKW"
	// A256GCMKW wraps the content encryption key with AES GCM using a 256-bit key.
	A256GCMKW Alg = "A256GCMKW"

	// PBES2HS256A128KW derives a key from a password with PBES2 (HMAC SHA-256) and wraps the CEK with A128KW.
	PBES2HS256A128KW Alg = "PBES2-HS256+A128KW"
	// PBES2HS384A192KW derives a key from a password with PBES2 (HMAC SHA-384) and wraps the CEK with A192KW.
	PBES2HS384A192KW Alg = "PBES2-HS384+A192KW"
	// PBES2HS512A256KW derives a key from a password with PBES2 (HMAC SHA-512) and wraps the CEK with A256KW.
	PBES2HS512A256KW Alg = "PBES2-HS512+A256KW"
)

// JWE algorithms using Hybrid Public Key Encryption (HPKE), registered by IANA from
// draft-ietf-jose-hpke-encrypt. Each fixes a key encapsulation mechanism, a key derivation function,
// and an AEAD. The X448 suites are not listed: the standard library does not implement X448.
// https://datatracker.ietf.org/doc/draft-ietf-jose-hpke-encrypt/
const (
	// HPKE0 encrypts the payload directly with DHKEM(P-256), HKDF-SHA256, and AES-128-GCM.
	HPKE0 Alg = "HPKE-0"
	// HPKE1 encrypts the payload directly with DHKEM(P-384), HKDF-SHA384, and AES-256-GCM.
	HPKE1 Alg = "HPKE-1"
	// HPKE2 encrypts the payload directly with DHKEM(P-521), HKDF-SHA512, and AES-256-GCM.
	HPKE2 Alg = "HPKE-2"
	// HPKE3 encrypts the payload directly with DHKEM(X25519), HKDF-SHA256, and AES-128-GCM.
	HPKE3 Alg = "HPKE-3"
	// HPKE4 encrypts the payload directly with DHKEM(X25519), HKDF-SHA256, and ChaCha20-Poly1305.
	HPKE4 Alg = "HPKE-4"
	// HPKE7 encrypts the payload directly with DHKEM(P-256), HKDF-SHA256, and AES-256-GCM.
	HPKE7 Alg = "HPKE-7"

	// HPKE0KE encrypts the CEK with DHKEM(P-256), HKDF-SHA256, and AES-128-GCM.
	HPKE0KE Alg = "HPKE-0-KE"
	// HPKE1KE encrypts the CEK with DHKEM(P-384), HKDF-SHA384, and AES-256-GCM.
	HPKE1KE Alg = "HPKE-1-KE"
	// HPKE2KE encrypts the CEK with DHKEM(P-521), HKDF-SHA512, and AES-256-GCM.
	HPKE2KE Alg = "HPKE-2-KE"
	// HPKE3KE encrypts the CEK with DHKEM(X25519), HKDF-SHA256, and AES-128-GCM.
	HPKE3KE Alg = "HPKE-3-KE"
	// HPKE7KE encrypts the CEK with DHKEM(P-256), HKDF-SHA256, and AES-256-GCM.
	HPKE7KE Alg = "HPKE-7-KE"
)
