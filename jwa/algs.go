package jwa

type Alg string

func (alg Alg) String() string {
	return string(alg)
}

const None Alg = "none"

func (alg Alg) Empty() bool {
	return alg == "" || alg == None
}

// JWS algorithms.
// https://datatracker.ietf.org/doc/html/rfc7518#section-3.1
const (
	// HS256 signing algorithm.
	//
	// HMAC using SHA-256.
	HS256 Alg = "HS256"
	// HS384 signing algorithm.
	//
	// HMAC using SHA-384.
	HS384 Alg = "HS384"
	// HS512 signing algorithm.
	//
	// HMAC using SHA-512.
	HS512 Alg = "HS512"

	// RS256 signing algorithm.
	//
	// RSASSA-PKCS1-v1_5 using SHA-256.
	RS256 Alg = "RS256"
	// RS384 signing algorithm.
	//
	// RSASSA-PKCS1-v1_5 using SHA-384.
	RS384 Alg = "RS384"
	// RS512 signing algorithm.
	//
	// RSASSA-PKCS1-v1_5 using SHA-512.
	RS512 Alg = "RS512"

	// ES256 signing algorithm.
	//
	// ECDSA using P-256 and SHA-256.
	ES256 Alg = "ES256"
	// ES384 signing algorithm.
	//
	// ECDSA using P-384 and SHA-384.
	ES384 Alg = "ES384"
	// ES512 signing algorithm.
	//
	// ECDSA using P-521 and SHA-512.
	ES512 Alg = "ES512"

	// PS256 signing algorithm.
	//
	// RSASSA-PSS using SHA-256 and MGF1 with SHA-256.
	PS256 Alg = "PS256"
	// PS384 signing algorithm.
	//
	// RSASSA-PSS using SHA-384 and MGF1 with SHA-384.
	PS384 Alg = "PS384"
	// PS512 signing algorithm.
	//
	// RSASSA-PSS using SHA-512 and MGF1 with SHA-512.
	PS512 Alg = "PS512"

	// EdDSA signing algorithm.
	EdDSA Alg = "EdDSA"
)

// JWE key management algorithms.
// https://datatracker.ietf.org/doc/html/rfc7518#section-4.1
const (
	// RSAOAEP key management algorithm.
	//
	// RSAES OAEP using default parameters.
	RSAOAEP Alg = "RSA-OAEP"
	// RSAOAEP256 key management algorithm.
	//
	// RSAES OAEP using SHA-256 and MGF1 with SHA-256.
	RSAOAEP256 Alg = "RSA-OAEP-256"

	// A128KW key management algorithm.
	//
	// AES Key Wrap with default initial value using 128-bit key.
	A128KW Alg = "A128KW"
	// A192KW key management algorithm.
	//
	// AES Key Wrap with default initial value using 192-bit key.
	A192KW Alg = "A192KW"
	// A256KW key management algorithm.
	//
	// AES Key Wrap with default initial value using 256-bit key.
	A256KW Alg = "A256KW"

	// DIR key management algorithm.
	//
	// Direct use of a shared symmetric key as the CEK.
	DIR Alg = "dir"

	// ECDHES key management algorithm.
	//
	// Elliptic Curve Diffie-Hellman Ephemeral Static key agreement using Concat KDF.
	ECDHES Alg = "ECDH-ES"

	// ECDHESA128KW key management algorithm.
	//
	// ECDH-ES using Concat KDF and CEK wrapped with A128KW.
	ECDHESA128KW Alg = "ECDH-ES+A128KW"
	// ECDHESA192KW key management algorithm.
	//
	// ECDH-ES using Concat KDF and CEK wrapped with A192KW.
	ECDHESA192KW Alg = "ECDH-ES+A192KW"
	// ECDHESA256KW key management algorithm.
	//
	// ECDH-ES using Concat KDF and CEK wrapped with A256KW.
	ECDHESA256KW Alg = "ECDH-ES+A256KW"

	// A128GCMKW key management algorithm.
	//
	// Key wrapping with AES GCM using 128-bit key.
	A128GCMKW Alg = "A128GCMKW"
	// A192GCMKW key management algorithm.
	//
	// Key wrapping with AES GCM using 192-bit key.
	A192GCMKW Alg = "A192GCMKW"
	// A256GCMKW key management algorithm.
	//
	// Key wrapping with AES GCM using 256-bit key.
	A256GCMKW Alg = "A256GCMKW"

	// PBES2HS256A128KW key management algorithm.
	//
	// PBES2 with HMAC SHA-256 and A128KW key wrapping.
	PBES2HS256A128KW Alg = "PBES2-HS256+A128KW"
	// PBES2HS384A192KW key management algorithm.
	//
	// PBES2 with HMAC SHA-384 and A192KW key wrapping.
	PBES2HS384A192KW Alg = "PBES2-HS384+A192KW"
	// PBES2HS512A256KW key management algorithm.
	//
	// PBES2 with HMAC SHA-512 and A256KW key wrapping.
	PBES2HS512A256KW Alg = "PBES2-HS512+A256KW"
)
