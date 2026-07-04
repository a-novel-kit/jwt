package jwa

// Enc identifies the content encryption algorithm named in a JWE "enc" header.
// Each value is an AEAD algorithm applied to the plaintext to produce the
// ciphertext and authentication tag.
type Enc string

func (enc Enc) String() string {
	return string(enc)
}

// Content encryption algorithms registered by RFC 7518.
// https://datatracker.ietf.org/doc/html/rfc7518#section-5.1
const (
	// A128CBC encrypts with AES-128-CBC and authenticates with HMAC SHA-256.
	A128CBC Enc = "A128CBC-HS256"
	// A192CBC encrypts with AES-192-CBC and authenticates with HMAC SHA-384.
	A192CBC Enc = "A192CBC-HS384"
	// A256CBC encrypts with AES-256-CBC and authenticates with HMAC SHA-512.
	A256CBC Enc = "A256CBC-HS512"

	// A128GCM encrypts and authenticates with AES-128-GCM.
	A128GCM Enc = "A128GCM"
	// A192GCM encrypts and authenticates with AES-192-GCM.
	A192GCM Enc = "A192GCM"
	// A256GCM encrypts and authenticates with AES-256-GCM.
	A256GCM Enc = "A256GCM"
)
