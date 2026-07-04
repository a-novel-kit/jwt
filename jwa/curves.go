package jwa

// Curve names for Octet Key Pair (OKP) keys.
// https://datatracker.ietf.org/doc/html/rfc8037#section-3
const (
	// CrvX25519 is the curve used for ECDH-ES key agreement.
	CrvX25519 = "X25519"
	// CrvEd25519 is the curve used for EdDSA signatures.
	CrvEd25519 = "Ed25519"
)
