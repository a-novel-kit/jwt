package jwa

// KTY is the "kty" (key type) parameter of a JWK. It names the cryptographic
// algorithm family the key belongs to.
type KTY string

func (k KTY) String() string { return string(k) }

const (
	// KTYOct is a symmetric key, held as a single octet sequence.
	// https://datatracker.ietf.org/doc/html/rfc7518#section-6.4
	KTYOct KTY = "oct"
	// KTYRSA is an RSA key.
	// https://datatracker.ietf.org/doc/html/rfc7518#section-6.3
	KTYRSA KTY = "RSA"
	// KTYEC is an elliptic curve key.
	// https://datatracker.ietf.org/doc/html/rfc7518#section-6.2
	KTYEC KTY = "EC"

	// KTYOKP is an Octet Key Pair, used by algorithms that key on octet strings
	// such as Ed25519 and X25519.
	// https://datatracker.ietf.org/doc/html/rfc8037#section-2
	KTYOKP KTY = "OKP"
)
