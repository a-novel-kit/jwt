package jwa

// KTY is used to determine the type of key in a JWA protocol.
type KTY string

const (
	// KTYOct Parameters for Symmetric Keys.
	//
	// https://datatracker.ietf.org/doc/html/rfc7518#section-6.4
	//
	// When the JWKCommon "kty" member value is "oct" (octet sequence), the member
	// "k" (see Section 6.4.1) is used to represent a symmetric key (or
	// another key whose value is a single octet sequence). An "alg" member
	// SHOULD also be present to identify the algorithm intended to be used
	// with the key, unless the application uses another means or convention
	// to determine the algorithm used.
	KTYOct KTY = "oct"
	// KTYRSA Parameters for RSA Public Keys.
	//
	// https://datatracker.ietf.org/doc/html/rfc7518#section-6.3
	//
	// JWKs can represent RSA [RFC3447] keys. In this case, the "kty"
	// member value is "RSA". The semantics of the parameters defined below
	// are the same as those defined in Sections 3.1 and 3.2 of RFC 3447.
	KTYRSA KTY = "RSA"
	// KTYEC Parameters for Elliptic Curve Public Keys.
	//
	// https://datatracker.ietf.org/doc/html/rfc7518#section-6.2
	//
	// JWKs can represent Elliptic Curve [DSS] keys. In this case, the
	// "kty" member value is "EC".
	KTYEC KTY = "EC"

	// KTYOKP Parameters for Octet Key Pair.
	//
	// https://datatracker.ietf.org/doc/html/rfc8037#section-2
	//
	// A new key type (kty) value "OKP" (Octet Key Pair) is defined for
	// public key algorithms that use octet strings as private and public
	// keys.
	KTYOKP KTY = "OKP"
)
