package jwa

// A J509 holds the X.509 certificate parameters that a JSON Web Key may use to
// bind its key to a certificate, as defined by RFC 7517.
type J509 struct {
	// X5U carries the "x5u" (X.509 URL) parameter, a URI referencing a resource
	// that holds the PEM-encoded certificate or certificate chain for the key. The
	// key in the first certificate matches the public key of the surrounding JSON
	// Web Key.
	//
	// When X5U and X5C are both set, they must describe the same certificate chain.
	//
	// https://datatracker.ietf.org/doc/html/rfc7517#section-4.6
	X5U string `json:"x5u,omitempty"`
	// X5C carries the "x5c" (X.509 certificate chain) parameter, a chain of one or
	// more PKIX certificates encoded as base64 (not base64url) DER values. The
	// first certificate holds the key and matches the public key of the
	// surrounding JSON Web Key; each subsequent certificate certifies the one
	// before it.
	//
	// When X5U and X5C are both set, they must describe the same certificate chain.
	//
	// https://datatracker.ietf.org/doc/html/rfc7517#section-4.7
	X5C []string `json:"x5c,omitempty"`
	// X5T carries the "x5t" (X.509 certificate SHA-1 thumbprint) parameter, the
	// base64url-encoded SHA-1 digest of the DER-encoded certificate.
	//
	// https://datatracker.ietf.org/doc/html/rfc7517#section-4.8
	X5T string `json:"x5t,omitempty"`
	// X5TS256 carries the "x5t#S256" (X.509 certificate SHA-256 thumbprint)
	// parameter, the base64url-encoded SHA-256 digest of the DER-encoded
	// certificate.
	//
	// https://datatracker.ietf.org/doc/html/rfc7517#section-4.9
	X5TS256 string `json:"x5t#S256,omitempty"` //nolint:tagliatelle
}

// Equal reports whether two J509 values carry identical certificate parameters.
// A nil argument is never equal.
func (payload *J509) Equal(other *J509) bool {
	if other == nil {
		return false
	}

	if payload.X5U != other.X5U {
		return false
	}

	if len(payload.X5C) != len(other.X5C) {
		return false
	}

	for i, v := range payload.X5C {
		if v != other.X5C[i] {
			return false
		}
	}

	if payload.X5T != other.X5T {
		return false
	}

	if payload.X5TS256 != other.X5TS256 {
		return false
	}

	return true
}
