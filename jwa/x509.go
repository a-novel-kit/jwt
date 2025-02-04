package jwa

// J509 represents x509 certificate information in a JSON Web Algorithm format.
type J509 struct {
	// X5U represents the "x5u" (X.509 URL) parameter in a JSON web key.
	//
	// If both X5U and X5C are set, their content must be semantically consistent.
	//
	// https://datatracker.ietf.org/doc/html/rfc7517#section-4.6
	//
	// The "x5u" (X.509 URL) parameter is a URI [RFC3986] that refers to a
	// resource for an X.509 public key certificate or certificate chain
	// [RFC5280]. The identified resource MUST provide a representation of
	// the certificate or certificate chain that conforms to RFC 5280
	// [RFC5280] in PEM-encoded form, with each certificate delimited as
	// specified in Section 6.1 of RFC 4945 [RFC4945]. The key in the first
	// certificate MUST match the public key represented by other members of
	// the JWKCommon. The protocol used to acquire the resource MUST provide
	// integrity protection; an HTTP GET request to retrieve the certificate
	// MUST use TLS [RFC2818] [RFC5246]; the identity of the server MUST be
	// validated, as per Section 6 of RFC 6125 [RFC6125]. Use of this
	// member is OPTIONAL.
	//
	// While there is no requirement that optional JWKCommon members providing key
	// usage, algorithm, or other information be present when the "x5u"
	// member is used, doing so may improve interoperability for
	// applications that do not handle PKIX certificates [RFC5280]. If
	// other members are present, the contents of those members MUST be
	// semantically consistent with the related fields in the first
	// certificate. For instance, if the "use" member is present, then it
	// MUST correspond to the usage that is specified in the certificate,
	// when it includes this information. Similarly, if the "alg" member is
	// present, it MUST correspond to the algorithm specified in the
	// certificate.
	X5U string `json:"x5u,omitempty"`
	// X5C represents the "x5c" (X.509 certificate chain) parameter in a JSON web key.
	//
	// If both X5U and X5C are set, their content must be semantically consistent.
	//
	// https://datatracker.ietf.org/doc/html/rfc7517#section-4.7
	//
	// The "x5c" (X.509 certificate chain) parameter contains a chain of one
	// or more PKIX certificates [RFC5280]. The certificate chain is
	// represented as a JSON array of certificate value strings. Each
	// string in the array is a base64-encoded (Section 4 of [RFC4648] --
	// not base64url-encoded) DER [ITU.X690.1994] PKIX certificate value.
	// The PKIX certificate containing the key value MUST be the first
	// certificate. This MAY be followed by additional certificates, with
	// each subsequent certificate being the one used to certify the
	// previous one. The key in the first certificate MUST match the public
	// key represented by other members of the JWKCommon. Use of this member is
	// OPTIONAL.
	//
	// As with the "x5u" member, optional JWKCommon members providing key usage,
	// algorithm, or other information MAY also be present when the "x5c"
	// member is used. If other members are present, the contents of those
	// members MUST be semantically consistent with the related fields in
	// the first certificate. See the last paragraph of Section 4.6 for
	// additional guidance on this.
	X5C []string `json:"x5c,omitempty"`
	// X5T represents the "x5t" (X.509 certificate SHA-1 thumbprint) parameter in a JSON web key.
	//
	// https://datatracker.ietf.org/doc/html/rfc7517#section-4.8
	//
	// The "x5t" (X.509 certificate SHA-1 thumbprint) parameter is a
	// base64url-encoded SHA-1 thumbprint (a.k.a. digest) of the DER
	// encoding of an X.509 certificate [RFC5280]. Note that certificate
	// thumbprints are also sometimes known as certificate fingerprints.
	// The key in the certificate MUST match the public key represented by
	// other members of the JWKCommon. Use of this member is OPTIONAL.
	//
	// As with the "x5u" member, optional JWKCommon members providing key usage,
	// algorithm, or other information MAY also be present when the "x5t"
	// member is used. If other members are present, the contents of those
	// members MUST be semantically consistent with the related fields in
	// the referenced certificate. See the last paragraph of Section 4.6
	// for additional guidance on this.
	X5T string `json:"x5t,omitempty"`
	// X5TS256 represents the "x5t#S256" (X.509 certificate SHA-256 thumbprint) parameter in a JSON web key.
	//
	// https://datatracker.ietf.org/doc/html/rfc7517#section-4.9
	//
	// The "x5t#S256" (X.509 certificate SHA-256 thumbprint) parameter is a
	// base64url-encoded SHA-256 thumbprint (a.k.a. digest) of the DER
	// encoding of an X.509 certificate [RFC5280]. Note that certificate
	// thumbprints are also sometimes known as certificate fingerprints.
	// The key in the certificate MUST match the public key represented by
	// other members of the JWKCommon. Use of this member is OPTIONAL.
	//
	// As with the "x5u" member, optional JWKCommon members providing key usage,
	// algorithm, or other information MAY also be present when the
	// "x5t#S256" member is used. If other members are present, the
	// contents of those members MUST be semantically consistent with the
	// related fields in the referenced certificate. See the last paragraph
	// of Section 4.6 for additional guidance on this.
	X5TS256 string `json:"x5t#S256,omitempty"` //nolint:tagliatelle
}

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
