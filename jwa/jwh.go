package jwa

import (
	"encoding/json"

	"github.com/a-novel-kit/jwt/jwa/internal"
)

// Typ represents the "typ" field of a JWT header.
//
// https://datatracker.ietf.org/doc/html/rfc7519#section-5.1
type Typ string

func (typ Typ) String() string {
	return string(typ)
}

const (
	TypJWT     Typ = "JWT"
	TypJOSE    Typ = "JOSE"
	TypJOSEJWT Typ = "JOSE+JWT"
)

// CTY represents the "cty" field of a JWT header.
//
// https://datatracker.ietf.org/doc/html/rfc7519#section-5.2
type CTY string

const CtyJWT CTY = "JWT"

// JWHCommon is a JOSE header.
//
// https://datatracker.ietf.org/doc/html/rfc7519#section-5
//
// # For a JWT object, the members of the JSON object represented by the
// JOSE Header describe the cryptographic operations applied to the JWT
// and optionally, additional properties of the JWT. Depending upon
// whether the JWT is a JWS or JWE, the corresponding rules for the JOSE
// Header values apply.
//
// This specification further specifies the use of the following Header
// Parameters in both the cases where the JWT is a JWS and where it is a
// JWE.
type JWHCommon struct {
	JWHEmbeddedKey

	JWHKeyAgreement
	JWHPBES2
	JWHAESGCMKW

	J509

	// JWT header.
	//
	// https://datatracker.ietf.org/doc/html/rfc7519#section-5.1
	//
	// The "typ" (type) Header Parameter defined by [JWS] and [JWE] is used
	// by JWT applications to declare the media type [IANA.MediaTypes] of
	// this complete JWT. This is intended for use by the JWT application
	// when values that are not JWTs could also be present in an application
	// data structure that can contain a JWT object; the application can use
	// this value to disambiguate among the different kinds of objects that
	// might be present. It will typically not be used by applications when
	// it is already known that the object is a JWT. This parameter is
	// ignored by JWT implementations; any processing of this parameter is
	// performed by the JWT application. If present, it is RECOMMENDED that
	// its value be "JWT" to indicate that this object is a JWT. While
	// media type names are not case-sensitive, it is RECOMMENDED that "JWT"
	// always be spelled using uppercase characters for compatibility with
	// legacy implementations. Use of this Header Parameter is OPTIONAL.
	//
	// https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.9
	//
	// The "typ" (type) Header Parameter is used by JWS applications to
	// declare the media type [IANA.MediaTypes] of this complete JWS. This
	// is intended for use by the application when more than one kind of
	// object could be present in an application data structure that can
	// contain a JWS; the application can use this value to disambiguate
	// among the different kinds of objects that might be present. It will
	// typically not be used by applications when the kind of object is
	// already known. This parameter is ignored by JWS implementations; any
	// processing of this parameter is performed by the JWS application.
	// Use of this Header Parameter is OPTIONAL.
	//
	// Per RFC 2045 [RFC2045], all media type values, subtype values, and
	// parameter names are case insensitive. However, parameter values are
	// case sensitive unless otherwise specified for the specific parameter.
	// To keep messages compact in common situations, it is RECOMMENDED that
	// producers omit an "application/" prefix of a media type value in a
	// "typ" Header Parameter when no other '/' appears in the media type
	// value. A recipient using the media type value MUST treat it as if
	// "application/" were prepended to any "typ" value not containing a
	// '/'. For instance, a "typ" value of "example" SHOULD be used to
	// represent the "application/example" media type, whereas the media
	// type "application/example;part="1/2"" cannot be shortened to
	// "example;part="1/2"".
	//
	// The "typ" value "JOSE" can be used by applications to indicate that
	// this object is a JWS or JWE using the JWS Compact Serialization or
	// the JWE Compact Serialization. The "typ" value "JOSE+JSON" can be
	// used by applications to indicate that this object is a JWS or JWE
	// using the JWS JSON Serialization or the JWE JSON Serialization.
	// Other type values can also be used by applications.
	Typ Typ `json:"typ,omitempty"`
	// CTY header.
	//
	// https://datatracker.ietf.org/doc/html/rfc7519#section-5.2
	//
	// The "cty" (content type) Header Parameter defined by [JWS] and [JWE]
	// is used by this specification to convey structural information about
	// the JWT.
	//
	// In the normal case in which nested signing or encryption operations
	// are not employed, the use of this Header Parameter is NOT
	// RECOMMENDED. In the case that nested signing or encryption is
	// employed, this Header Parameter MUST be present; in this case, the
	// value MUST be "JWT", to indicate that a Nested JWT is carried in this
	// JWT. While media type names are not case-sensitive, it is
	// RECOMMENDED that "JWT" always be spelled using uppercase characters
	// for compatibility with legacy implementations. See Appendix A.2 for
	// an example of a Nested JWT.
	//
	// https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.10
	//
	// The "cty" (content type) Header Parameter is used by JWS applications
	// to declare the media type [IANA.MediaTypes] of the secured content
	// (the payload). This is intended for use by the application when more
	// than one kind of object could be present in the JWS J509; the
	// application can use this value to disambiguate among the different
	// kinds of objects that might be present. It will typically not be
	// used by applications when the kind of object is already known. This
	// parameter is ignored by JWS implementations; any processing of this
	// parameter is performed by the JWS application. Use of this Header
	// Parameter is OPTIONAL.
	//
	// Per RFC 2045 [RFC2045], all media type values, subtype values, and
	// parameter names are case insensitive. However, parameter values are
	// case sensitive unless otherwise specified for the specific parameter.
	//
	// To keep messages compact in common situations, it is RECOMMENDED that
	// producers omit an "application/" prefix of a media type value in a
	// "cty" Header Parameter when no other '/' appears in the media type
	// value. A recipient using the media type value MUST treat it as if
	// "application/" were prepended to any "cty" value not containing a
	// '/'. For instance, a "cty" value of "example" SHOULD be used to
	// represent the "application/example" media type, whereas the media
	// type "application/example;part="1/2"" cannot be shortened to
	// "example;part="1/2"".
	//
	// Values:
	// - CtyJWT
	CTY CTY `json:"cty,omitempty"`

	// Alg header.
	//
	// https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.1
	//
	// The "alg" (algorithm) Header Parameter identifies the cryptographic
	// algorithm used to secure the JWS. The JWS Signature value is not
	// valid if the "alg" value does not represent a supported algorithm or
	// if there is not a key for use with that algorithm associated with the
	// party that digitally signed or MACed the content. "alg" values
	// should either be registered in the IANA "JSON Web Signature and
	// Encryption Algorithms" registry established by [JWA] or be a value
	// that contains a Collision-Resistant Name. The "alg" value is a case-
	// sensitive ASCII string containing a StringOrURI value. This Header
	// Parameter MUST be present and MUST be understood and processed by
	// implementations.
	//
	// A list of defined "alg" values for this use can be found in the IANA
	// "JSON Web Signature and Encryption Algorithms" registry established
	// by [JWA]; the initial contents of this registry are the values
	// defined in Section 3.1 of [JWA].
	Alg Alg `json:"alg,omitempty"`
	// Enc header.
	//
	// https://datatracker.ietf.org/doc/html/rfc7516#section-4.1.2
	// The "enc" (encryption algorithm) Header Parameter identifies the
	// content encryption algorithm used to perform authenticated encryption
	// on the plaintext to produce the ciphertext and the Authentication
	// Tag. This algorithm MUST be an AEAD algorithm with a specified key
	// length. The encrypted content is not usable if the "enc" value does
	// not represent a supported algorithm. "enc" values should either be
	// registered in the IANA "JSON Web Signature and Encryption Algorithms"
	// registry established by [JWA] or be a value that contains a
	// Collision-Resistant Name. The "enc" value is a case-sensitive ASCII
	// string containing a StringOrURI value. This Header Parameter MUST be
	// present and MUST be understood and processed by implementations.
	Enc Enc `json:"enc,omitempty"`
	// Zip header.
	//
	// https://datatracker.ietf.org/doc/html/rfc7516#section-4.1.3
	//
	// The "zip" (compression algorithm) applied to the plaintext before
	// encryption, if any. The "zip" value defined by this specification
	// is:
	//
	// o "DEF" - Compression with the DEFLATE [RFC1951] algorithm
	//
	// Other values MAY be used. Compression algorithm values can be
	// registered in the IANA "JSON Web Encryption Compression Algorithms"
	// registry established by [JWA]. The "zip" value is a case-sensitive
	// string. If no "zip" parameter is present, no compression is applied
	// to the plaintext before encryption. When used, this Header Parameter
	// MUST be integrity protected; therefore, it MUST occur only within the
	// JWE Protected Header. Use of this Header Parameter is OPTIONAL.
	// This Header Parameter MUST be understood and processed by
	// implementations.
	Zip Zip `json:"zip,omitempty"`

	// Crit (Critical) Header Parameter.
	//
	// https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.11
	//
	// The "crit" (critical) Header Parameter indicates that extensions to
	// this specification and/or [JWA] are being used that MUST be
	// understood and processed. Its value is an array listing the Header
	// Parameter names present in the JOSE Header that use those extensions.
	// If any of the listed extension Header Parameters are not understood
	// and supported by the recipient, then the JWS is invalid. Producers
	// MUST NOT include Header Parameter names defined by this specification
	// or [JWA] for use with JWS, duplicate names, or names that do not
	// occur as Header Parameter names within the JOSE Header in the "crit"
	// list. Producers MUST NOT use the empty list "[]" as the "crit"
	// value. Recipients MAY consider the JWS to be invalid if the critical
	// list contains any Header Parameter names defined by this
	// specification or [JWA] for use with JWS or if any other constraints
	// on its use are violated. When used, this Header Parameter MUST be
	// integrity protected; therefore, it MUST occur only within the JWS
	// Protected Header. Use of this Header Parameter is OPTIONAL. This
	// Header Parameter MUST be understood and processed by implementations.
	//
	// An example use, along with a hypothetical "exp" (expiration time)
	// field is:
	//
	// {"alg":"ES256",
	// "crit":["exp"],
	// "exp":1363284000
	// }
	Crit []string `json:"crit,omitempty"`

	// https://datatracker.ietf.org/doc/html/rfc7519#section-5.3
	//
	// In some applications using encrypted JWTs, it is useful to have an
	// unencrypted representation of some claims. This might be used, for
	// instance, in application processing rules to determine whether and
	// how to process the JWT before it is decrypted.
	//
	// This specification allows claims present in the JWT Claims Set to be
	// replicated as Header Parameters in a JWT that is a JWE, as needed by
	// the application. If such replicated claims are present, the
	// application receiving them SHOULD verify that their values are
	// identical, unless the application defines other specific processing
	// rules for these claims. It is the responsibility of the application
	// to ensure that only claims that are safe to be transmitted in an
	// unencrypted manner are replicated as Header Parameter values in the
	// JWT.
	//
	// Section 10.4.1 of this specification registers the "iss" (producer),
	// "sub" (subject), and "aud" (audience) Header Parameter names for the
	// purpose of providing unencrypted replicas of these claims in
	// encrypted JWTs for applications that need them. Other specifications
	// MAY similarly register other names that are registered Claim Names as
	// Header Parameter names, as needed.

	// Iss is the producer of the token.
	//
	// This parameter is replicated from the body, to allow processing of encrypted body, where this information is
	// not available.
	//
	// https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.1
	//
	// The "iss" (producer) claim identifies the principal that issued the
	// JWT. The processing of this claim is generally application specific.
	// The "iss" value is a case-sensitive string containing a StringOrURI
	// value. Use of this claim is OPTIONAL.
	Iss string `json:"iss,omitempty"`
	// Sub is the subject of the token.
	//
	// This parameter is replicated from the body, to allow processing of encrypted body, where this information is
	// not available.
	//
	// https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.2
	//
	// The "sub" (subject) claim identifies the principal that is the
	// subject of the JWT. The claims in a JWT are normally statements
	// about the subject. The subject value MUST either be scoped to be
	// locally unique in the context of the producer or be globally unique.
	// The processing of this claim is generally application specific. The
	// "sub" value is a case-sensitive string containing a StringOrURI
	// value. Use of this claim is OPTIONAL.
	Sub string `json:"sub,omitempty"`
	// Aud is the audience of the token.
	//
	// This parameter is replicated from the body, to allow processing of encrypted body, where this information is
	// not available.
	//
	// https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.3
	//
	// The "aud" (audience) claim identifies the recipients that the JWT is
	// intended for. Each principal intended to process the JWT MUST
	// identify itself with a value in the audience claim. If the principal
	// processing the claim does not identify itself with a value in the
	// "aud" claim when this claim is present, then the JWT MUST be
	// rejected. In the general case, the "aud" value is an array of case-
	// sensitive strings, each containing a StringOrURI value. In the
	// special case when the JWT has one audience, the "aud" value MAY be a
	// single case-sensitive string containing a StringOrURI value. The
	// interpretation of audience values is generally application specific.
	// Use of this claim is OPTIONAL.
	Aud string `json:"aud,omitempty"`
}

type JWHEmbeddedKey struct {
	// JKU (JWK Set URL) Header Parameter.
	//
	// https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.2
	//
	// The "jku" (JWK Set URL) Header Parameter is a URI [RFC3986] that
	// refers to a resource for a set of JSON-encoded public keys, one of
	// which corresponds to the key used to digitally sign the JWS. The
	// keys MUST be encoded as a JWK Set [JWKCommon]. The protocol used to
	// acquire the resource MUST provide integrity protection; an HTTP GET
	// request to retrieve the JWK Set MUST use Transport Layer Security
	// (TLS) [RFC2818] [RFC5246]; and the identity of the server MUST be
	// validated, as per Section 6 of RFC 6125 [RFC6125]. Also, see
	// Section 8 on TLS requirements. Use of this Header Parameter is
	// OPTIONAL.
	JKU string `json:"jku,omitempty"`
	// JWK (JSON Web CEK) Header Parameter.
	//
	// https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.3
	//
	// The "jwk" (JSON Web CEK) Header Parameter is the public key that
	// corresponds to the key used to digitally sign the JWS. This key is
	// represented as a JSON Web CEK [JWKCommon]. Use of this Header Parameter is
	// OPTIONAL.
	JWK *JWK `json:"jwk,omitempty"`
	// KID (Key ID) Header Parameter.
	//
	// https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.4
	//
	// The "kid" (key ID) Header Parameter is a hint indicating which key
	// was used to secure the JWS. This parameter allows originators to
	// explicitly signal a change of key to recipients. The structure of
	// the "kid" value is unspecified. Its value MUST be a case-sensitive
	// string. Use of this Header Parameter is OPTIONAL.
	//
	// When used with a JWK, the "kid" value is used to match a JWK "kid"
	// parameter value.
	KID string `json:"kid,omitempty"`
}

type JWHKeyAgreement struct {
	// EPK is the Ephemeral Public Key Header Parameter.
	//
	// https://datatracker.ietf.org/doc/html/rfc7518#section-4.6.1.1
	//
	// The "epk" (ephemeral public key) value created by the originator for
	// the use in key agreement algorithms. This key is represented as a
	// JSON Web Key [JWKCommon] public key value. It MUST contain only public key
	// parameters and SHOULD contain only the minimum JWKCommon parameters
	// necessary to represent the key; other JWKCommon parameters included can be
	// checked for consistency and honored, or they can be ignored. This
	// Header Parameter MUST be present and MUST be understood and processed
	// by implementations when these algorithms are used.
	EPK *JWK `json:"epk,omitempty"`
	// APU is the Agreement PartyUInfo Header Parameter.
	//
	// https://datatracker.ietf.org/doc/html/rfc7518#section-4.6.1.2
	//
	// The "apu" (agreement PartyUInfo) value for key agreement algorithms
	// using it (such as "ECDH-ES"), represented as a base64url-encoded
	// string. When used, the PartyUInfo value contains information about
	// the producer. Use of this Header Parameter is OPTIONAL. This Header
	// Parameter MUST be understood and processed by implementations when
	// these algorithms are used.
	APU string `json:"apu,omitempty"`
	// APV is the Agreement PartyVInfo Header Parameter.
	//
	// https://datatracker.ietf.org/doc/html/rfc7518#section-4.6.1.3
	//
	// The "apv" (agreement PartyVInfo) value for key agreement algorithms
	// using it (such as "ECDH-ES"), represented as a base64url encoded
	// string. When used, the PartyVInfo value contains information about
	// the recipient. Use of this Header Parameter is OPTIONAL. This
	// Header Parameter MUST be understood and processed by implementations
	// when these algorithms are used.
	APV string `json:"apv,omitempty"`
}

type JWHPBES2 struct {
	// P2S is the salt input of the PBES2 algorithm.
	P2S string `json:"p2s,omitempty"`
	// P2C is the iteration count of the PBES2 algorithm.
	P2C int `json:"p2c,omitempty"`
}

type JWHAESGCMKW struct {
	IV  string `json:"iv,omitempty"`
	Tag string `json:"tag,omitempty"`
}

type JWH struct {
	JWHCommon

	Payload json.RawMessage
}

func (header JWH) MarshalJSON() ([]byte, error) {
	return internal.MarshalPartial(header.JWHCommon, header.Payload)
}

func (header *JWH) UnmarshalJSON(src []byte) error {
	var err error

	header.JWHCommon, header.Payload, err = internal.UnmarshalPartial[JWHCommon](src)

	return err
}
