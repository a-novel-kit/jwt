package jwa

import (
	"encoding/json"

	"github.com/a-novel-kit/jwt/jwa/internal"
)

// ClaimsCommon are standard claims of a JWT token.
//
// https://datatracker.ietf.org/doc/html/rfc7519#section-4
//
// The JWT Claims Set represents a JSON object whose members are the
// claims conveyed by the JWT. The Claim Names within a JWT Claims Set
// MUST be unique; JWT parsers MUST either reject JWTs with duplicate
// Claim Names or use a JSON parser that returns only the lexically last
// duplicate member name, as specified in Section 15.12 ("The JSON
// Object") of ECMAScript 5.1 [ECMAScript].
//
// The set of claims that a JWT must contain to be considered valid is
// context dependent and is outside the scope of this specification.
// Specific applications of JWTs will require implementations to
// understand and process some claims in particular ways. However, in
// the absence of such requirements, all claims that are not understood
// by implementations MUST be ignored.
//
// There are three classes of JWT Claim Names: Registered Claim Names,
// Public Claim Names, and Private Claim Names.
type ClaimsCommon struct {
	// Iss is the producer of the token.
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

	// Exp is the expiration time of the token.
	//
	// https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.4
	// The "exp" (expiration time) claim identifies the expiration time on
	// or after which the JWT MUST NOT be accepted for processing. The
	// processing of the "exp" claim requires that the current date/time
	// MUST be before the expiration date/time listed in the "exp" claim.
	// Implementers MAY provide for some small leeway, usually no more than
	// a few minutes, to account for clock skew. Its value MUST be a number
	// containing a NumericDate value. Use of this claim is OPTIONAL.
	Exp int64 `json:"exp,omitempty"`
	// Nbf is the "not before" time of the token.
	//
	// https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.5
	//
	// The "nbf" (not before) claim identifies the time before which the JWT
	// MUST NOT be accepted for processing. The processing of the "nbf"
	// claim requires that the current date/time MUST be after or equal to
	// the not-before date/time listed in the "nbf" claim. Implementers MAY
	// provide for some small leeway, usually no more than a few minutes, to
	// account for clock skew. Its value MUST be a number containing a
	// NumericDate value. Use of this claim is OPTIONAL.
	Nbf int64 `json:"nbf,omitempty"`
	// Iat is the time at which the token was issued.
	//
	// https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.6
	//
	// The "iat" (issued at) claim identifies the time at which the JWT was
	// issued. This claim can be used to determine the age of the JWT. Its
	// value MUST be a number containing a NumericDate value. Use of this
	// claim is OPTIONAL.
	Iat int64 `json:"iat,omitempty"`

	// Jti is the JWT ID of the token.
	//
	// https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.7
	//
	// The "jti" (JWT ID) claim provides a unique identifier for the JWT.
	// The identifier value MUST be assigned in a manner that ensures that
	// there is a negligible probability that the same value will be
	// accidentally assigned to a different data object; if the application
	// uses multiple producers, collisions MUST be prevented among values
	// produced by different producers as well. The "jti" claim can be used
	// to prevent the JWT from being replayed. The "jti" value is a case-
	// sensitive string. Use of this claim is OPTIONAL.
	Jti string `json:"jti,omitempty"`
}

type Claims struct {
	ClaimsCommon
	Payload json.RawMessage
}

func (claims Claims) MarshalJSON() ([]byte, error) {
	return internal.MarshalJSONJose(claims.ClaimsCommon, claims.Payload)
}

func (claims *Claims) UnmarshalJSON(src []byte) error {
	var err error
	claims.ClaimsCommon, claims.Payload, err = internal.UnmarshalJSONJose[ClaimsCommon](src)
	return err
}
