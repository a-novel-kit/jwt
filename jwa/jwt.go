package jwa

import (
	"encoding/json"

	"github.com/a-novel-kit/jwt/v2/jwa/internal"
)

// ClaimsCommon holds the registered claims of a JWT, the standard fields every
// token may carry. Application-specific claims live alongside them in the
// payload; see Claims.
//
// https://datatracker.ietf.org/doc/html/rfc7519#section-4
type ClaimsCommon struct {
	// Iss identifies the issuer of the token.
	// https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.1
	Iss string `json:"iss,omitempty"`
	// Sub identifies the subject the claims are about. It is unique either
	// within the issuer's scope or globally.
	// https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.2
	Sub string `json:"sub,omitempty"`
	// Aud identifies the recipients the token is intended for. A recipient that
	// does not find itself in the audience rejects the token. It is a string or
	// an array of strings.
	// https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.3
	Aud Audience `json:"aud,omitempty"`

	// Exp is the time on or after which the token must not be accepted, as a
	// Unix timestamp in seconds.
	// https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.4
	Exp int64 `json:"exp,omitempty"`
	// Nbf is the time before which the token must not be accepted, as a Unix
	// timestamp in seconds.
	// https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.5
	Nbf int64 `json:"nbf,omitempty"`
	// Iat is the time the token was issued, as a Unix timestamp in seconds.
	// https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.6
	Iat int64 `json:"iat,omitempty"`

	// Jti is a unique identifier for the token, assigned so collisions are
	// negligible. It lets a recipient detect a replayed token.
	// https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.7
	Jti string `json:"jti,omitempty"`
}

// Claims is a full JWT claims set: the registered ClaimsCommon fields plus the
// application-specific payload. Marshaling merges the two into one JSON object.
type Claims struct {
	ClaimsCommon

	Payload json.RawMessage
}

func (claims Claims) MarshalJSON() ([]byte, error) {
	return internal.MarshalPartial(claims.ClaimsCommon, claims.Payload)
}

func (claims *Claims) UnmarshalJSON(src []byte) error {
	var err error

	claims.ClaimsCommon, claims.Payload, err = internal.UnmarshalPartial[ClaimsCommon](src)

	return err
}
