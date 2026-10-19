package jwt

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/a-novel-kit/jwt/v2/jwa"
)

// TargetConfig scopes a set of claims to an intended context. Recording where a token comes from
// and who it is for lets a recipient reject one that was replayed against the wrong service.
type TargetConfig struct {
	// Issuer that produced the token. A recipient should accept only tokens from producers it trusts.
	Issuer string
	// Audience the token is meant for (RFC 7519 §4.1.3). On a producer it sets the token's aud. In a
	// recipient check it lists the identities to match, and the token must name at least one of them.
	// Empty opts out of the audience check.
	Audience jwa.Audience
	// Subject the token describes. A recipient should reject tokens issued for a different subject.
	Subject string
}

// ClaimsProducerConfig scopes and time-bounds the claims a producer stamps on every token.
type ClaimsProducerConfig struct {
	TargetConfig

	// TTL is how long the token stays valid after issuance. Zero issues a token that never expires.
	TTL time.Duration
}

// NewBasicClaims wraps payload in a claims set whose registered claims scope and time-bound the
// token as config describes, under a fresh token ID. Encoding the result merges payload into the
// same JSON object, and fails with [jwa.ErrReservedMember] when payload names a registered claim.
func NewBasicClaims(payload any, config ClaimsProducerConfig) (*jwa.Claims, error) {
	payloadSerialized, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("(NewBasicClaims) marshal payload: %w", err)
	}

	now := time.Now()

	var exp int64
	if config.TTL != 0 {
		exp = now.Add(config.TTL).Unix()
	}

	claims := &jwa.Claims{
		ClaimsCommon: jwa.ClaimsCommon{
			Iss: config.Issuer,
			Sub: config.Subject,
			Aud: config.Audience,
			Exp: exp,
			Nbf: now.Unix(),
			Iat: now.Unix(),
			Jti: uuid.NewString(),
		},
		Payload: payloadSerialized,
	}

	return claims, nil
}
