package jwt

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/samber/lo"

	"github.com/a-novel-kit/jwt/v2/jwa"
)

// TargetConfig scopes a set of claims to an intended context. Recording where a token comes from
// and who it is for lets a recipient reject one that was replayed against the wrong service.
type TargetConfig struct {
	// Issuer that produced the token. A recipient should accept only tokens from producers it trusts.
	Issuer string
	// Audience the token is meant for (RFC 7519 §4.1.3). On a producer it sets the token's aud; in a
	// recipient check it is the identities to match — the token must name at least one. Empty opts
	// out of the audience check.
	Audience jwa.Audience
	// Subject the token describes. A recipient should reject tokens issued for a different subject.
	Subject string
}

// ClaimsProducerConfig scopes and time-bounds the claims a producer stamps on every token.
type ClaimsProducerConfig struct {
	TargetConfig

	// TTL is the time to live of the token. If set to 0, the token will never expire.
	TTL time.Duration
}

// NewBasicClaims creates a new encoded claims object for a JSON Web Token. It uses the standardized claims format to
// wrap the user-provided payload.
func NewBasicClaims(payload any, config ClaimsProducerConfig) (*jwa.Claims, error) {
	payloadSerialized, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("(NewBasicClaims) marshal payload: %w", err)
	}

	now := time.Now()

	claims := &jwa.Claims{
		ClaimsCommon: jwa.ClaimsCommon{
			Iss: config.Issuer,
			Sub: config.Subject,
			Aud: config.Audience,
			Exp: lo.Ternary(config.TTL == 0, 0, now.Add(config.TTL).Unix()),
			Nbf: now.Unix(),
			Iat: now.Unix(),
			Jti: uuid.NewString(),
		},
		Payload: payloadSerialized,
	}

	return claims, nil
}
