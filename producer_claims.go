package jwt

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/samber/lo"

	"github.com/a-novel-kit/jwt/jwa"
)

// TargetConfig sets the target of a given set of claims. Target information prevents the token from being misused.
type TargetConfig struct {
	// Issuer of the token. The receiving side MUST filter only tokens that come from trusted producers.
	Issuer string
	// Audience of the token. The receiving side MUST filter only tokens that are intended for them.
	Audience string
	// Subject of the token. The receiving side MUST filter only tokens that are intended for the given subject.
	Subject string
}

// ClaimsProducerConfig is a configuration struct used to issue standardized claims.
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
			Exp: lo.Ternary(config.TTL == 0, 0, time.Now().Add(config.TTL).Unix()),
			Nbf: now.Unix(),
			Iat: now.Unix(),
			Jti: uuid.NewString(),
		},
		Payload: payloadSerialized,
	}

	return claims, nil
}
