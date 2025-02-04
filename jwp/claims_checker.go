package jwp

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/a-novel-kit/jwt"
	"github.com/a-novel-kit/jwt/jwa"
)

var ErrInvalidClaims = errors.New("invalid claims")

type ClaimsCheckerConfig struct {
	// If set, check that the target of a set of claims match the current recipient.
	Target *jwt.TargetConfig
	// Leeme is a margin of error allowed when checking the expiration date of a token.
	Leeme time.Duration
	// If set, require the expiration date to be set.
	RequireExpiration bool
}

type ClaimsChecker struct {
	config ClaimsCheckerConfig
}

func (checker *ClaimsChecker) Unmarshal(raw []byte, dst any) error {
	var token *jwa.Claims
	if err := json.Unmarshal(raw, &token); err != nil {
		return fmt.Errorf("(ClaimsChecker.Unmarshal) unmarshal claims: %w", err)
	}

	if checker.config.Target != nil {
		if checker.config.Target.Audience != token.Aud {
			return fmt.Errorf(
				"(ClaimsChecker.Unmarshal) %w: invalid audience %s, expected %s",
				ErrInvalidClaims, token.Aud, checker.config.Target.Audience,
			)
		}

		if checker.config.Target.Issuer != token.Iss {
			return fmt.Errorf(
				"(ClaimsChecker.Unmarshal) %w: invalid issuer %s, expected %s",
				ErrInvalidClaims, token.Iss, checker.config.Target.Issuer,
			)
		}

		if checker.config.Target.Subject != token.Sub {
			return fmt.Errorf(
				"(ClaimsChecker.Unmarshal) %w: invalid subject %s, expected %s",
				ErrInvalidClaims, token.Sub, checker.config.Target.Subject,
			)
		}
	}

	if checker.config.RequireExpiration && token.Exp == 0 {
		return fmt.Errorf("(ClaimsChecker.Unmarshal) %w: missing expiration date", ErrInvalidClaims)
	}

	exp := time.Unix(token.Exp, 0)
	if token.Exp > 0 && exp.Before(time.Now().Add(checker.config.Leeme)) {
		return fmt.Errorf(
			"(ClaimsChecker.Unmarshal) %w: token expired at %s",
			ErrInvalidClaims, exp.String(),
		)
	}

	if token.Nbf > 0 && time.Unix(token.Nbf, 0).After(time.Now()) {
		return fmt.Errorf(
			"(ClaimsChecker.Unmarshal) %w: token not valid before %s",
			ErrInvalidClaims, time.Unix(token.Nbf, 0).String(),
		)
	}

	if claimsDST, ok := dst.(*jwa.Claims); ok {
		*claimsDST = *token
		return nil
	}

	return json.Unmarshal(raw, dst)
}

// NewClaimsChecker is a custom claims unmarshaler, that performs extra checks on the claims.
func NewClaimsChecker(config *ClaimsCheckerConfig) *ClaimsChecker {
	return &ClaimsChecker{
		config: *config,
	}
}
