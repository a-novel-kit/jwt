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

type RawClaimsCheck interface {
	CheckRaw(raw []byte) error
}

type ClaimsCheck interface {
	CheckClaims(claims *jwa.Claims) error
}

type ClaimsCheckTarget struct {
	target jwt.TargetConfig
}

func (claimsCheck *ClaimsCheckTarget) CheckClaims(claims *jwa.Claims) error {
	if claimsCheck.target.Audience != claims.Aud {
		return fmt.Errorf(
			"invalid audience %s, expected %s",
			claims.Aud, claimsCheck.target.Audience,
		)
	}

	if claimsCheck.target.Issuer != claims.Iss {
		return fmt.Errorf(
			"invalid issuer %s, expected %s",
			claims.Iss, claimsCheck.target.Issuer,
		)
	}

	if claimsCheck.target.Subject != claims.Sub {
		return fmt.Errorf(
			"invalid subject %s, expected %s",
			claims.Sub, claimsCheck.target.Subject,
		)
	}

	return nil
}

type ClaimsCheckTimestamp struct {
	leeway     time.Duration
	requireExp bool
}

func (claimsCheck *ClaimsCheckTimestamp) CheckClaims(claims *jwa.Claims) error {
	exp := time.Unix(claims.Exp, 0)
	if claims.Exp > 0 && exp.Before(time.Now().Add(-claimsCheck.leeway)) {
		return fmt.Errorf(
			"token expired at %s",
			exp.String(),
		)
	}

	if claimsCheck.requireExp && claims.Exp == 0 {
		return errors.New("missing expiration date")
	}

	if claims.Nbf > 0 && time.Unix(claims.Nbf, 0).After(time.Now().Add(claimsCheck.leeway)) {
		return fmt.Errorf(
			"token not valid before %s",
			time.Unix(claims.Nbf, 0).String(),
		)
	}

	return nil
}

func NewClaimsCheckTarget(target jwt.TargetConfig) *ClaimsCheckTarget {
	return &ClaimsCheckTarget{
		target: target,
	}
}

func NewClaimsCheckTimestamp(leeway time.Duration, requireExp bool) *ClaimsCheckTimestamp {
	return &ClaimsCheckTimestamp{
		leeway:     leeway,
		requireExp: requireExp,
	}
}

type RawClaimsChecker[T any] struct {
	config   T
	callback func(raw []byte, config T) error
}

func (claimsCheck *RawClaimsChecker[T]) CheckRaw(raw []byte) error {
	return claimsCheck.callback(raw, claimsCheck.config)
}

func NewRawClaimsChecker[T any](config T, callback func(raw []byte, config T) error) *RawClaimsChecker[T] {
	return &RawClaimsChecker[T]{
		config:   config,
		callback: callback,
	}
}

type ClaimsCheckerConfig struct {
	Checks    []ClaimsCheck
	ChecksRaw []RawClaimsCheck

	// Set a custom deserializer to decode the token's payload. Uses json.Unmarshal by default.
	Deserializer func(raw []byte, dst any) error
}

type ClaimsChecker struct {
	config ClaimsCheckerConfig
}

func (checker *ClaimsChecker) Unmarshal(raw []byte, dst any) error {
	var token *jwa.Claims

	err := json.Unmarshal(raw, &token)
	if err != nil {
		return fmt.Errorf("(ClaimsChecker.Unmarshal) unmarshal claims: %w", err)
	}

	for _, check := range checker.config.Checks {
		err := check.CheckClaims(token)
		if err != nil {
			return fmt.Errorf("(ClaimsChecker.Unmarshal) %w: %w", ErrInvalidClaims, err)
		}
	}

	for _, check := range checker.config.ChecksRaw {
		err := check.CheckRaw(raw)
		if err != nil {
			return fmt.Errorf("(ClaimsChecker.Unmarshal) %w: %w", ErrInvalidClaims, err)
		}
	}

	if checker.config.Deserializer == nil {
		checker.config.Deserializer = json.Unmarshal
	}

	return json.Unmarshal(raw, dst)
}

// NewClaimsChecker is a custom claims unmarshaler, that performs extra checks on the claims.
func NewClaimsChecker(config *ClaimsCheckerConfig) *ClaimsChecker {
	return &ClaimsChecker{
		config: *config,
	}
}
