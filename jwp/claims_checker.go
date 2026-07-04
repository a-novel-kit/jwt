package jwp

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/a-novel-kit/jwt/v2"
	"github.com/a-novel-kit/jwt/v2/jwa"
)

// ErrInvalidClaims wraps every failure reported by a claims check, so callers can detect a rejected
// token by identity while the wrapped error carries which check failed. Returned by
// [ClaimsChecker.Unmarshal].
var ErrInvalidClaims = errors.New("invalid claims")

// A RawClaimsCheck validates a token's payload from its raw JSON bytes, before any decoding. Use it
// for custom claims that are not part of the registered [jwa.Claims] set. CheckRaw returns an error
// to reject the token.
type RawClaimsCheck interface {
	CheckRaw(raw []byte) error
}

// A ClaimsCheck validates the registered claims of a token after they are decoded. CheckClaims
// returns an error to reject the token.
type ClaimsCheck interface {
	CheckClaims(claims *jwa.Claims) error
}

// A ClaimsCheckTarget rejects a token whose audience, issuer, or subject does not match the expected
// target. It implements [ClaimsCheck].
type ClaimsCheckTarget struct {
	target jwt.TargetConfig
}

// NewClaimsCheckTarget returns a [ClaimsCheck] that accepts only tokens matching the given target.
func NewClaimsCheckTarget(target jwt.TargetConfig) *ClaimsCheckTarget {
	return &ClaimsCheckTarget{
		target: target,
	}
}

func (claimsCheck *ClaimsCheckTarget) CheckClaims(claims *jwa.Claims) error {
	// RFC 7519 §4.1.3: the recipient identifies with a value in the token's audience. The check
	// passes when any configured audience appears in the token's aud; an empty target audience opts
	// out of the check (matching go-jose / golang-jwt).
	if len(claimsCheck.target.Audience) > 0 && !audienceContainsAny(claims.Aud, claimsCheck.target.Audience) {
		return fmt.Errorf(
			"invalid audience %v, expected one of %v",
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

// audienceContainsAny reports whether have and want share at least one value — the token names an
// audience the recipient answers to.
func audienceContainsAny(have, want jwa.Audience) bool {
	for _, w := range want {
		for _, h := range have {
			if w == h {
				return true
			}
		}
	}

	return false
}

// A ClaimsCheckTimestamp rejects a token that has expired or is not yet valid, comparing the "exp"
// and "nbf" claims against the current time. It implements [ClaimsCheck].
type ClaimsCheckTimestamp struct {
	leeway     time.Duration
	requireExp bool
}

// NewClaimsCheckTimestamp returns a [ClaimsCheck] that validates the token's time bounds. The leeway
// widens the accepted window on both ends to absorb clock skew. When requireExp is true, a token
// without an "exp" claim is rejected.
func NewClaimsCheckTimestamp(leeway time.Duration, requireExp bool) *ClaimsCheckTimestamp {
	return &ClaimsCheckTimestamp{
		leeway:     leeway,
		requireExp: requireExp,
	}
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

// A RawClaimsChecker adapts an arbitrary callback into a [RawClaimsCheck], passing a caller-supplied
// config of type T alongside the raw payload on every check. Use it to validate custom claims
// without declaring a dedicated type.
type RawClaimsChecker[T any] struct {
	config   T
	callback func(raw []byte, config T) error
}

// NewRawClaimsChecker returns a [RawClaimsCheck] that runs the callback against each token's raw
// payload, threading config through to it.
func NewRawClaimsChecker[T any](config T, callback func(raw []byte, config T) error) *RawClaimsChecker[T] {
	return &RawClaimsChecker[T]{
		config:   config,
		callback: callback,
	}
}

func (claimsCheck *RawClaimsChecker[T]) CheckRaw(raw []byte) error {
	return claimsCheck.callback(raw, claimsCheck.config)
}

// A ClaimsCheckerConfig lists the validations a [ClaimsChecker] runs before it decodes a token's
// payload.
type ClaimsCheckerConfig struct {
	// Checks run against the decoded registered claims.
	Checks []ClaimsCheck
	// ChecksRaw run against the raw payload bytes, for claims outside the registered set.
	ChecksRaw []RawClaimsCheck

	// Deserializer decodes the validated payload into the destination. Defaults to json.Unmarshal.
	Deserializer func(raw []byte, dst any) error
}

// A ClaimsChecker is a payload deserializer that validates a token's claims before decoding it. It
// plugs into the recipient as the claims unmarshaler, rejecting the token with [ErrInvalidClaims]
// when any configured check fails.
type ClaimsChecker struct {
	config ClaimsCheckerConfig
}

// NewClaimsChecker returns a [ClaimsChecker] that runs the configured checks on each token before
// decoding its payload.
func NewClaimsChecker(config *ClaimsCheckerConfig) *ClaimsChecker {
	return &ClaimsChecker{
		config: *config,
	}
}

// Unmarshal runs every configured check against the token's claims, then decodes the payload into
// dst. It returns [ErrInvalidClaims] as soon as a check rejects the token, leaving dst untouched.
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

	// Fall back to json.Unmarshal via a local variable, never by writing config: a first-call write
	// to a shared checker would be a data race, and a zero-value checker must still work.
	deserialize := checker.config.Deserializer
	if deserialize == nil {
		deserialize = json.Unmarshal
	}

	return deserialize(raw, dst)
}
