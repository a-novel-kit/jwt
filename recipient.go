package jwt

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/a-novel-kit/jwt/jwa"
)

// DefaultMaxTokenBytes bounds the size of an untrusted token Consume will parse when the
// RecipientConfig does not set a limit. It is deliberately generous — even a JWE carrying an
// embedded certificate chain stays well under it — while capping the work an attacker can force
// with an oversized input.
const DefaultMaxTokenBytes = 1 << 18 // 256 KiB.

// ErrTokenTooLarge is returned by Consume when a token exceeds the configured size limit.
var ErrTokenTooLarge = errors.New("token exceeds maximum size")

// RecipientConfig configures a Recipient: the ordered plugins that verify or decrypt a token and
// an optional deserializer for its claims.
type RecipientConfig struct {
	// Plugins run in order until one recognizes the token.
	Plugins []RecipientPlugin

	// Deserializer decodes the raw claims payload into the destination. Defaults to json.Unmarshal.
	Deserializer func(raw []byte, dst any) error

	// MaxTokenBytes rejects tokens larger than this before parsing. Non-positive selects DefaultMaxTokenBytes.
	MaxTokenBytes int

	// CriticalHeaders names the "crit" extensions this recipient understands and will process. A
	// token whose crit list names anything outside this set is rejected (RFC 7515 §4.1.11).
	CriticalHeaders []string
}

// A Recipient verifies and decodes JWTs against a fixed set of plugins.
type Recipient struct {
	config RecipientConfig
}

// NewRecipient returns a Recipient for the given configuration. With no plugins, it falls back to
// consuming unsecured ("none") tokens.
func NewRecipient(config RecipientConfig) *Recipient {
	if config.Plugins == nil {
		config.Plugins = []RecipientPlugin{NewDefaultRecipientPlugin()}
	}

	if config.MaxTokenBytes <= 0 {
		config.MaxTokenBytes = DefaultMaxTokenBytes
	}

	// Resolve the default here rather than lazily in Consume: a Recipient is built once and shared
	// across goroutines, so writing config on first use would be a data race.
	if config.Deserializer == nil {
		config.Deserializer = json.Unmarshal
	}

	return &Recipient{
		config: config,
	}
}

// Consume validates rawToken and decodes its claims into dst. It tries each plugin in order, uses
// the first that recognizes the token, and fails if none do.
func (recipient *Recipient) Consume(ctx context.Context, rawToken string, dst any) error {
	if len(rawToken) > recipient.config.MaxTokenBytes {
		// Only lengths in the message — never the token itself (a bearer credential).
		return fmt.Errorf(
			"(Recipient.Consume) %w: %d bytes exceeds limit %d",
			ErrTokenTooLarge, len(rawToken), recipient.config.MaxTokenBytes,
		)
	}

	rawHeader, err := DecodeToken(rawToken, &HeaderDecoder{})
	if err != nil {
		return fmt.Errorf("(Recipient.Consume) decode token: %w", err)
	}

	decodedHeader, err := base64.RawURLEncoding.DecodeString(rawHeader)
	if err != nil {
		return fmt.Errorf("(Recipient.Consume) decode header: %w", err)
	}

	var header *jwa.JWH

	err = json.Unmarshal(decodedHeader, &header)
	if err != nil {
		return fmt.Errorf("(Recipient.Consume) unmarshal header: %w", err)
	}

	// A header segment of JSON "null" unmarshals into a nil pointer without error; reject it before
	// dereferencing rather than panicking on untrusted input.
	if header == nil {
		return fmt.Errorf("(Recipient.Consume) %w: null header", ErrUnsupportedTokenFormat)
	}

	// A non-nil Crit means the "crit" member is present in the header. Whether it is well-formed —
	// including the RFC 7515 §4.1.11 rule that it must not be empty — is CheckCritUnderstood's call.
	if header.Crit != nil {
		err = CheckCritUnderstood(decodedHeader, header.Crit, recipient.config.CriticalHeaders)
		if err != nil {
			return fmt.Errorf("(Recipient.Consume) check crit: %w", err)
		}
	}

	// A plugin that does not match the token yields ErrMismatchRecipientPlugin; fall through to the
	// next one. Any other error is fatal.
	for _, plugin := range recipient.config.Plugins {
		rawClaims, err := plugin.Transform(ctx, header, rawToken)
		if err != nil {
			if errors.Is(err, ErrMismatchRecipientPlugin) {
				continue
			}

			return fmt.Errorf("(Recipient.Consume) transform token: %w", err)
		}

		err = recipient.config.Deserializer(rawClaims, dst)
		if err != nil {
			return fmt.Errorf("(Recipient.Consume) unmarshal claims: %w", err)
		}

		return nil
	}

	return fmt.Errorf("(Recipient.Consume) %w: no compatible plugin found", ErrMismatchRecipientPlugin)
}
