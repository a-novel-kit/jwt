package jwt

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"mime"
	"strings"

	"github.com/a-novel-kit/jwt/v2/jwa"
)

// DefaultMaxTokenBytes bounds the size of an untrusted token Consume will parse when the
// RecipientConfig does not set a limit. It caps the work an oversized input can force while staying
// well clear of a legitimate token, down to a JWE carrying an embedded certificate chain.
const DefaultMaxTokenBytes = 1 << 18 // 256 KiB.

// ErrTokenTooLarge is returned by Consume when a token exceeds the configured size limit.
var ErrTokenTooLarge = errors.New("token exceeds maximum size")

// ErrUnexpectedTyp is returned by Consume when a token's "typ" header does not declare the media type
// the recipient expects.
var ErrUnexpectedTyp = errors.New("unexpected token type")

// RecipientConfig configures a Recipient: the ordered plugins that verify or decrypt a token and
// an optional deserializer for its claims.
type RecipientConfig struct {
	// Plugins run in order until one recognizes the token. A recipient without plugins accepts no
	// token: unsecured ("none") tokens are consumed only when [DefaultRecipientPlugin] is listed here.
	Plugins []RecipientPlugin

	// Deserializer decodes the raw claims payload into the destination. Defaults to json.Unmarshal.
	Deserializer func(raw []byte, dst any) error

	// MaxTokenBytes rejects tokens larger than this before parsing. Non-positive selects DefaultMaxTokenBytes.
	MaxTokenBytes int

	// CriticalHeaders names the "crit" extensions this recipient understands and will process. A
	// token whose crit list names anything outside this set is rejected (RFC 7515 §4.1.11).
	CriticalHeaders []string

	// Typ is the media type a token's "typ" header must declare, such as "at+jwt" for OAuth access
	// tokens. Distinct types keep one kind of token from being accepted as another. The comparison
	// follows RFC 7515 §4.1.9: the type, subtype, and parameter names ignore case, parameter values
	// keep it, and a value without any "/" stands for one under "application/". Empty skips the
	// check.
	Typ jwa.Typ
}

// A Recipient verifies and decodes JWTs against a fixed set of plugins.
type Recipient struct {
	config RecipientConfig
}

// NewRecipient returns a Recipient for the given configuration.
func NewRecipient(config RecipientConfig) *Recipient {
	if config.MaxTokenBytes <= 0 {
		config.MaxTokenBytes = DefaultMaxTokenBytes
	}

	// A Recipient is built once and shared across goroutines, so defaults are resolved at
	// construction and never written afterwards.
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
		// The token is a bearer credential; the message carries lengths only.
		return fmt.Errorf(
			"(Recipient.Consume) %w: %d bytes exceeds limit %d",
			ErrTokenTooLarge, len(rawToken), recipient.config.MaxTokenBytes,
		)
	}

	err := checkCompactAlphabet(rawToken)
	if err != nil {
		return fmt.Errorf("(Recipient.Consume) %w", err)
	}

	rawHeader, err := DecodeToken(rawToken, &HeaderDecoder{})
	if err != nil {
		return fmt.Errorf("(Recipient.Consume) decode token: %w", err)
	}

	decodedHeader, err := base64.RawURLEncoding.DecodeString(rawHeader)
	if err != nil {
		return fmt.Errorf("(Recipient.Consume) %w: decode header: %w", ErrUnsupportedTokenFormat, err)
	}

	var header *jwa.JWH

	err = json.Unmarshal(decodedHeader, &header)
	if err != nil {
		return fmt.Errorf("(Recipient.Consume) %w: unmarshal header: %w", ErrUnsupportedTokenFormat, err)
	}

	// A header segment of JSON "null" unmarshals into a nil pointer without error; reject it before
	// anything dereferences it.
	if header == nil {
		return fmt.Errorf("(Recipient.Consume) %w: null header", ErrUnsupportedTokenFormat)
	}

	if recipient.config.Typ != "" && !sameMediaType(header.Typ, recipient.config.Typ) {
		return fmt.Errorf("(Recipient.Consume) %w: %q, expected %q", ErrUnexpectedTyp, header.Typ, recipient.config.Typ)
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

// DecodeUnverified decodes rawToken's claims into dst without verifying its signature. The result is
// untrusted and must never carry a trust decision. Use it only on a token whose authenticity is
// already established — one just minted locally, or one a separate step has verified. To verify and
// decode, use [Recipient.Consume].
//
// It reads the payload of a signed (JWS) token; it does not decrypt JWE. The size limit still
// applies, but no plugin runs and the header's crit list is not enforced.
func (recipient *Recipient) DecodeUnverified(rawToken string, dst any) error {
	if len(rawToken) > recipient.config.MaxTokenBytes {
		// The token is a bearer credential; the message carries lengths only.
		return fmt.Errorf(
			"(Recipient.DecodeUnverified) %w: %d bytes exceeds limit %d",
			ErrTokenTooLarge, len(rawToken), recipient.config.MaxTokenBytes,
		)
	}

	err := checkCompactAlphabet(rawToken)
	if err != nil {
		return fmt.Errorf("(Recipient.DecodeUnverified) %w", err)
	}

	token, err := DecodeToken(rawToken, &SignedTokenDecoder{})
	if err != nil {
		return fmt.Errorf("(Recipient.DecodeUnverified) decode token: %w", err)
	}

	// Confirm the input is a structurally valid JWS — the header must be base64url-encoded, non-null
	// JSON — so a non-JWT input cannot silently yield claims.
	decodedHeader, err := base64.RawURLEncoding.DecodeString(token.Header)
	if err != nil {
		return fmt.Errorf("(Recipient.DecodeUnverified) %w: decode header: %w", ErrUnsupportedTokenFormat, err)
	}

	var header *jwa.JWH

	err = json.Unmarshal(decodedHeader, &header)
	if err != nil {
		return fmt.Errorf("(Recipient.DecodeUnverified) %w: unmarshal header: %w", ErrUnsupportedTokenFormat, err)
	}

	if header == nil {
		return fmt.Errorf("(Recipient.DecodeUnverified) %w: null header", ErrUnsupportedTokenFormat)
	}

	rawClaims, err := base64.RawURLEncoding.DecodeString(token.Payload)
	if err != nil {
		return fmt.Errorf("(Recipient.DecodeUnverified) %w: decode payload: %w", ErrUnsupportedTokenFormat, err)
	}

	err = recipient.config.Deserializer(rawClaims, dst)
	if err != nil {
		return fmt.Errorf("(Recipient.DecodeUnverified) unmarshal claims: %w", err)
	}

	return nil
}

// checkCompactAlphabet rejects input holding anything besides base64url characters and the "."
// separator, the only characters a compact token consists of. The base64 decoder skips line breaks,
// so this runs before any segment is decoded.
//
// https://datatracker.ietf.org/doc/html/draft-ietf-oauth-rfc8725bis#section-3.14
func checkCompactAlphabet(rawToken string) error {
	for i := range len(rawToken) {
		c := rawToken[i]
		if (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' && c != '_' && c != '.' {
			// The token is a bearer credential; the message names the position only.
			return fmt.Errorf("%w: illegal character at offset %d", ErrUnsupportedTokenFormat, i)
		}
	}

	return nil
}

// sameMediaType reports whether two "typ" values name the same media type under the RFC 7515 §4.1.9
// rules RecipientConfig.Typ describes. A value that does not parse matches nothing.
func sameMediaType(got, want jwa.Typ) bool {
	gotType, gotParams, err := parseTyp(got)
	if err != nil {
		return false
	}

	wantType, wantParams, err := parseTyp(want)

	return err == nil && gotType == wantType && maps.Equal(gotParams, wantParams)
}

// parseTyp splits a "typ" value into its lowercased media type and its parameters. The "application/"
// prefix applies only to a value with no "/" anywhere, so `example;part="1/2"` keeps the bare type.
func parseTyp(typ jwa.Typ) (string, map[string]string, error) {
	value := string(typ)
	if !strings.Contains(value, "/") {
		value = "application/" + value
	}

	return mime.ParseMediaType(value)
}
