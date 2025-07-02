package jwt

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/a-novel-kit/jwt/jwa"
)

type RecipientConfig struct {
	// Sorted list of operations to perform on the token.
	Plugins []RecipientPlugin

	// Set a custom deserializer to decode the token's payload. Uses json.Unmarshal by default.
	Deserializer func(raw []byte, dst any) error
}

type Recipient struct {
	config RecipientConfig
}

func (recipient *Recipient) Consume(ctx context.Context, rawToken string, dst any) error {
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

	if len(header.Crit) > 0 {
		err = CheckCrit(decodedHeader, header.Crit)
		if err != nil {
			return fmt.Errorf("(Recipient.Consume) check crit: %w", err)
		}
	}

	if recipient.config.Deserializer == nil {
		recipient.config.Deserializer = json.Unmarshal
	}

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

func NewRecipient(config RecipientConfig) *Recipient {
	if config.Plugins == nil {
		config.Plugins = []RecipientPlugin{NewDefaultRecipientPlugin()}
	}

	return &Recipient{
		config: config,
	}
}
