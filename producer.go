package jwt

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
)

type ProducerConfig struct {
	Header HeaderProducerConfig

	// Sorted list of operations to perform on the token.
	Plugins []ProducerPlugin
	// StaticPlugins to apply to the token. Those are executed BEFORE the regular operations.
	StaticPlugins []ProducerStaticPlugin
}

type Producer struct {
	config ProducerConfig
	header *HeaderProducer
}

func (producer *Producer) Issue(ctx context.Context, customClaims, customHeader any) (string, error) {
	header, err := producer.header.New(customHeader)
	if err != nil {
		return "", fmt.Errorf("(Issuer.Issue) issue header: %w", err)
	}

	// Transform static operations first.
	for _, operation := range producer.config.StaticPlugins {
		header, err = operation.Header(ctx, header)
		if err != nil {
			return "", fmt.Errorf("(Issuer.Issue) static operation: %w", err)
		}
	}

	// Each operation describes itself in the header.
	for _, operation := range producer.config.Plugins {
		header, err = operation.Header(ctx, header)
		if err != nil {
			return "", fmt.Errorf("(Issuer.Issue) operation: %w", err)
		}
	}

	claimsSerialized, err := json.Marshal(customClaims)
	if err != nil {
		return "", fmt.Errorf("(Issuer.Issue) serialize claims: %w", err)
	}

	claimsEncoded := base64.RawURLEncoding.EncodeToString(claimsSerialized)

	headerSerialized, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("(Issuer.Issue) serialize header: %w", err)
	}

	headerEncoded := base64.RawURLEncoding.EncodeToString(headerSerialized)

	token := headerEncoded + "." + claimsEncoded

	// Transform transformations to the token.
	for _, operation := range producer.config.Plugins {
		token, err = operation.Transform(ctx, header, token)
		if err != nil {
			return "", fmt.Errorf("(Issuer.Issue) operation: %w", err)
		}
	}

	return token, nil
}

func NewProducer(config ProducerConfig) *Producer {
	return &Producer{
		config: config,
		header: NewHeaderProducer(config.Header),
	}
}
