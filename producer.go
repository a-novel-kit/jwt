package jwt

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
)

// ProducerConfig configures a Producer: the base header shared by every token and the ordered
// plugins that sign, encrypt, or otherwise transform each one.
type ProducerConfig struct {
	Header HeaderProducerConfig

	// Plugins run in order. Each describes its operation in the header, then transforms the
	// serialized token to match.
	Plugins []ProducerPlugin
	// StaticPlugins run before Plugins and only amend the header. They produce intermediate
	// header values, such as a derived key, that a transforming plugin later consumes.
	StaticPlugins []ProducerStaticPlugin
}

// A Producer issues signed or encrypted JWTs from a fixed configuration. Create one with
// NewProducer and reuse it across tokens.
type Producer struct {
	config ProducerConfig
	header *HeaderProducer
}

// NewProducer returns a Producer for the given configuration.
func NewProducer(config ProducerConfig) *Producer {
	return &Producer{
		config: config,
		header: NewHeaderProducer(config.Header),
	}
}

// Issue builds a token from customClaims and customHeader, then runs the configured plugins to
// produce the final serialized JWT.
func (producer *Producer) Issue(ctx context.Context, customClaims, customHeader any) (string, error) {
	header, err := producer.header.New(customHeader)
	if err != nil {
		return "", fmt.Errorf("(Producer.Issue) issue header: %w", err)
	}

	// Static plugins amend the header before the transforming plugins see it.
	for _, operation := range producer.config.StaticPlugins {
		header, err = operation.Header(ctx, header)
		if err != nil {
			return "", fmt.Errorf("(Producer.Issue) static operation: %w", err)
		}
	}

	// Each plugin records its algorithm and parameters in the header.
	for _, operation := range producer.config.Plugins {
		header, err = operation.Header(ctx, header)
		if err != nil {
			return "", fmt.Errorf("(Producer.Issue) operation: %w", err)
		}
	}

	claimsSerialized, err := json.Marshal(customClaims)
	if err != nil {
		return "", fmt.Errorf("(Producer.Issue) serialize claims: %w", err)
	}

	claimsEncoded := base64.RawURLEncoding.EncodeToString(claimsSerialized)

	headerSerialized, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("(Producer.Issue) serialize header: %w", err)
	}

	headerEncoded := base64.RawURLEncoding.EncodeToString(headerSerialized)

	token := headerEncoded + "." + claimsEncoded

	// With the header settled and serialized, each plugin applies its transformation to the token.
	for _, operation := range producer.config.Plugins {
		token, err = operation.Transform(ctx, header, token)
		if err != nil {
			return "", fmt.Errorf("(Producer.Issue) operation: %w", err)
		}
	}

	return token, nil
}
