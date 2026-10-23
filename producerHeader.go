package jwt

import (
	"encoding/json"
	"fmt"

	"github.com/a-novel-kit/jwt/v2/jwa"
)

// HeaderProducerConfig describes the base JOSE header stamped onto every token: its media types,
// target claims, and the parameters a recipient is required to understand.
type HeaderProducerConfig struct {
	// TargetConfig replicates the token's iss, sub and aud claims in its header (RFC 7519 §5.3), where
	// a recipient reads them before decrypting the token. Each value set here must equal the claim in
	// the payload, or [Producer.Issue] fails with [ErrReplicatedClaimMismatch].
	TargetConfig

	// Typ is the media type of the complete token.
	Typ jwa.Typ
	// CTY is the media type of the secured content, such as jwa.CtyJWT on a nested token.
	CTY jwa.CTY

	// Crit lists custom header parameter names a recipient must process. Every name here has to
	// appear in the custom header, or building the header fails.
	Crit []string
}

// A HeaderProducer builds the base header for each token from a fixed configuration.
type HeaderProducer struct {
	config HeaderProducerConfig
}

// NewHeaderProducer returns a HeaderProducer for the given configuration.
func NewHeaderProducer(config HeaderProducerConfig) *HeaderProducer {
	return &HeaderProducer{config: config}
}

// New builds the base header, folding custom in as the extra header parameters. It fails when a
// name declared in Crit is missing from custom.
func (producer *HeaderProducer) New(custom any) (*jwa.JWH, error) {
	customSerialized, err := json.Marshal(custom)
	if err != nil {
		return nil, fmt.Errorf("(HeaderProducer.New) marshal custom header: %w", err)
	}

	err = CheckCrit(customSerialized, producer.config.Crit)
	if err != nil {
		return nil, fmt.Errorf("(HeaderProducer.New) check crit: %w", err)
	}

	return &jwa.JWH{
		JWHCommon: jwa.JWHCommon{
			Typ:  producer.config.Typ,
			CTY:  producer.config.CTY,
			Alg:  jwa.None,
			Crit: producer.config.Crit,
			Iss:  producer.config.Issuer,
			Sub:  producer.config.Subject,
			Aud:  producer.config.Audience,
		},
		Payload: customSerialized,
	}, nil
}
