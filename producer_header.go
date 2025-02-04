package jwt

import (
	"encoding/json"
	"fmt"

	"github.com/a-novel-kit/jwt/jwa"
)

type HeaderProducerConfig struct {
	Typ jwa.Typ
	CTY jwa.CTY

	Crit []string

	TargetConfig
}

type HeaderProducer struct {
	config HeaderProducerConfig
}

func (producer *HeaderProducer) New(custom any) (*jwa.JWH, error) {
	customSerialized, err := json.Marshal(custom)
	if err != nil {
		return nil, fmt.Errorf("(HeaderProducer.NewHeader) marshal custom header: %w", err)
	}

	if err := CheckCrit(customSerialized, producer.config.Crit); err != nil {
		return nil, fmt.Errorf("(HeaderProducer.NewHeader) check crit: %w", err)
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

func NewHeaderProducer(config HeaderProducerConfig) *HeaderProducer {
	return &HeaderProducer{config: config}
}
