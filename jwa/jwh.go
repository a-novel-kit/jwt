package jwa

import (
	"encoding/json"

	"github.com/a-novel-kit/jwt/v2/jwa/internal"
)

// Typ is the "typ" (type) header parameter. It declares the media type of the
// complete token, letting an application tell a JWT apart from other objects
// that might appear in the same position. Optional.
//
// https://datatracker.ietf.org/doc/html/rfc7519#section-5.1
type Typ string

func (typ Typ) String() string {
	return string(typ)
}

const (
	// TypJWT marks the object as a JWT.
	TypJWT Typ = "JWT"
	// TypJOSE marks the object as a JWS or JWE in compact serialization.
	TypJOSE Typ = "JOSE"
	// TypJOSEJWT marks a JOSE object carrying a JWT.
	TypJOSEJWT Typ = "JOSE+JWT"
)

// CTY is the "cty" (content type) header parameter. It conveys structural
// information about the token; on a nested JWT it must be set to CtyJWT.
//
// https://datatracker.ietf.org/doc/html/rfc7519#section-5.2
type CTY string

// CtyJWT marks the secured content as itself being a JWT, as required on a
// nested JWT.
const CtyJWT CTY = "JWT"

// JWHCommon holds the JOSE header parameters shared by JWS and JWE tokens. The
// members that apply depend on whether the token is signed or encrypted.
//
// https://datatracker.ietf.org/doc/html/rfc7519#section-5
type JWHCommon struct {
	JWHEmbeddedKey

	JWHKeyAgreement
	JWHPBES2
	JWHAESGCMKW

	J509

	// Typ declares the media type of the complete token. See the Typ constants.
	// https://datatracker.ietf.org/doc/html/rfc7519#section-5.1
	Typ Typ `json:"typ,omitempty"`
	// CTY conveys structural information about the token. On a nested JWT it is
	// CtyJWT.
	// https://datatracker.ietf.org/doc/html/rfc7519#section-5.2
	CTY CTY `json:"cty,omitempty"`

	// Alg identifies the algorithm securing the token. It must be present and
	// understood by the recipient.
	// https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.1
	Alg Alg `json:"alg,omitempty"`
	// Enc identifies the content encryption algorithm of a JWE. Required on
	// encrypted tokens.
	// https://datatracker.ietf.org/doc/html/rfc7516#section-4.1.2
	Enc Enc `json:"enc,omitempty"`
	// Zip names the compression applied to the plaintext before encryption, if
	// any. When set it must live in the protected header.
	// https://datatracker.ietf.org/doc/html/rfc7516#section-4.1.3
	Zip Zip `json:"zip,omitempty"`

	// Crit lists header parameters, introduced by extensions, that the recipient
	// must understand; an unrecognized entry invalidates the token. It must not
	// be empty when present, nor name parameters defined by the base
	// specifications.
	// https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.11
	Crit []string `json:"crit,omitempty"`

	// The following claims may be replicated from an encrypted token's payload
	// into its header, so a recipient can act on them without first decrypting
	// the body. When present, their values must match those in the payload.
	// https://datatracker.ietf.org/doc/html/rfc7519#section-5.3

	// Iss mirrors the payload's issuer claim.
	Iss string `json:"iss,omitempty"`
	// Sub mirrors the payload's subject claim.
	Sub string `json:"sub,omitempty"`
	// Aud mirrors the payload's audience claim. It is a string or an array of strings.
	Aud Audience `json:"aud,omitempty"`
}

// JWHEmbeddedKey carries the header parameters that reference or embed the key
// used to secure the token.
type JWHEmbeddedKey struct {
	// JKU is a URL to a JWK Set holding the public key that verifies the token.
	// The fetch must be integrity-protected.
	// https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.2
	JKU string `json:"jku,omitempty"`
	// JWK embeds the public key that verifies the token.
	// https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.3
	JWK *JWK `json:"jwk,omitempty"`
	// KID hints which key secured the token, letting an originator signal a key
	// change. When keys are matched by identifier, it is compared against a
	// JWK's KID.
	// https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.4
	KID string `json:"kid,omitempty"`
}

// JWHKeyAgreement carries the header parameters of ECDH key agreement
// algorithms such as ECDH-ES.
type JWHKeyAgreement struct {
	// EPK is the ephemeral public key the originator created for key agreement.
	// It holds public key parameters only.
	// https://datatracker.ietf.org/doc/html/rfc7518#section-4.6.1.1
	EPK *JWK `json:"epk,omitempty"`
	// APU is agreement PartyUInfo: base64url-encoded information about the
	// producer, consumed by key agreement.
	// https://datatracker.ietf.org/doc/html/rfc7518#section-4.6.1.2
	APU string `json:"apu,omitempty"`
	// APV is agreement PartyVInfo: base64url-encoded information about the
	// recipient, consumed by key agreement.
	// https://datatracker.ietf.org/doc/html/rfc7518#section-4.6.1.3
	APV string `json:"apv,omitempty"`
}

// JWHPBES2 carries the salt and iteration count of the PBES2 password-based
// key-derivation algorithms.
type JWHPBES2 struct {
	// P2S is the salt input to PBES2.
	P2S string `json:"p2s,omitempty"`
	// P2C is the PBES2 iteration count.
	P2C int `json:"p2c,omitempty"`
}

// JWHAESGCMKW carries the initialization vector and authentication tag of the
// AES GCM key-wrapping algorithms.
type JWHAESGCMKW struct {
	// IV is the initialization vector used to wrap the key.
	IV string `json:"iv,omitempty"`
	// Tag is the authentication tag produced when wrapping the key.
	Tag string `json:"tag,omitempty"`
}

// JWH is a full JOSE header: the common parameters plus an application-specific
// payload. Marshaling merges the two into one JSON object.
type JWH struct {
	JWHCommon

	Payload json.RawMessage
}

func (header JWH) MarshalJSON() ([]byte, error) {
	return internal.MarshalPartial(header.JWHCommon, header.Payload)
}

func (header *JWH) UnmarshalJSON(src []byte) error {
	var err error

	header.JWHCommon, header.Payload, err = internal.UnmarshalPartial[JWHCommon](src)

	return err
}
