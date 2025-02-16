package jwa

import (
	"encoding/json"

	"github.com/samber/lo"

	"github.com/a-novel-kit/jwt/jwa/internal"
)

// JWKCommon represents a key in standard JSOM web key format.
//
// https://datatracker.ietf.org/doc/html/rfc7517#section-4
//
// A JWKCommon is a JSON object that represents a cryptographic key. The
// members of the object represent properties of the key, including its
// value. This JSON object MAY contain whitespace and/or line breaks
// before or after any JSON values or structural characters, in
// accordance with Section 2 of RFC 7159 [RFC7159]. This document
// defines the key parameters that are not algorithm specific and, thus,
// common to many keys.
//
// In addition to the common parameters, each JWKCommon will have members that
// are key type specific. These members represent the parameters of the
// key. Section 6 of the JSON Web Algorithms (JWA) [JWA] specification
// defines multiple kinds of cryptographic keys and their associated
// members.
//
// The member names within a JWKCommon MUST be unique; JWKCommon parsers MUST either
// reject JWKs with duplicate member names or use a JSON parser that
// returns only the lexically last duplicate member name, as specified
// in Section 15.12 (The JSON Object) of ECMAScript 5.1 [ECMAScript].
//
// Additional members can be present in the JWKCommon; if not understood by
// implementations encountering them, they MUST be ignored. Member
// names used for representing key parameters for different keys types
// need not be distinct. Any new member name should either be
// registered in the IANA "JSON Web CEK Parameters" registry established
// by Section 8.1 or be a value that contains a Collision-Resistant
// Name.
type JWKCommon struct {
	// KTY represents the "kty" (key type) parameter in a JSON web key.
	//
	// https://datatracker.ietf.org/doc/html/rfc7518#section-6.1
	//
	// The "kty" (key type) parameter identifies the cryptographic algorithm
	// family used with the key, such as "RSA" or "EC". "kty" values should
	// either be registered in the IANA "JSON Web CEK Types" registry
	// established by [JWA] or be a value that contains a Collision-
	// Resistant Name. The "kty" value is a case-sensitive string. This
	// member MUST be present in a JWKCommon.
	//
	// A list of defined "kty" values can be found in the IANA "JSON Web CEK
	// Types" registry established by [JWA]; the initial contents of this
	// registry are the values defined in Section 6.1 of [JWA].
	//
	// The key type definitions include specification of the members to be
	// used for those key types. Members used with specific "kty" values
	// can be found in the IANA "JSON Web CEK Parameters" registry
	// established by Section 8.1.
	KTY KTY `json:"kty"`
	// Use represents the "use" parameter in a JSON web key.
	//
	// https://datatracker.ietf.org/doc/html/rfc7517#section-4.2
	//
	// The "use" (public key use) parameter identifies the intended use of
	// the public key. The "use" parameter is employed to indicate whether
	// a public key is used for encrypting data or verifying the signature
	// on data.
	//
	// Values defined by this specification are:
	//
	// o "sig" (signature)
	// o "enc" (encryption)
	//
	// Other values MAY be used. The "use" value is a case-sensitive
	// string. Use of the "use" member is OPTIONAL, unless the application
	// requires its presence.
	//
	// When a key is used to wrap another key and a public key use
	// designation for the first key is desired, the "enc" (encryption) key
	// use value is used, since key wrapping is a kind of encryption. The
	// "enc" value is also to be used for public keys used for key agreement
	// operations.
	//
	// Additional "use" (public key use) values can be registered in the
	// IANA "JSON Web CEK Use" registry established by Section 8.2.
	// Registering any extension values used is highly recommended when this
	// specification is used in open environments, in which multiple
	// organizations need to have a common understanding of any extensions
	// used. However, unregistered extension values can be used in closed
	// environments, in which the producing and consuming organization will
	// always be the same.
	Use Use `json:"use,omitempty"`
	// KeyOps represents the "key_ops" parameter in a JSON web key.
	//
	// https://datatracker.ietf.org/doc/html/rfc7517#section-4.3
	//
	// The "key_ops" (key operations) parameter identifies the operation(s)
	// for which the key is intended to be used. The "key_ops" parameter is
	// intended for use cases in which public, private, or symmetric keys
	// may be present.
	//
	// Its value is an array of key operation values. Values defined by
	// this specification are:
	//
	// o "sign" (compute digital signature or MAC)
	// o "verify" (verify digital signature or MAC)
	// o "encrypt" (encrypt content)
	// o "decrypt" (decrypt content and validate decryption, if applicable)
	// o "wrapKey" (encrypt key)
	// o "unwrapKey" (decrypt key and validate decryption, if applicable)
	// o "deriveKey" (derive key)
	// o "deriveBits" (derive bits not to be used as a key)
	//
	// (Note that the "key_ops" values intentionally match the "KeyUsage"
	// values defined in the Web Cryptography API
	// [W3C.CR-WebCryptoAPI-20141211] specification.)
	//
	// Other values MAY be used. The key operation values are case-
	// sensitive strings. Duplicate key operation values MUST NOT be
	// present in the array. Use of the "key_ops" member is OPTIONAL,
	// unless the application requires its presence.
	//
	// Multiple unrelated key operations SHOULD NOT be specified for a key
	// because of the potential vulnerabilities associated with using the
	// same key with multiple algorithms. Thus, the combinations "sign"
	// with "verify", "encrypt" with "decrypt", and "wrapKey" with
	// "unwrapKey" are permitted, but other combinations SHOULD NOT be used.
	//
	// Additional "key_ops" (key operations) values can be registered in the
	// IANA "JSON Web CEK Plugins" registry established by Section 8.3.
	// The same considerations about registering extension values apply to
	// the "key_ops" member as do for the "use" member.
	//
	// The "use" and "key_ops" JWKCommon members SHOULD NOT be used together;
	// however, if both are used, the information they convey MUST be
	// consistent. Applications should specify which of these members they
	// use, if either is to be used by the application.
	KeyOps []KeyOp `json:"key_ops,omitempty"`
	// Alg represents the algorithm used in a JSON web key.
	//
	// https://datatracker.ietf.org/doc/html/rfc7517#section-4.4
	//
	// The "alg" (algorithm) parameter identifies the algorithm intended for
	// use with the key. The values used should either be registered in the
	// IANA "JSON Web Signature and Encryption Algorithms" registry
	// established by [JWA] or be a value that contains a Collision-
	// Resistant Name. The "alg" value is a case-sensitive ASCII string.
	// Use of this member is OPTIONAL.
	Alg Alg `json:"alg,omitempty"`
	// KID (Key ID) JWKCommon Parameter.
	//
	// https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.4
	//
	// The "kid" (key ID) JWKCommon Parameter is a hint indicating which key
	// was used to secure the JWS. This parameter allows originators to
	// explicitly signal a change of key to recipients. The structure of
	// the "kid" value is unspecified. Its value MUST be a case-sensitive
	// string. Use of this JWKCommon Parameter is OPTIONAL.
	//
	// When used with a JWKCommon, the "kid" value is used to match a JWKCommon "kid"
	// parameter value.
	KID string `json:"kid,omitempty"`

	J509
}

// MatchPreset is used to check is the description of a JSON Web Key matches the expected preset.
func (jwk JWKCommon) MatchPreset(other JWKCommon) bool {
	for _, keyOp := range other.KeyOps {
		if !lo.Contains(jwk.KeyOps, keyOp) {
			return false
		}
	}

	return jwk.KTY == other.KTY &&
		jwk.Use == other.Use &&
		jwk.Alg == other.Alg
}

// JWK represents a JSON Web Key, with both generic and key-specific information.
type JWK struct {
	JWKCommon
	Payload json.RawMessage
}

func (key JWK) MarshalJSON() ([]byte, error) {
	return internal.MarshalPartial(key.JWKCommon, key.Payload)
}

func (key *JWK) UnmarshalJSON(src []byte) error {
	var err error
	key.JWKCommon, key.Payload, err = internal.UnmarshalPartial[JWKCommon](src)

	return err
}
