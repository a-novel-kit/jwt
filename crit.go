package jwt

import (
	"encoding/json"
	"errors"
	"fmt"
)

// ErrMissingCritHeader is returned when the "crit" list names a header parameter that is absent
// from the header being checked.
var ErrMissingCritHeader = errors.New("missing crit header value")

// ErrUnsupportedCritHeader is returned when the "crit" list names an extension the recipient is not
// configured to understand, or a registered JOSE parameter that a producer must not mark critical.
var ErrUnsupportedCritHeader = errors.New("unsupported crit header")

// reservedHeaderParams are the header parameters defined by the JWS/JWE/JWA/JWT specifications. A
// producer must not mark any of them critical (RFC 7515 §4.1.11), so a recipient rejects a crit list
// that names one; otherwise "crit" could smuggle contradictory processing rules.
var reservedHeaderParams = map[string]bool{
	"alg": true, "jku": true, "jwk": true, "kid": true,
	"x5u": true, "x5c": true, "x5t": true, "x5t#S256": true,
	"typ": true, "cty": true, "crit": true,
	"enc": true, "zip": true,
	"epk": true, "apu": true, "apv": true,
	"iv": true, "tag": true, "p2s": true, "p2c": true,
	"iss": true, "sub": true, "aud": true,
}

// CheckCrit verifies that every parameter named in crit is present in data, the JSON object of
// extra header parameters. The JOSE "crit" list marks parameters a recipient is required to
// understand, so a listed name with no matching value makes the token invalid. An empty crit list
// passes unconditionally.
func CheckCrit(data json.RawMessage, crit []string) error {
	if len(crit) == 0 {
		return nil
	}

	if data == nil {
		return fmt.Errorf("%w: no extra header", ErrMissingCritHeader)
	}

	var dataMap map[string]json.RawMessage

	err := json.Unmarshal(data, &dataMap)
	if err != nil {
		return fmt.Errorf("unmarshal custom header: %w", err)
	}

	for _, c := range crit {
		if _, ok := dataMap[c]; !ok {
			return fmt.Errorf("%w: %s", ErrMissingCritHeader, c)
		}
	}

	return nil
}

// CheckCritUnderstood enforces the recipient's "crit" obligation (RFC 7515 §4.1.11): the token is
// invalid unless every listed critical extension is both understood by the recipient and present in
// the header. understood is the set of extension names the recipient is configured to process; any
// crit entry outside it, or one naming a registered JOSE parameter, is rejected. data is the decoded
// header. A present but empty crit list is itself invalid, so callers pass crit only when the member
// is present.
func CheckCritUnderstood(data json.RawMessage, crit, understood []string) error {
	// The caller invokes this only when the member is present, so an empty slice is the "crit":[]
	// form RFC 7515 §4.1.11 forbids.
	if len(crit) == 0 {
		return fmt.Errorf("%w: crit list must not be empty", ErrUnsupportedCritHeader)
	}

	understoodSet := make(map[string]struct{}, len(understood))
	for _, name := range understood {
		understoodSet[name] = struct{}{}
	}

	for _, name := range crit {
		if reservedHeaderParams[name] {
			return fmt.Errorf("%w: %q is a registered parameter and must not be critical", ErrUnsupportedCritHeader, name)
		}

		if _, ok := understoodSet[name]; !ok {
			return fmt.Errorf("%w: %q is not understood by this recipient", ErrUnsupportedCritHeader, name)
		}
	}

	// Every understood critical extension must also be present in the header.
	return CheckCrit(data, crit)
}
