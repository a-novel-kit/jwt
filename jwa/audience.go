package jwa

import (
	"bytes"
	"encoding/json"
)

// Audience is the "aud" claim (RFC 7519 §4.1.3): the recipients a token is intended for. It is an
// array of strings, but a single audience serializes as a bare string. The RFC allows that special
// case and most producers emit it, so one-audience tokens stay compatible with peers that expect a
// plain string.
type Audience []string

// MarshalJSON emits a bare string for a single audience and a (possibly empty) array otherwise.
func (aud Audience) MarshalJSON() ([]byte, error) {
	if len(aud) == 1 {
		return json.Marshal(aud[0])
	}

	// A nil slice marshals to null, so an empty audience writes [] itself. As an omitempty field it is
	// left out entirely, so only direct marshaling reaches this branch.
	if len(aud) == 0 {
		return []byte("[]"), nil
	}

	return json.Marshal([]string(aud))
}

// UnmarshalJSON accepts the array form, the single-string special case, and JSON null (which yields
// a nil Audience).
func (aud *Audience) UnmarshalJSON(data []byte) error {
	if bytes.Equal(bytes.TrimSpace(data), []byte("null")) {
		*aud = nil

		return nil
	}

	var single string

	err := json.Unmarshal(data, &single)
	if err == nil {
		*aud = Audience{single}

		return nil
	}

	var many []string

	err = json.Unmarshal(data, &many)
	if err != nil {
		return err
	}

	*aud = many

	return nil
}
