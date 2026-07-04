// Package internal provides JSON helpers for payloads that combine a fixed set of
// typed fields with arbitrary caller-defined ones, letting a JWT carry both
// registered claims and custom extensions in a single object.
package internal

import (
	"encoding/json"
	"fmt"
)

// MarshalPartial encodes common and custom into one JSON object, with custom's
// members overriding any that collide with common. A nil or "null" custom yields
// the encoding of common alone.
func MarshalPartial[T any](common T, custom json.RawMessage) ([]byte, error) {
	if custom == nil || string(custom) == "null" {
		return json.Marshal(common)
	}

	serializedCommon, err := json.Marshal(common)
	if err != nil {
		return nil, fmt.Errorf("(MarshalPartial) serialize common: %w", err)
	}

	var merged map[string]json.RawMessage

	err = json.Unmarshal(serializedCommon, &merged)
	if err != nil {
		return nil, fmt.Errorf("(MarshalPartial) convert common to map: %w", err)
	}

	err = json.Unmarshal(custom, &merged)
	if err != nil {
		return nil, fmt.Errorf("(MarshalPartial) convert custom to map: %w", err)
	}

	mergedSerialized, err := json.Marshal(merged)
	if err != nil {
		return nil, fmt.Errorf("(MarshalPartial) serialize merged: %w", err)
	}

	return mergedSerialized, nil
}

// UnmarshalPartial decodes the typed fields of src into a value of type T and
// returns src unchanged alongside it, so the caller can later decode its own
// custom fields from the same bytes.
func UnmarshalPartial[T any](src []byte) (T, json.RawMessage, error) {
	var common T

	err := json.Unmarshal(src, &common)
	if err != nil {
		return common, nil, fmt.Errorf("(UnmarshalPartial) unmarshal common: %w", err)
	}

	return common, src, nil
}
