package internal

import (
	"encoding/json"
	"fmt"
)

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

func UnmarshalPartial[T any](src []byte) (T, json.RawMessage, error) {
	var common T

	err := json.Unmarshal(src, &common)
	if err != nil {
		return common, nil, fmt.Errorf("(UnmarshalPartial) unmarshal common: %w", err)
	}

	return common, src, nil
}
