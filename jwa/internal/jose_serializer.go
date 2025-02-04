package internal

import (
	"encoding/json"
	"fmt"
)

func MarshalJSONJose[T any](common T, custom json.RawMessage) ([]byte, error) {
	if custom == nil || string(custom) == "null" {
		return json.Marshal(common)
	}

	serializedCommon, err := json.Marshal(common)
	if err != nil {
		return nil, fmt.Errorf("(MarshalJSONJose) serialize common: %w", err)
	}

	var merged map[string]json.RawMessage

	if err := json.Unmarshal(serializedCommon, &merged); err != nil {
		return nil, fmt.Errorf("(MarshalJSONJose) convert common to map: %w", err)
	}
	if err := json.Unmarshal(custom, &merged); err != nil {
		return nil, fmt.Errorf("(MarshalJSONJose) convert custom to map: %w", err)
	}

	mergedSerialized, err := json.Marshal(merged)
	if err != nil {
		return nil, fmt.Errorf("(MarshalJSONJose) serialize merged: %w", err)
	}

	return mergedSerialized, nil
}

func UnmarshalJSONJose[T any](src []byte) (T, json.RawMessage, error) {
	var common T

	if err := json.Unmarshal(src, &common); err != nil {
		return common, nil, fmt.Errorf("(UnmarshalJSONJose) unmarshal common: %w", err)
	}

	return common, src, nil
}
