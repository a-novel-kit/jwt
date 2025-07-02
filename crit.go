package jwt

import (
	"encoding/json"
	"errors"
	"fmt"
)

var ErrMissingCritHeader = errors.New("missing crit header value")

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
