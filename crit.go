package jwt

import (
	"encoding/json"
	"errors"
	"fmt"
)

// ErrMissingCritHeader is returned when the "crit" list names a header parameter that is absent
// from the header being checked.
var ErrMissingCritHeader = errors.New("missing crit header value")

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
