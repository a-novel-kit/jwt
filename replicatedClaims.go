package jwt

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	"github.com/a-novel-kit/jwt/v2/jwa"
)

// ErrReplicatedClaimMismatch is returned by [Producer.Issue] and [Recipient.Consume] when a token's
// header replicates its iss, sub or aud claim with a value its payload does not hold. RFC 7519 §5.3
// lets a header copy these claims, so a recipient can act on them before decrypting the payload.
// Each copy must then equal the payload's claim.
var ErrReplicatedClaimMismatch = errors.New("replicated claim mismatch")

// checkReplicatedClaims compares each claim the header replicates with the same claim in payload, the
// JSON claims set. A claim the header leaves out is not compared, so a header without replicated
// claims accepts any payload, including one that is not a claims set.
func checkReplicatedClaims(header *jwa.JWH, payload []byte) error {
	if header.Iss == "" && header.Sub == "" && len(header.Aud) == 0 {
		return nil
	}

	var claims jwa.Claims

	err := json.Unmarshal(payload, &claims)
	if err != nil {
		return fmt.Errorf("%w: decode payload claims: %w", ErrReplicatedClaimMismatch, err)
	}

	// The messages name the claim only, since a received token is untrusted input.
	switch {
	case header.Iss != "" && header.Iss != claims.Iss:
		return fmt.Errorf("%w: iss", ErrReplicatedClaimMismatch)
	case header.Sub != "" && header.Sub != claims.Sub:
		return fmt.Errorf("%w: sub", ErrReplicatedClaimMismatch)
	case len(header.Aud) > 0 && !slices.Equal(header.Aud, claims.Aud):
		return fmt.Errorf("%w: aud", ErrReplicatedClaimMismatch)
	}

	return nil
}
