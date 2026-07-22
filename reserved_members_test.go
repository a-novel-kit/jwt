package jwt_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/a-novel-kit/jwt/v2"
	"github.com/a-novel-kit/jwt/v2/jwa"
)

// End-to-end cover for the custom-payload override, at the level a consumer meets it. A caller that
// routes semi-trusted data into customClaims or customHeader reaches an override no guard can see:
// each signer refuses a header that already carries an alg by reading the struct field, and the
// override lands later, inside MarshalJSON.

// signingPlugin stands in for a signer: it stamps the algorithm on the header, which is exactly the
// value a custom header used to be able to replace.
type signingPlugin struct{ alg jwa.Alg }

func (plugin *signingPlugin) Header(_ context.Context, header *jwa.JWH) (*jwa.JWH, error) {
	header.Alg = plugin.alg

	return header, nil
}

func (plugin *signingPlugin) Transform(_ context.Context, _ *jwa.JWH, token string) (string, error) {
	return token + ".signature", nil
}

func newSigningProducer(alg jwa.Alg) *jwt.Producer {
	return jwt.NewProducer(jwt.ProducerConfig{
		Plugins: []jwt.ProducerPlugin{&signingPlugin{alg: alg}},
	})
}

func TestIssueRejectsAReservedCustomHeader(t *testing.T) {
	t.Parallel()

	producer := newSigningProducer(jwa.HS256)

	_, err := producer.Issue(t.Context(), map[string]any{"role": "user"}, map[string]any{
		"alg": "none",
		"kid": "attacker-kid",
	})

	require.ErrorIs(t, err, jwa.ErrReservedMember)
	require.ErrorContains(t, err, "alg")
	require.ErrorContains(t, err, "kid")
}

func TestIssueKeepsAnUnreservedCustomHeader(t *testing.T) {
	t.Parallel()

	producer := newSigningProducer(jwa.HS256)

	token, err := producer.Issue(t.Context(), map[string]any{"role": "user"}, map[string]any{
		"myapp-tenant": "acme",
	})
	require.NoError(t, err)

	header := decodeSegment(t, token, 0)
	require.JSONEq(t, `{"alg":"HS256","myapp-tenant":"acme"}`, header)
}

func TestIssueRejectsReservedCustomClaims(t *testing.T) {
	t.Parallel()

	for _, name := range []string{"exp", "sub", "iss", "aud", "jti", "nbf", "iat"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			claims, err := jwt.NewBasicClaims(
				map[string]any{name: "injected"},
				jwt.ClaimsProducerConfig{TTL: time.Hour},
			)
			require.NoError(t, err)

			// NewBasicClaims only stores the payload; the merge happens when the
			// claims are encoded, which is where every earlier check has already
			// finished.
			_, err = json.Marshal(claims)
			require.ErrorIs(t, err, jwa.ErrReservedMember)
			require.ErrorContains(t, err, name)
		})
	}
}

func TestIssueKeepsUnreservedCustomClaims(t *testing.T) {
	t.Parallel()

	claims, err := jwt.NewBasicClaims(
		map[string]any{"role": "admin"},
		jwt.ClaimsProducerConfig{TTL: time.Hour},
	)
	require.NoError(t, err)

	producer := newSigningProducer(jwa.HS256)

	token, err := producer.Issue(t.Context(), claims, nil)
	require.NoError(t, err)

	var payload map[string]any

	require.NoError(t, json.Unmarshal([]byte(decodeSegment(t, token, 1)), &payload))
	require.Equal(t, "admin", payload["role"])
	require.NotZero(t, payload["exp"], "the producer's own exp must survive")
}

func decodeSegment(t *testing.T, token string, index int) string {
	t.Helper()

	segments := strings.Split(token, ".")
	require.Greater(t, len(segments), index)

	raw, err := base64.RawURLEncoding.DecodeString(segments[index])
	require.NoError(t, err)

	return string(raw)
}
