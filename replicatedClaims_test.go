package jwt_test

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/a-novel-kit/jwt/v2"
	"github.com/a-novel-kit/jwt/v2/jwa"
	"github.com/a-novel-kit/jwt/v2/jwe"
	"github.com/a-novel-kit/jwt/v2/jwe/jwek"
	"github.com/a-novel-kit/jwt/v2/jwk"
	"github.com/a-novel-kit/jwt/v2/jws"
)

func TestProducerReplicatedClaims(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name string

		// header is the target the producer replicates in the token header.
		header jwt.TargetConfig
		claims any

		expectErr error
	}{
		{
			name:   "Success/Iss",
			header: jwt.TargetConfig{Issuer: "accounts"},
			claims: map[string]any{"iss": "accounts"},
		},
		{
			name:   "Success/Sub",
			header: jwt.TargetConfig{Subject: "user-123"},
			claims: map[string]any{"sub": "user-123"},
		},
		{
			name:   "Success/Aud",
			header: jwt.TargetConfig{Audience: jwa.Audience{"api"}},
			claims: map[string]any{"aud": "api"},
		},
		{
			// RFC 7519 §4.1.3: a single audience is the same claim as a bare string or as an array.
			name:   "Success/AudArray",
			header: jwt.TargetConfig{Audience: jwa.Audience{"api"}},
			claims: map[string]any{"aud": []string{"api"}},
		},
		{
			// A claim the header leaves out is not compared, while the replicated ones still are.
			name:   "Success/IssNotReplicated",
			header: jwt.TargetConfig{Subject: "user-123", Audience: jwa.Audience{"api"}},
			claims: map[string]any{"iss": "billing", "sub": "user-123", "aud": "api"},
		},
		{
			name:   "Success/SubNotReplicated",
			header: jwt.TargetConfig{Issuer: "accounts", Audience: jwa.Audience{"api"}},
			claims: map[string]any{"iss": "accounts", "sub": "user-456", "aud": "api"},
		},
		{
			name:   "Success/AudNotReplicated",
			header: jwt.TargetConfig{Issuer: "accounts", Subject: "user-123"},
			claims: map[string]any{"iss": "accounts", "sub": "user-123", "aud": "admin"},
		},
		{
			name:      "Error/IssMismatch",
			header:    jwt.TargetConfig{Issuer: "accounts"},
			claims:    map[string]any{"iss": "billing"},
			expectErr: jwt.ErrReplicatedClaimMismatch,
		},
		{
			name:      "Error/SubMismatch",
			header:    jwt.TargetConfig{Subject: "user-123"},
			claims:    map[string]any{"sub": "user-456"},
			expectErr: jwt.ErrReplicatedClaimMismatch,
		},
		{
			name:      "Error/AudMismatch",
			header:    jwt.TargetConfig{Audience: jwa.Audience{"api"}},
			claims:    map[string]any{"aud": []string{"api", "admin"}},
			expectErr: jwt.ErrReplicatedClaimMismatch,
		},
		{
			name:      "Error/MissingFromPayload",
			header:    jwt.TargetConfig{Issuer: "accounts"},
			claims:    map[string]any{"sub": "user-123"},
			expectErr: jwt.ErrReplicatedClaimMismatch,
		},
		{
			name:      "Error/NotAClaimsSet",
			header:    jwt.TargetConfig{Issuer: "accounts"},
			claims:    "accounts",
			expectErr: jwt.ErrReplicatedClaimMismatch,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			producer := jwt.NewProducer(jwt.ProducerConfig{
				Header: jwt.HeaderProducerConfig{TargetConfig: testCase.header},
			})

			_, err := producer.Issue(t.Context(), testCase.claims, nil)
			require.ErrorIs(t, err, testCase.expectErr)
		})
	}
}

func TestRecipientReplicatedClaims(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name string

		// header and payload are the JSON of an unsecured token's two segments.
		header  string
		payload string

		expectErr error
	}{
		{
			name:    "Success/Iss",
			header:  `{"alg":"none","iss":"accounts"}`,
			payload: `{"iss":"accounts"}`,
		},
		{
			name:    "Success/Sub",
			header:  `{"alg":"none","sub":"user-123"}`,
			payload: `{"sub":"user-123"}`,
		},
		{
			name:    "Success/Aud",
			header:  `{"alg":"none","aud":"api"}`,
			payload: `{"aud":"api"}`,
		},
		{
			name:    "Success/AudArray",
			header:  `{"alg":"none","aud":["api"]}`,
			payload: `{"aud":"api"}`,
		},
		{
			name:    "Success/IssNotReplicated",
			header:  `{"alg":"none","sub":"user-123","aud":"api"}`,
			payload: `{"iss":"billing","sub":"user-123","aud":"api"}`,
		},
		{
			name:    "Success/SubNotReplicated",
			header:  `{"alg":"none","iss":"accounts","aud":"api"}`,
			payload: `{"iss":"accounts","sub":"user-456","aud":"api"}`,
		},
		{
			name:    "Success/AudNotReplicated",
			header:  `{"alg":"none","iss":"accounts","sub":"user-123"}`,
			payload: `{"iss":"accounts","sub":"user-123","aud":"admin"}`,
		},
		{
			name:      "Error/IssMismatch",
			header:    `{"alg":"none","iss":"accounts"}`,
			payload:   `{"iss":"billing"}`,
			expectErr: jwt.ErrReplicatedClaimMismatch,
		},
		{
			name:      "Error/SubMismatch",
			header:    `{"alg":"none","sub":"user-123"}`,
			payload:   `{"sub":"user-456"}`,
			expectErr: jwt.ErrReplicatedClaimMismatch,
		},
		{
			name:      "Error/AudMismatch",
			header:    `{"alg":"none","aud":"api"}`,
			payload:   `{"aud":["api","admin"]}`,
			expectErr: jwt.ErrReplicatedClaimMismatch,
		},
		{
			name:      "Error/MissingFromPayload",
			header:    `{"alg":"none","iss":"accounts"}`,
			payload:   `{"sub":"user-123"}`,
			expectErr: jwt.ErrReplicatedClaimMismatch,
		},
		{
			name:      "Error/NotAClaimsSet",
			header:    `{"alg":"none","iss":"accounts"}`,
			payload:   `"accounts"`,
			expectErr: jwt.ErrReplicatedClaimMismatch,
		},
	}

	recipient := jwt.NewRecipient(jwt.RecipientConfig{
		Plugins: []jwt.RecipientPlugin{jwt.NewDefaultRecipientPlugin()},
	})

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			token := base64.RawURLEncoding.EncodeToString([]byte(testCase.header)) + "." +
				base64.RawURLEncoding.EncodeToString([]byte(testCase.payload))

			var claims map[string]any

			err := recipient.Consume(t.Context(), token, &claims)
			require.ErrorIs(t, err, testCase.expectErr)

			if testCase.expectErr != nil {
				require.Nil(t, claims, "a rejected token must not reach the deserializer")

				return
			}

			var expect map[string]any

			require.NoError(t, json.Unmarshal([]byte(testCase.payload), &expect))
			require.Equal(t, expect, claims)
		})
	}
}

func TestReplicatedClaimsRoundTrip(t *testing.T) {
	t.Parallel()

	hmacKey, err := jwk.GenerateHMAC(jwk.HS256)
	require.NoError(t, err)

	aesKey, err := jwk.GenerateAES(jwk.A256GCM)
	require.NoError(t, err)

	plugins := []struct {
		name string

		producer  jwt.ProducerPlugin
		recipient jwt.RecipientPlugin
	}{
		{
			name:      "JWS",
			producer:  jws.NewHMACSigner(hmacKey.Key(), jws.HS256),
			recipient: jws.NewHMACVerifier(hmacKey.Key(), jws.HS256),
		},
		{
			name: "JWE",
			producer: jwe.NewAESGCMEncryption(&jwe.AESGCMEncryptionConfig{
				CEKManager: jwek.NewDirectKeyManager(aesKey.Key()),
			}, jwe.A256GCM),
			recipient: jwe.NewAESGCMDecryption(&jwe.AESGCMDecryptionConfig{
				CEKDecoder: jwek.NewDirectKeyDecoder(&jwek.DirectKeyDecoderConfig{CEK: aesKey.Key()}),
			}, jwe.A256GCM),
		},
	}

	target := jwt.TargetConfig{Issuer: "accounts", Audience: jwa.Audience{"api"}, Subject: "user-123"}

	claims, err := jwt.NewBasicClaims(map[string]any{"role": "admin"}, jwt.ClaimsProducerConfig{TargetConfig: target})
	require.NoError(t, err)

	// tamper runs before the signer or encrypter, which then secures a payload whose issuer differs
	// from the one the header replicates.
	tamper := &fakeProducerPlugin{
		header: func(header *jwa.JWH) *jwa.JWH { return header },
		token: withPayload(base64.RawURLEncoding.EncodeToString(
			[]byte(`{"iss":"billing","sub":"user-123","aud":"api"}`),
		)),
	}

	for _, plugin := range plugins {
		recipient := jwt.NewRecipient(jwt.RecipientConfig{Plugins: []jwt.RecipientPlugin{plugin.recipient}})

		t.Run(plugin.name+"/Success", func(t *testing.T) {
			t.Parallel()

			producer := jwt.NewProducer(jwt.ProducerConfig{
				Header:  jwt.HeaderProducerConfig{TargetConfig: target},
				Plugins: []jwt.ProducerPlugin{plugin.producer},
			})

			token, err := producer.Issue(t.Context(), claims, nil)
			require.NoError(t, err)

			// The header holds the claims in the clear, so they read without verifying or decrypting.
			var header jwa.JWH

			require.NoError(t, json.Unmarshal([]byte(decodeSegment(t, token, 0)), &header))

			replicated := jwt.TargetConfig{Issuer: header.Iss, Audience: header.Aud, Subject: header.Sub}
			require.Equal(t, target, replicated)

			var payload map[string]any

			require.NoError(t, recipient.Consume(t.Context(), token, &payload))
			require.Equal(t, "admin", payload["role"])
		})

		t.Run(plugin.name+"/Error/Tampered", func(t *testing.T) {
			t.Parallel()

			producer := jwt.NewProducer(jwt.ProducerConfig{
				Header:  jwt.HeaderProducerConfig{TargetConfig: target},
				Plugins: []jwt.ProducerPlugin{tamper, plugin.producer},
			})

			token, err := producer.Issue(t.Context(), claims, nil)
			require.NoError(t, err)

			var payload map[string]any

			require.ErrorIs(t, recipient.Consume(t.Context(), token, &payload), jwt.ErrReplicatedClaimMismatch)
		})
	}
}
