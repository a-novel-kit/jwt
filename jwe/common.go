package jwe

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/a-novel-kit/jwt/v2"
	"github.com/a-novel-kit/jwt/v2/jwa"
)

// ErrInvalidSecret is returned when the content encryption key resolved for a token
// has the wrong length for the chosen algorithm, or when an authentication tag fails
// to verify during decryption. A failed tag also matches [jwt.ErrTokenRejected]. A key
// of the wrong length does not, since a misconfigured direct key produces one.
var ErrInvalidSecret = errors.New("invalid secret")

// ErrInvalidToken is returned when an encrypted token is structurally malformed, such as an
// initialization vector or padding of the wrong length. It matches [jwt.ErrTokenRejected].
var ErrInvalidToken = fmt.Errorf("%w: invalid token", jwt.ErrTokenRejected)

// segmentEncoding decodes the encrypted key, IV, tag and cipher text segments of a received token.
// Strict refuses unused trailing bits that are not zero, so each segment has a single encoding and a
// token decrypts only in the form it was issued in. The header needs no such check: it is the
// additional data the authentication tag covers as written.
var segmentEncoding = base64.RawURLEncoding.Strict()

// aad builds the additional data bound into the JWE integrity check, which AES-GCM takes as its AAD
// and AES-CBC-HMAC folds into its HMAC. It is the encoded protected header (RFC 7516 §5.1), followed
// by ".BASE64URL(additionalData)" when additionalData is set, as the JWE JSON serialization does.
// Both encryption and decryption derive it from the transmitted header, so a tampered header fails
// the integrity check.
func aad(encodedHeader string, additionalData []byte) []byte {
	if len(additionalData) == 0 {
		return []byte(encodedHeader)
	}

	out := make([]byte, 0, len(encodedHeader)+1+base64.RawURLEncoding.EncodedLen(len(additionalData)))
	out = append(out, encodedHeader...)
	out = append(out, '.')

	return base64.RawURLEncoding.AppendEncode(out, additionalData)
}

// sealFunc encrypts plainText under cek and binds aad into the authentication tag. It returns the
// token segments that carry the result.
type sealFunc func(cek, plainText, aad []byte) (iv, cipherText, tag []byte, err error)

// contentEncryption holds the steps the AES-CBC-HMAC and AES-GCM producer plugins share. Each
// plugin embeds it and passes its own sealFunc.
type contentEncryption struct {
	cekManager     CEKManager
	additionalData []byte

	enc jwa.Enc
	// cekLen is the content encryption key length enc takes, in bytes.
	cekLen int
}

// Header sets the token's "enc" and lets the CEKManager add its key management members, such as
// "alg".
func (enc *contentEncryption) Header(ctx context.Context, header *jwa.JWH) (*jwa.JWH, error) {
	if header.Enc != "" {
		return nil, fmt.Errorf("(contentEncryption.Header) %w: enc field already set", jwt.ErrConflictingHeader)
	}

	header, err := enc.cekManager.SetHeader(ctx, header)
	if err != nil {
		return nil, fmt.Errorf("(contentEncryption.Header) set key derivation header: %w", err)
	}

	// A CEKManager may pin the token to one enc, which this plugin must then match.
	if header.Enc != "" && header.Enc != enc.enc {
		return nil, fmt.Errorf(
			"(contentEncryption.Header) %w: cek manager is incompatible with the current encryption algorithm: "+
				"expected %s, got %s",
			jwt.ErrConflictingHeader, enc.enc, header.Enc,
		)
	}

	header.Enc = enc.enc

	return header, nil
}

// encrypt runs key management for one token, seals its payload, and returns the JWE compact token.
// Key management can add per-token parameters to the header, such as an ephemeral key. The
// protected header is therefore encoded after key management runs (RFC 7516 §5.1), and the
// producer's serialized header is discarded.
func (enc *contentEncryption) encrypt(
	ctx context.Context, header *jwa.JWH, rawToken string, seal sealFunc,
) (string, error) {
	token, err := (&jwt.RawTokenDecoder{}).Decode(rawToken)
	if err != nil {
		return "", fmt.Errorf("(contentEncryption.encrypt) split token: %w", err)
	}

	plainText, err := base64.RawURLEncoding.DecodeString(token.Payload)
	if err != nil {
		return "", fmt.Errorf("(contentEncryption.encrypt) decode payload: %w", err)
	}

	cek, err := enc.cekManager.ComputeCEK(ctx, header)
	if err != nil {
		return "", fmt.Errorf("(contentEncryption.encrypt) compute cek: %w", err)
	}

	if len(cek) != enc.cekLen {
		return "", fmt.Errorf(
			"(contentEncryption.encrypt) %w: cek has length %d, expected %d", ErrInvalidSecret, len(cek), enc.cekLen,
		)
	}

	encryptedKey, err := enc.cekManager.EncryptCEK(ctx, header, cek)
	if err != nil {
		return "", fmt.Errorf("(contentEncryption.encrypt) encrypt key: %w", err)
	}

	serializedHeader, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("(contentEncryption.encrypt) serialize header: %w", err)
	}

	encodedHeader := base64.RawURLEncoding.EncodeToString(serializedHeader)

	iv, cipherText, tag, err := seal(cek, plainText, aad(encodedHeader, enc.additionalData))
	if err != nil {
		return "", fmt.Errorf("(contentEncryption.encrypt) %w", err)
	}

	return jwt.EncryptedToken{
		Header:     encodedHeader,
		EncKey:     base64.RawURLEncoding.EncodeToString(encryptedKey),
		IV:         base64.RawURLEncoding.EncodeToString(iv),
		CipherText: base64.RawURLEncoding.EncodeToString(cipherText),
		Tag:        base64.RawURLEncoding.EncodeToString(tag),
	}.String(), nil
}

// openFunc decrypts segments under cek and checks their authentication tag against aad. The
// segments come from the token, so it checks every length a cipher call panics on before making the
// call.
type openFunc func(cek []byte, segments *encryptedSegments, aad []byte) ([]byte, error)

// contentDecryption holds the steps the AES-CBC-HMAC and AES-GCM recipient plugins share. Each
// plugin embeds it and passes its own openFunc.
type contentDecryption struct {
	cekDecoder     CEKDecoder
	additionalData []byte

	enc jwa.Enc
	// cekLen is the content encryption key length enc takes, in bytes.
	cekLen int
}

// decrypt checks that the token names this plugin's enc, recovers its content encryption key, and
// opens its payload.
func (dec *contentDecryption) decrypt(
	ctx context.Context, header *jwa.JWH, rawToken string, open openFunc,
) ([]byte, error) {
	if header.Enc != dec.enc {
		return nil, fmt.Errorf(
			"(contentDecryption.decrypt) %w: invalid enc %s, expected %s",
			jwt.ErrMismatchRecipientPlugin, header.Enc, dec.enc,
		)
	}

	// This package performs no decompression, so it refuses a compressed payload.
	if header.Zip != "" {
		return nil, fmt.Errorf(
			"(contentDecryption.decrypt) %w: unsupported zip %s", jwt.ErrUnsupportedTokenFormat, header.Zip,
		)
	}

	token, err := (&jwt.EncryptedTokenDecoder{}).Decode(rawToken)
	if err != nil {
		return nil, fmt.Errorf("(contentDecryption.decrypt) split token: %w", err)
	}

	segments, err := decodeSegments(token)
	if err != nil {
		return nil, fmt.Errorf("(contentDecryption.decrypt) %w", err)
	}

	cek, err := dec.cekDecoder.ComputeCEK(ctx, header, segments.encryptedKey)
	if err != nil {
		return nil, fmt.Errorf("(contentDecryption.decrypt) get secret key: %w", err)
	}

	if len(cek) != dec.cekLen {
		return nil, fmt.Errorf(
			"(contentDecryption.decrypt) %w: cek has length %d, expected %d", ErrInvalidSecret, len(cek), dec.cekLen,
		)
	}

	plainText, err := open(cek, segments, aad(token.Header, dec.additionalData))
	if err != nil {
		return nil, fmt.Errorf("(contentDecryption.decrypt) %w", err)
	}

	return plainText, nil
}

// encryptedSegments holds the decoded binary segments of a JWE compact token.
type encryptedSegments struct {
	encryptedKey []byte
	iv           []byte
	tag          []byte
	cipherText   []byte
}

// decodeSegments decodes the base64url segments of a JWE compact token. An empty encrypted key
// segment, which direct encryption and key agreement produce, stays nil.
func decodeSegments(token *jwt.EncryptedToken) (*encryptedSegments, error) {
	var (
		segments encryptedSegments
		err      error
	)

	if len(token.EncKey) > 0 {
		segments.encryptedKey, err = segmentEncoding.DecodeString(token.EncKey)
		if err != nil {
			return nil, fmt.Errorf("%w: decode enc key: %w", jwt.ErrUnsupportedTokenFormat, err)
		}
	}

	segments.iv, err = segmentEncoding.DecodeString(token.IV)
	if err != nil {
		return nil, fmt.Errorf("%w: decode iv: %w", jwt.ErrUnsupportedTokenFormat, err)
	}

	segments.tag, err = segmentEncoding.DecodeString(token.Tag)
	if err != nil {
		return nil, fmt.Errorf("%w: decode tag: %w", jwt.ErrUnsupportedTokenFormat, err)
	}

	segments.cipherText, err = segmentEncoding.DecodeString(token.CipherText)
	if err != nil {
		return nil, fmt.Errorf("%w: decode cipher text: %w", jwt.ErrUnsupportedTokenFormat, err)
	}

	return &segments, nil
}
