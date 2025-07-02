package generators

import (
	"crypto/rand"
	"fmt"
)

// NewOct generates a new random byte sequence for symmetric key algorithms.
func NewOct(keySize int) ([]byte, error) {
	key := make([]byte, keySize)

	_, err := rand.Read(key)
	if err != nil {
		return nil, fmt.Errorf("(aesGenerator.Generate) generate key: %w", err)
	}

	return key, nil
}
