package random

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
)

func RandomString(length int) (string, error) {
	if length <= 0 || length%2 != 0 {
		return "", errors.New("length must be positive even integer")
	}
	byteLength := length / 2
	b := make([]byte, byteLength)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
