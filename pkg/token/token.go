package token

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

const Separator string = "."

type Header struct {
	Type      string `json:"typ"`
	Algorithm string `json:"alg"`
	KeyID     string `json:"kid"`
}

type ClaimSet struct {
	Issuer     string        `json:"iss"`
	Subject    string        `json:"sub"`
	Audience   string        `json:"aud"`
	Expiration int64         `json:"exp"`
	NotBefore  int64         `json:"nbf"`
	IssuedAt   int64         `json:"iat"`
	JwtID      string        `json:"jti"`
	Access     []AccessEntry `json:"access"`
}

type AccessEntry struct {
	Type    string   `json:"type"`
	Name    string   `json:"name"`
	Actions []string `json:"actions"`
}

func MakePayload(header Header, claimSet ClaimSet) ([]byte, error) {
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return nil, err
	}
	claimSetJSON, err := json.Marshal(claimSet)
	if err != nil {
		return nil, err
	}
	s := fmt.Sprintf("%s%s%s", Base64Encode(headerJSON), Separator, Base64Encode(claimSetJSON))
	return []byte(s), nil
}

func MakeToken(payload []byte, signature []byte) string {
	return fmt.Sprintf("%s%s%s", string(payload), Separator, Base64Encode(signature))
}

func Base64Encode(b []byte) string {
	// https://docs.docker.com/registry/spec/auth/jwt/
	// urlsafe encoding without trailing =
	return strings.TrimRight(base64.URLEncoding.EncodeToString(b), "=")
}
