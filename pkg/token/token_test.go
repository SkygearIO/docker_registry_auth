package token

import (
	"bytes"
	"testing"
)

func TestMakePayload(t *testing.T) {
	header := Header{
		Type:      "JWT",
		Algorithm: "ES256",
		KeyID:     "PYYO:TEWU:V7JH:26JV:AQTZ:LJC3:SXVJ:XGHA:34F2:2LAQ:ZRMK:Z7Q6",
	}
	claimSet := ClaimSet{
		Issuer:     "auth.docker.com",
		Subject:    "johndoe",
		Audience:   "registry.docker.com",
		Expiration: 1415387315,
		NotBefore:  1415387015,
		IssuedAt:   1415387015,
		JwtID:      "tYJCO1c6cnyy7kAn0c7rKPgbV1H1bFws",
		Access: []AccessEntry{
			AccessEntry{
				Type:    "repository",
				Name:    "janedoe/myapp",
				Actions: []string{"pull", "push"},
			},
		},
	}
	payload, err := MakePayload(header, claimSet)
	if err != nil {
		t.Errorf("error: %v\n", err)
	}
	expected := []byte("eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiIsImtpZCI6IlBZWU86VEVXVTpWN0pIOjI2SlY6QVFUWjpMSkMzOlNYVko6WEdIQTozNEYyOjJMQVE6WlJNSzpaN1E2In0.eyJpc3MiOiJhdXRoLmRvY2tlci5jb20iLCJzdWIiOiJqb2huZG9lIiwiYXVkIjoicmVnaXN0cnkuZG9ja2VyLmNvbSIsImV4cCI6MTQxNTM4NzMxNSwibmJmIjoxNDE1Mzg3MDE1LCJpYXQiOjE0MTUzODcwMTUsImp0aSI6InRZSkNPMWM2Y255eTdrQW4wYzdyS1BnYlYxSDFiRndzIiwiYWNjZXNzIjpbeyJ0eXBlIjoicmVwb3NpdG9yeSIsIm5hbWUiOiJqYW5lZG9lL215YXBwIiwiYWN0aW9ucyI6WyJwdWxsIiwicHVzaCJdfV19")
	if !bytes.Equal(payload, expected) {
		t.Errorf("actual: %v\n", string(payload))
	}
}
