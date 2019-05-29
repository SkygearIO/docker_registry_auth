package httphandler

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/skygeario/docker_registry_auth/pkg/auth"
	"github.com/skygeario/docker_registry_auth/pkg/random"
	"github.com/skygeario/docker_registry_auth/pkg/signing"
	"github.com/skygeario/docker_registry_auth/pkg/token"
)

type Handler struct {
	Issuer     string
	Expiration int64
	CertFile   string
	KeyFile    string
	Key        *signing.Key
	Auth       auth.Auth
}

type Options struct {
	Issuer     string
	Expiration int64
	CertFile   string
	KeyFile    string
	Auth       auth.Auth
}

type Response struct {
	Token       string `json:"token"`
	AccessToken string `json:"access_token"`
}

func New(options Options) (*Handler, error) {
	key, err := signing.NewKey(options.CertFile, options.KeyFile)
	if err != nil {
		return nil, err
	}
	return &Handler{
		Issuer:     options.Issuer,
		Expiration: options.Expiration,
		CertFile:   options.CertFile,
		KeyFile:    options.KeyFile,
		Key:        key,
		Auth:       options.Auth,
	}, nil
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	now := time.Now().Unix()

	authRequest, err := auth.ParseRequest(r)
	if err != nil {
		w.WriteHeader(400)
		return
	}

	scopes, err := h.Auth.AuthenticateAndAuthorize(authRequest)
	if err != nil {
		w.WriteHeader(401)
		return
	}

	jwtID, err := random.RandomString(64)
	if err != nil {
		w.WriteHeader(500)
		return
	}
	access := scopesToAccess(scopes)
	header := token.Header{
		Type:      "JWT",
		Algorithm: h.Key.Algorithm,
		KeyID:     h.Key.KeyID,
	}
	claimSet := token.ClaimSet{
		Issuer:     h.Issuer,
		Subject:    authRequest.Username,
		Audience:   authRequest.Service,
		IssuedAt:   now,
		NotBefore:  now,
		Expiration: now + h.Expiration,
		JwtID:      jwtID,
		Access:     access,
	}

	payload, err := token.MakePayload(header, claimSet)
	if err != nil {
		w.WriteHeader(500)
		return
	}
	signature, err := h.Key.Sign(payload)
	if err != nil {
		w.WriteHeader(500)
		return
	}
	tokenStr := token.MakeToken(payload, signature)
	response := Response{
		Token:       tokenStr,
		AccessToken: tokenStr,
	}
	body, err := json.Marshal(response)
	if err != nil {
		w.WriteHeader(500)
		return
	}
	w.Header().Set("content-type", "application/json")
	w.Header().Set("content-length", strconv.Itoa(len(body)))
	w.WriteHeader(200)
	w.Write(body)
}

func scopesToAccess(scopes []auth.Scope) []token.AccessEntry {
	access := make([]token.AccessEntry, len(scopes))
	for i, scope := range scopes {
		access[i] = token.AccessEntry{
			Type:    scope.Type,
			Name:    scope.Name,
			Actions: scope.Actions,
		}
	}
	return access
}
