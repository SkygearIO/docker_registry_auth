package httphandler

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/skygeario/docker_registry_auth/pkg/auth"
	"github.com/skygeario/docker_registry_auth/pkg/random"
	"github.com/skygeario/docker_registry_auth/pkg/signing"
	"github.com/skygeario/docker_registry_auth/pkg/token"
)

type Options struct {
	Issuer     string
	Expiration int64
	CertFile   string
	KeyFile    string
	Key        *signing.Key
	LogLevel   logrus.Level
	Logger     *logrus.Logger
}

type Response struct {
	Token       string `json:"token"`
	AccessToken string `json:"access_token"`
}

func NewOptions(options Options) (Options, error) {
	key, err := signing.NewKey(options.CertFile, options.KeyFile)
	if err != nil {
		return options, err
	}
	options.Key = key

	logger := logrus.New()
	logger.SetLevel(options.LogLevel)
	options.Logger = logger

	return options, nil
}

func NewHandler(options Options, auther auth.Auth) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logger := options.Logger
		now := time.Now().Unix()

		logger.Debugf("%v %v %v", r.Method, r.URL.String(), r.Proto)
		for name, values := range r.Header {
			for _, value := range values {
				logger.Debugf("%v: %v", name, value)
			}
		}

		authRequest, err := auth.ParseRequest(r)
		if err != nil {
			w.WriteHeader(400)
			logger.WithError(err).Debug("auth.ParseRequest")
			return
		}

		scopes, err := auther.AuthenticateAndAuthorize(authRequest)
		if err != nil {
			w.WriteHeader(401)
			logger.WithError(err).Debug("auth.AuthenticateAndAuthorize")
			return
		}

		jwtID, err := random.RandomString(64)
		if err != nil {
			w.WriteHeader(500)
			logger.WithError(err).Debug("random.RandomString")
			return
		}
		access := scopesToAccess(scopes)
		header := token.Header{
			Type:      "JWT",
			Algorithm: options.Key.Algorithm,
			KeyID:     options.Key.KeyID,
		}
		claimSet := token.ClaimSet{
			Issuer:     options.Issuer,
			Subject:    authRequest.Username,
			Audience:   authRequest.Service,
			IssuedAt:   now,
			NotBefore:  now,
			Expiration: now + options.Expiration,
			JwtID:      jwtID,
			Access:     access,
		}

		payload, err := token.MakePayload(header, claimSet)
		if err != nil {
			w.WriteHeader(500)
			logger.WithError(err).Debug("token.MakePayload")
			return
		}
		signature, err := options.Key.Sign(payload)
		if err != nil {
			w.WriteHeader(500)
			logger.WithError(err).Debug("key.Sign")
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
			logger.WithError(err).Debug("json.Marshal")
			return
		}
		w.Header().Set("content-type", "application/json")
		w.Header().Set("content-length", strconv.Itoa(len(body)))
		w.WriteHeader(200)
		w.Write(body)

	})
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
