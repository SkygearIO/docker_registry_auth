package auth

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
)

type AuthRequest struct {
	HTTPRequest *http.Request
	Username    string
	Password    string
	Service     string
	Scopes      []Scope
}

type Scope struct {
	Type    string
	Name    string
	Actions []string
}

type Auth interface {
	AuthenticateAndAuthorize(req AuthRequest) ([]Scope, error)
}

func ParseRequest(r *http.Request) (authRequest AuthRequest, err error) {
	authRequest.HTTPRequest = r

	username, password, ok := r.BasicAuth()
	if !ok {
		err = errors.New("missing Authorization header")
		return
	}
	authRequest.Username = username
	authRequest.Password = password

	err = r.ParseForm()
	if err != nil {
		return
	}

	service := r.FormValue("service")
	if service == "" {
		err = errors.New("missing query param: service")
		return
	}
	authRequest.Service = service

	// docker login myregistry.local
	// does not include scope.
	scopes := []Scope{}
	for _, scopeStr := range r.Form["scope"] {
		parts := strings.Split(scopeStr, ":")
		if len(parts) < 3 {
			err = fmt.Errorf("invalid scope: %s", scopeStr)
			return
		}
		typ := parts[0]
		actionsStr := parts[len(parts)-1]
		actions := strings.Split(actionsStr, ",")
		nameParts := parts[1 : len(parts)-1]
		name := strings.Join(nameParts, ":")
		scope := Scope{
			Type:    typ,
			Name:    name,
			Actions: actions,
		}
		scopes = append(scopes, scope)
	}
	authRequest.Scopes = scopes

	return
}
