package main

import (
	"log"
	"net/http"
	"os"

	"github.com/skygeario/docker_registry_auth/pkg/auth"
	"github.com/skygeario/docker_registry_auth/pkg/httphandler"
)

type InsecureAuth struct{}

func (a InsecureAuth) AuthenticateAndAuthorize(req auth.AuthRequest) ([]auth.Scope, error) {
	return req.Scopes, nil
}

func main() {
	issuer := os.Getenv("ISSUER")
	expiration := int64(60)
	certFile := os.Getenv("CERT_FILE")
	keyFile := os.Getenv("KEY_FILE")
	auth := InsecureAuth{}
	handler, err := httphandler.New(httphandler.Options{
		Issuer:     issuer,
		Expiration: expiration,
		CertFile:   certFile,
		KeyFile:    keyFile,
		Auth:       auth,
	})
	if err != nil {
		log.Fatalf("failed to start server: %v\n", err)
	}
	http.Handle("/", handler)
	http.ListenAndServe(":8080", nil)
}
