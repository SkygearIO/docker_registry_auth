# docker_registry_auth

It is a http.Handler to implementing [Token Authentication Specification](https://docs.docker.com/registry/spec/auth/token/). This intended use-case is you are deploying your own registry:2 and
you want to use `REGISTRY_AUTH=token`

## Usage

```go
import (
	"github.com/skygeario/docker_registry_auth/pkg/httphandler"
)

// None of the option fields has default value.
// You must specify every field.
options, err := httphandler.NewOptions(httphandler.Options{
	// It must match REGISTRY_AUTH_TOKEN_ISSUER
	Issuer: "issuer",
	// How long the token is valid after it is issued, in seconds.
	Expiration: 60,
	// Arguments to https://golang.org/pkg/crypto/tls/#LoadX509KeyPair
	// Particularly, CertFile should have the same content as REGISTRY_AUTH_TOKEN_ROOTCERTBUNDLE
	CertFile: "/path/my.crt",
	KeyFile: "/path/my.key",
})
// A type implementing "github.com/skygeario/docker_registry_auth/pkg/auth".Auth
// The handler itself delegates authentication and authorization
// to this interface. Authenticate and authorization in any way you want.
myauth := ...
handler := httphandler.NewHandler(options, myauth)
// Mount the handler in any way you want.
// If you mount it at https://auth.example.com/docker
// then REGISTRY_AUTH_TOKEN_REALM=https://auth.example.com/docker
```
