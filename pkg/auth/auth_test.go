package auth

import (
	"net/http"
	"reflect"
	"testing"
)

func httpRequest(t *testing.T, url string) *http.Request {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		t.Errorf("cannot create HTTP request: %v", req)
		t.FailNow()
	}
	return req
}

func TestParseRequest(t *testing.T) {
	r := httpRequest(t, "/")

	_, err := ParseRequest(r)
	if err == nil || err.Error() != "missing Authorization header" {
		t.Errorf("expected Authorization error, but got: %v", err)
	}

	r.SetBasicAuth("johndoe", "secret")
	_, err = ParseRequest(r)
	if err == nil || err.Error() != "missing query param: service" {
		t.Errorf("expected missing service error, but got: %v", err)
	}

	r = httpRequest(t, "/?service=myregistry")
	r.SetBasicAuth("johndoe", "secret")
	_, err = ParseRequest(r)
	if err == nil || err.Error() != "missing query param: scope" {
		t.Errorf("expected missing scope error, but got: %v", err)
	}

	r = httpRequest(t, "/?service=myregistry&scope=repository:johndoe/myapp:pull,push&scope=repository:janedoe/myapp:pull")
	r.SetBasicAuth("johndoe", "secret")
	req, err := ParseRequest(r)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	expected := AuthRequest{
		Username: "johndoe",
		Password: "secret",
		Service:  "myregistry",
		Scopes: []Scope{
			Scope{
				Type:    "repository",
				Name:    "johndoe/myapp",
				Actions: []string{"pull", "push"},
			},
			Scope{
				Type:    "repository",
				Name:    "janedoe/myapp",
				Actions: []string{"pull"},
			},
		},
	}
	if !reflect.DeepEqual(req, expected) {
		t.Errorf("not equal")
	}
}
