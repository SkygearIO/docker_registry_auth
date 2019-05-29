package random

import (
	"testing"
)

func TestRandomString(t *testing.T) {
	for i := -1; i < 2; i++ {
		_, err := RandomString(i)
		if err == nil || err.Error() != "length must be positive even integer" {
			t.Errorf("expected error: %d", i)
		}
	}
	for i := 2; i < 1000; i += 2 {
		out, err := RandomString(i)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		} else if len(out) != i {
			t.Errorf("unexpected len: %d", len(out))
		}
	}
}
