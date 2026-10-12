//go:build !darwin

package keychain

import (
	"context"
	"testing"

	secrets "github.com/goliatone/go-secrets"
)

func TestUnsupportedPlatform(t *testing.T) {
	provider := New(Config{Executable: "security"})
	reference, err := secrets.ParseReference("keychain://service/account")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provider.Resolve(context.Background(), reference); !secrets.IsKind(err, secrets.ErrorUnavailable) {
		t.Fatalf("unsupported platform returned %v", err)
	}
}
