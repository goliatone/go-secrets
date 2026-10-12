package environment

import (
	"context"
	"strings"
	"testing"

	secrets "github.com/goliatone/ctx/pkg/go-secrets"
	"github.com/goliatone/ctx/pkg/go-secrets/testkit"
)

func TestProviderConformance(t *testing.T) {
	values := map[string]string{"TOKEN": "value"}
	provider := New(Config{Lookup: func(name string) (string, bool) { value, ok := values[name]; return value, ok }})
	testkit.RunProviderConformance(t, provider, "env://TOKEN", "env://MISSING")
}

func TestReferenceGrammarAndBounds(t *testing.T) {
	provider := New(Config{Lookup: func(string) (string, bool) { return "too-long", true }, MaxBytes: 3})
	for _, raw := range []string{"env://BAD/NAME", "env://1BAD", "env://TOKEN?x=1", "file-ref:///tmp/token"} {
		reference, err := secrets.ParseReference(raw)
		if err == nil {
			_, err = provider.Resolve(context.Background(), reference)
		}
		if !secrets.IsKind(err, secrets.ErrorInvalidReference) {
			t.Fatalf("reference %q returned %v", raw, err)
		}
	}
	reference, _ := secrets.ParseReference("env://TOKEN")
	if _, err := provider.Resolve(context.Background(), reference); !secrets.IsKind(err, secrets.ErrorInvalidSecret) || strings.Contains(err.Error(), "too-long") {
		t.Fatalf("bounded resolution returned unsafe error %v", err)
	}
}

func TestZeroValueProviderFailsSafely(t *testing.T) {
	reference, _ := secrets.ParseReference("env://TOKEN")
	if _, err := (&Provider{}).Resolve(context.Background(), reference); !secrets.IsKind(err, secrets.ErrorUnavailable) {
		t.Fatalf("zero-value provider returned %v", err)
	}
}
