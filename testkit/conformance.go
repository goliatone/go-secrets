package testkit

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	secrets "github.com/goliatone/ctx/pkg/go-secrets"
)

// RunProviderConformance exercises generic provider behavior. Provider
// packages supply references that are valid and missing for their grammar.
func RunProviderConformance(t *testing.T, provider secrets.Provider, valid, missing string) {
	t.Helper()
	t.Run("identity", func(t *testing.T) {
		if provider.ID() == "" || len(provider.Schemes()) == 0 {
			t.Fatal("provider has no safe identity")
		}
	})
	t.Run("valid", func(t *testing.T) {
		ref, err := secrets.ParseReference(valid)
		if err != nil {
			t.Fatal(err)
		}
		value, err := provider.Resolve(context.Background(), ref)
		if err != nil {
			t.Fatal(err)
		}
		if value == nil || value.Len() == 0 {
			t.Fatal("empty value")
		}
		if strings.Contains(fmt.Sprintf("%v %#v", value, value), string(value.Bytes())) {
			t.Fatal("provider value leaked through formatting")
		}
		value.Destroy()
	})
	t.Run("missing", func(t *testing.T) {
		ref, err := secrets.ParseReference(missing)
		if err != nil {
			t.Fatal(err)
		}
		value, err := provider.Resolve(context.Background(), ref)
		if value != nil {
			value.Destroy()
		}
		if err == nil {
			t.Fatal("missing reference succeeded")
		}
	})
	t.Run("cancellation", func(t *testing.T) {
		ref, err := secrets.ParseReference(valid)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		done := make(chan struct{})
		var resolveErr error
		var value *secrets.Value
		go func() {
			value, resolveErr = provider.Resolve(ctx, ref)
			if value != nil {
				value.Destroy()
			}
			close(done)
		}()
		select {
		case <-done:
			if !errors.Is(resolveErr, context.Canceled) {
				t.Fatalf("provider returned %v after cancellation", resolveErr)
			}
		case <-time.After(time.Second):
			t.Fatal("provider ignored cancellation")
		}
	})
}
