//go:build darwin

package keychain

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	secrets "github.com/goliatone/go-secrets"
	"github.com/goliatone/go-secrets/providers/internal/subprocess"
	"github.com/goliatone/go-secrets/testkit"
)

func TestProviderConformance(t *testing.T) {
	runner := subprocess.RunnerFunc(func(_ context.Context, _ string, args, _ []string, _ int) (subprocess.Result, error) {
		if args[4] == "missing" {
			return subprocess.Result{Stderr: []byte("item not found")}, errors.New("exit")
		}
		return subprocess.Result{Stdout: []byte("value\n")}, nil
	})
	provider := New(Config{Executable: "security", Runner: runner})
	testkit.RunProviderConformance(t, provider, "keychain://ctx/token", "keychain://ctx/missing")
}

func TestCommandShapeBoundsAndSanitization(t *testing.T) {
	var got []string
	runner := subprocess.RunnerFunc(func(_ context.Context, _ string, args, _ []string, _ int) (subprocess.Result, error) {
		got = append([]string(nil), args...)
		return subprocess.Result{Stderr: []byte("permission denied: SECRET-CANARY")}, errors.New("SECRET-CANARY")
	})
	provider := New(Config{Executable: "security", Runner: runner, MaxBytes: 4})
	reference, _ := secrets.ParseReference("keychain://service/account")
	_, err := provider.Resolve(context.Background(), reference)
	if !secrets.IsKind(err, secrets.ErrorPermissionDenied) || strings.Contains(err.Error(), "SECRET-CANARY") {
		t.Fatalf("unsafe classified error: %v", err)
	}
	want := []string{"find-generic-password", "-s", "service", "-a", "account", "-w"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("command args = %q, want %q", got, want)
	}

	oversized := New(Config{Executable: "security", MaxBytes: 3, Runner: subprocess.RunnerFunc(func(context.Context, string, []string, []string, int) (subprocess.Result, error) {
		return subprocess.Result{Stdout: []byte("large"), OutputExceeded: true}, nil
	})})
	if _, err := oversized.Resolve(context.Background(), reference); !secrets.IsKind(err, secrets.ErrorInvalidSecret) {
		t.Fatalf("oversized output returned %v", err)
	}
}

func TestReferenceValidation(t *testing.T) {
	provider := New(Config{Executable: "security"})
	for _, raw := range []string{"keychain://service", "keychain://service/a/b", "keychain://service/account?x=1", "env://TOKEN"} {
		reference, err := secrets.ParseReference(raw)
		if err == nil {
			err = provider.ValidateReference(reference)
		}
		if !secrets.IsKind(err, secrets.ErrorInvalidReference) {
			t.Fatalf("reference %q returned %v", raw, err)
		}
	}
}
