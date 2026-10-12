package onepassword

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	secrets "github.com/goliatone/go-secrets"
	"github.com/goliatone/go-secrets/providers/internal/subprocess"
	"github.com/goliatone/go-secrets/testkit"
)

func serviceAccountConfig(runner subprocess.Runner) Config {
	return Config{Mode: ModeServiceAccount, Executable: "op", Environment: map[string]string{"OP_SERVICE_ACCOUNT_TOKEN": "account-token"}, Runner: runner}
}

func TestProviderConformance(t *testing.T) {
	runner := subprocess.RunnerFunc(func(_ context.Context, _ string, args, _ []string, _ int) (subprocess.Result, error) {
		if strings.Contains(args[2], "/missing/") {
			return subprocess.Result{Stderr: []byte("item not found")}, errors.New("exit")
		}
		return subprocess.Result{Stdout: []byte("value")}, nil
	})
	provider, err := New(serviceAccountConfig(runner))
	if err != nil {
		t.Fatal(err)
	}
	testkit.RunProviderConformance(t, provider, "op://vault/item/field", "op://vault/missing/field")
}

func TestDirectNonInteractiveCommandAndControlledEnvironment(t *testing.T) {
	var executable string
	var args, environment []string
	runner := subprocess.RunnerFunc(func(_ context.Context, command string, commandArgs, commandEnvironment []string, _ int) (subprocess.Result, error) {
		executable, args, environment = command, append([]string(nil), commandArgs...), append([]string(nil), commandEnvironment...)
		return subprocess.Result{Stdout: []byte("value")}, nil
	})
	provider, err := New(serviceAccountConfig(runner))
	if err != nil {
		t.Fatal(err)
	}
	reference, _ := secrets.ParseReference("op://vault/item/section/field")
	value, err := provider.Resolve(context.Background(), reference)
	if err != nil {
		t.Fatal(err)
	}
	value.Destroy()
	if executable != "op" || !reflect.DeepEqual(args, []string{"read", "--no-newline", reference.URI()}) {
		t.Fatalf("command = %q %q", executable, args)
	}
	wantEnvironment := []string{"OP_BIOMETRIC_UNLOCK_ENABLED=false", "OP_SERVICE_ACCOUNT_TOKEN=account-token"}
	if !reflect.DeepEqual(environment, wantEnvironment) {
		t.Fatalf("environment = %q, want %q", environment, wantEnvironment)
	}
}

func TestModesAndSafeDiagnostics(t *testing.T) {
	if _, err := New(Config{Mode: ModeDesktopSession, Executable: "op"}); !secrets.IsKind(err, secrets.ErrorPolicyDenied) {
		t.Fatalf("background desktop mode returned %v", err)
	}
	desktop, err := New(Config{Mode: ModeDesktopSession, Foreground: true, Executable: "op"})
	if err != nil || !desktop.Diagnostic().Configured {
		t.Fatalf("foreground desktop mode diagnostic=%+v err=%v", desktop.Diagnostic(), err)
	}
	connect, err := New(Config{Mode: ModeConnect, Executable: "op", Environment: map[string]string{"OP_CONNECT_HOST": "https://connect.example", "OP_CONNECT_TOKEN": "connect-token"}})
	if err != nil || !connect.Diagnostic().Configured {
		t.Fatalf("connect diagnostic=%+v err=%v", connect.Diagnostic(), err)
	}
	missing, err := New(Config{Mode: ModeServiceAccount, Executable: "op"})
	if err != nil || missing.Diagnostic().Configured || strings.Contains(missing.Diagnostic().Reason, "TOKEN") {
		t.Fatalf("missing diagnostic=%+v err=%v", missing.Diagnostic(), err)
	}
	data := strings.Join([]string{missing.Diagnostic().ID, string(missing.Diagnostic().Mode), missing.Diagnostic().Reason}, " ")
	if strings.Contains(data, "account-token") || strings.Contains(data, "connect-token") {
		t.Fatalf("diagnostic leaked environment: %s", data)
	}
}

func TestClassificationBoundsCancellationAndGrammar(t *testing.T) {
	cases := []struct {
		stderr string
		kind   secrets.ErrorKind
	}{
		{"item not found SECRET-CANARY", secrets.ErrorNotFound},
		{"not signed in SECRET-CANARY", secrets.ErrorAuthenticationRequired},
		{"permission denied SECRET-CANARY", secrets.ErrorPermissionDenied},
		{"network unavailable SECRET-CANARY", secrets.ErrorTemporary},
		{"unknown SECRET-CANARY", secrets.ErrorUnavailable},
	}
	for _, tc := range cases {
		provider, _ := New(serviceAccountConfig(subprocess.RunnerFunc(func(context.Context, string, []string, []string, int) (subprocess.Result, error) {
			return subprocess.Result{Stderr: []byte(tc.stderr)}, errors.New("SECRET-CANARY")
		})))
		reference, _ := secrets.ParseReference("op://vault/item/field")
		_, err := provider.Resolve(context.Background(), reference)
		if !secrets.IsKind(err, tc.kind) || strings.Contains(err.Error(), "SECRET-CANARY") {
			t.Fatalf("stderr %q returned unsafe %v", tc.stderr, err)
		}
	}

	provider, _ := New(Config{Mode: ModeServiceAccount, Executable: "op", Environment: map[string]string{"OP_SERVICE_ACCOUNT_TOKEN": "token"}, MaxBytes: 3, Runner: subprocess.RunnerFunc(func(context.Context, string, []string, []string, int) (subprocess.Result, error) {
		return subprocess.Result{Stdout: []byte("large"), OutputExceeded: true}, nil
	})})
	reference, _ := secrets.ParseReference("op://vault/item/field")
	if _, err := provider.Resolve(context.Background(), reference); !secrets.IsKind(err, secrets.ErrorInvalidSecret) {
		t.Fatalf("oversized output returned %v", err)
	}

	blocking, _ := New(Config{Mode: ModeServiceAccount, Executable: "op", Environment: map[string]string{"OP_SERVICE_ACCOUNT_TOKEN": "token"}, Timeout: time.Millisecond, Runner: subprocess.RunnerFunc(func(ctx context.Context, _ string, _ []string, _ []string, _ int) (subprocess.Result, error) {
		<-ctx.Done()
		return subprocess.Result{}, ctx.Err()
	})})
	if _, err := blocking.Resolve(context.Background(), reference); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("timeout returned %v", err)
	}

	for _, raw := range []string{"op://vault/item", "op://vault/a/b/c/d", "op://vault/item/field?x=1", "env://TOKEN"} {
		reference, err := secrets.ParseReference(raw)
		if err == nil {
			err = provider.ValidateReference(reference)
		}
		if !secrets.IsKind(err, secrets.ErrorInvalidReference) {
			t.Fatalf("reference %q returned %v", raw, err)
		}
	}
}
