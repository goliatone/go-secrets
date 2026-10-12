package providers_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	secrets "github.com/goliatone/ctx/pkg/go-secrets"
	environmentprovider "github.com/goliatone/ctx/pkg/go-secrets/providers/environment"
	fileprovider "github.com/goliatone/ctx/pkg/go-secrets/providers/file"
	"github.com/goliatone/ctx/pkg/go-secrets/providers/internal/subprocess"
	keychainprovider "github.com/goliatone/ctx/pkg/go-secrets/providers/keychain"
	onepasswordprovider "github.com/goliatone/ctx/pkg/go-secrets/providers/onepassword"
	"github.com/goliatone/ctx/pkg/go-secrets/testkit"
)

func TestMultiProviderOrderedFallback(t *testing.T) {
	root := t.TempDir()
	filename := filepath.Join(root, "token")
	if err := os.WriteFile(filename, []byte("file-value\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	op, err := onepasswordprovider.New(onepasswordprovider.Config{
		Mode: onepasswordprovider.ModeServiceAccount, Executable: "op", Environment: map[string]string{"OP_SERVICE_ACCOUNT_TOKEN": "configured"},
		Runner: subprocess.RunnerFunc(func(context.Context, string, []string, []string, int) (subprocess.Result, error) {
			return subprocess.Result{Stderr: []byte("item not found")}, errors.New("exit")
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	keychain := keychainprovider.New(keychainprovider.Config{Executable: "security", Runner: subprocess.RunnerFunc(func(context.Context, string, []string, []string, int) (subprocess.Result, error) {
		return subprocess.Result{Stderr: []byte("item not found")}, errors.New("exit")
	})})
	environment := environmentprovider.New(environmentprovider.Config{Lookup: func(string) (string, bool) { return "", false }})
	file := fileprovider.New(fileprovider.Config{AllowedRoots: []string{root}, TrimTrailingNewline: true})

	registry := secrets.NewRegistry()
	for _, provider := range []secrets.Provider{op, keychain, environment, file} {
		if err := registry.Register(provider); err != nil {
			t.Fatal(err)
		}
	}
	repository := testkit.NewRepository()
	scope := secrets.Scope{Kind: "host", ID: "local"}
	set := mixedSet(t, scope, "file-ref://"+filename)
	if err := repository.Create(context.Background(), set); err != nil {
		t.Fatal(err)
	}
	resolution, err := (secrets.ResolutionService{Repository: repository, Registry: registry}).Resolve(context.Background(), set.ID, scope, set.Purpose)
	if err != nil {
		t.Fatal(err)
	}
	defer resolution.Value.Destroy()
	if string(resolution.Value.Bytes()) != "file-value" || resolution.Metadata.ProviderID != "file" || len(resolution.Metadata.Attempts) != 4 {
		t.Fatalf("resolution = value %q metadata %+v", resolution.Value.Bytes(), resolution.Metadata)
	}
	wantKinds := []secrets.ErrorKind{secrets.ErrorNotFound, secrets.ErrorNotFound, secrets.ErrorNotFound, ""}
	if runtime.GOOS != "darwin" {
		wantKinds[1] = secrets.ErrorUnavailable
	}
	for index, want := range wantKinds {
		if resolution.Metadata.Attempts[index].Kind != want {
			t.Fatalf("attempt %d kind=%q, want %q", index, resolution.Metadata.Attempts[index].Kind, want)
		}
	}
}

func TestMultiProviderFailClosedAndCancellation(t *testing.T) {
	for _, tc := range []struct {
		name   string
		result subprocess.Result
		err    error
		kind   secrets.ErrorKind
	}{
		{"permission", subprocess.Result{Stderr: []byte("permission denied")}, errors.New("exit"), secrets.ErrorPermissionDenied},
		{"invalid secret", subprocess.Result{}, nil, secrets.ErrorInvalidSecret},
	} {
		t.Run(tc.name, func(t *testing.T) {
			op, err := onepasswordprovider.New(onepasswordprovider.Config{
				Mode: onepasswordprovider.ModeServiceAccount, Executable: "op", Environment: map[string]string{"OP_SERVICE_ACCOUNT_TOKEN": "configured"},
				Runner: subprocess.RunnerFunc(func(context.Context, string, []string, []string, int) (subprocess.Result, error) {
					return tc.result, tc.err
				}),
			})
			if err != nil {
				t.Fatal(err)
			}
			environmentCalls := 0
			environment := environmentprovider.New(environmentprovider.Config{Lookup: func(string) (string, bool) { environmentCalls++; return "fallback", true }})
			registry := secrets.NewRegistry()
			if err := registry.Register(op); err != nil {
				t.Fatal(err)
			}
			if err := registry.Register(environment); err != nil {
				t.Fatal(err)
			}
			repository := testkit.NewRepository()
			scope := secrets.Scope{Kind: "host", ID: "local"}
			now := time.Now().UTC()
			opRef, _ := secrets.ParseReference("op://vault/item/field")
			envRef, _ := secrets.ParseReference("env://TOKEN")
			set := secrets.ReferenceSet{ID: "set", Name: "Set", Purpose: "api-key", Scope: scope, Candidates: []secrets.Candidate{{Reference: opRef, Priority: 0, Enabled: true}, {Reference: envRef, Priority: 1, Enabled: true}}, Status: secrets.ReferenceSetActive, Revision: 1, CreatedAt: now, UpdatedAt: now}
			if err := repository.Create(context.Background(), set); err != nil {
				t.Fatal(err)
			}
			_, err = (secrets.ResolutionService{Repository: repository, Registry: registry}).Resolve(context.Background(), set.ID, scope, set.Purpose)
			if !secrets.IsKind(err, tc.kind) || environmentCalls != 0 {
				t.Fatalf("error=%v environment calls=%d", err, environmentCalls)
			}

			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			_, err = (secrets.ResolutionService{Repository: repository, Registry: registry}).Resolve(ctx, set.ID, scope, set.Purpose)
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("canceled resolution returned %v", err)
			}
		})
	}
}

func mixedSet(t *testing.T, scope secrets.Scope, fileURI string) secrets.ReferenceSet {
	t.Helper()
	raw := []string{"op://vault/item/field", "keychain://ctx/account", "env://TOKEN", fileURI}
	candidates := make([]secrets.Candidate, 0, len(raw))
	for index, value := range raw {
		reference, err := secrets.ParseReference(value)
		if err != nil {
			t.Fatal(err)
		}
		candidates = append(candidates, secrets.Candidate{Reference: reference, Priority: index, Enabled: true})
	}
	now := time.Now().UTC()
	return secrets.ReferenceSet{ID: "mixed", Name: "Mixed", Purpose: "api-key", Scope: scope, Candidates: candidates, Status: secrets.ReferenceSetActive, Revision: 1, CreatedAt: now, UpdatedAt: now}
}
