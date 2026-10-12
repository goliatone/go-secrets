package secrets_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	secrets "github.com/goliatone/ctx/pkg/go-secrets"
	"github.com/goliatone/ctx/pkg/go-secrets/testkit"
)

type providerFunc struct {
	id      string
	schemes []string
	resolve func(context.Context, secrets.Reference) (*secrets.Value, error)
}

func (p providerFunc) ID() string        { return p.id }
func (p providerFunc) Schemes() []string { return append([]string(nil), p.schemes...) }
func (p providerFunc) Resolve(ctx context.Context, ref secrets.Reference) (*secrets.Value, error) {
	return p.resolve(ctx, ref)
}

type replacingProvider struct {
	mu          sync.Mutex
	registry    *secrets.Registry
	replacement secrets.Provider
	calls       int
}

func (p *replacingProvider) ID() string        { return "env" }
func (p *replacingProvider) Schemes() []string { return []string{"env"} }
func (p *replacingProvider) Resolve(context.Context, secrets.Reference) (*secrets.Value, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls++
	if p.calls == 1 {
		if err := p.registry.Replace(p.replacement); err != nil {
			return nil, err
		}
		return nil, secrets.NewError(secrets.ErrorNotFound, "", "missing")
	}
	return secrets.NewValue([]byte("snapshot-secret"), secrets.ValueOptions{})
}

type policies struct{ p secrets.FallbackPolicy }

func (p policies) Policy(secrets.Scope, string) secrets.FallbackPolicy { return p.p }
func TestResolutionFallbackPolicyAndCheckDestruction(t *testing.T) {
	now := time.Unix(10, 0)
	r1, _ := secrets.ParseReference("env://ONE")
	r2, _ := secrets.ParseReference("op://v/i/f")
	repo := testkit.NewRepository()
	set := secrets.ReferenceSet{ID: "s", Name: "S", Purpose: "p", Scope: secrets.Scope{Kind: "host", ID: "h"}, Candidates: []secrets.Candidate{{Reference: r2, Priority: 2, Enabled: true}, {Reference: r1, Priority: 1, Enabled: true}}, Status: secrets.ReferenceSetActive, Revision: 1, CreatedAt: now, UpdatedAt: now}
	if err := repo.Create(context.Background(), set); err != nil {
		t.Fatal(err)
	}
	registry := secrets.NewRegistry()
	first := testkit.NewProvider("env", "env")
	first.SetError(secrets.NewError(secrets.ErrorNotFound, "", "missing"))
	second := testkit.NewProvider("op", "op")
	second.SetValue([]byte("secret"))
	_ = registry.Register(first)
	_ = registry.Register(second)
	service := secrets.ResolutionService{Repository: repo, Registry: registry, Policies: policies{}, Now: func() time.Time { return now }}
	result, err := service.Resolve(context.Background(), "s", set.Scope, "p")
	if err != nil {
		t.Fatal(err)
	}
	if result.Metadata.ProviderID != "op" || string(result.Value.Bytes()) != "secret" {
		t.Fatal("fallback failed")
	}
	result.Value.Destroy()
	if _, err := service.Resolve(context.Background(), "s", set.Scope, "wrong"); !secrets.IsKind(err, secrets.ErrorPolicyDenied) {
		t.Fatalf("purpose mismatch: %v", err)
	}
	second.SetValue([]byte("check-secret"))
	check, err := service.Check(context.Background(), "s", set.Scope, "p")
	if err != nil || !check.OK {
		t.Fatalf("check: %v", err)
	}
}
func TestResolutionStopsOnPermissionAndCancellation(t *testing.T) {
	now := time.Unix(1, 0)
	ref, _ := secrets.ParseReference("env://ONE")
	repo := testkit.NewRepository()
	set := secrets.ReferenceSet{ID: "s", Name: "S", Purpose: "p", Scope: secrets.Scope{Kind: "host", ID: "h"}, Candidates: []secrets.Candidate{{Reference: ref, Enabled: true}}, Status: secrets.ReferenceSetActive, Revision: 1, CreatedAt: now, UpdatedAt: now}
	_ = repo.Create(context.Background(), set)
	registry := secrets.NewRegistry()
	p := testkit.NewProvider("env", "env")
	p.SetError(secrets.NewError(secrets.ErrorPermissionDenied, "", "denied"))
	_ = registry.Register(p)
	service := secrets.ResolutionService{Repository: repo, Registry: registry}
	if _, err := service.Resolve(context.Background(), "s", set.Scope, "p"); !secrets.IsKind(err, secrets.ErrorPermissionDenied) {
		t.Fatalf("got %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := service.Resolve(ctx, "s", set.Scope, "p"); err != context.Canceled {
		t.Fatalf("got %v", err)
	}
}

func TestResolutionRejectsValueReturnedAfterAttemptDeadline(t *testing.T) {
	now := time.Unix(1, 0)
	ref, _ := secrets.ParseReference("env://ONE")
	repo := testkit.NewRepository()
	set := secrets.ReferenceSet{ID: "s", Name: "S", Purpose: "p", Scope: secrets.Scope{Kind: "host", ID: "h"}, Candidates: []secrets.Candidate{{Reference: ref, Enabled: true}}, Status: secrets.ReferenceSetActive, Revision: 1, CreatedAt: now, UpdatedAt: now}
	_ = repo.Create(context.Background(), set)
	var returned *secrets.Value
	provider := providerFunc{id: "env", schemes: []string{"env"}, resolve: func(ctx context.Context, _ secrets.Reference) (*secrets.Value, error) {
		<-ctx.Done()
		returned, _ = secrets.NewValue([]byte("late-secret"), secrets.ValueOptions{})
		return returned, nil
	}}
	registry := secrets.NewRegistry()
	_ = registry.Register(provider)
	service := secrets.ResolutionService{Repository: repo, Registry: registry, AttemptTimeout: time.Millisecond}
	result, err := service.Resolve(context.Background(), "s", set.Scope, "p")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("got %v", err)
	}
	if result.Value != nil || returned == nil || returned.Len() != 0 {
		t.Fatal("late value was returned or not destroyed")
	}
	if len(result.Metadata.Attempts) != 1 || result.Metadata.Attempts[0].Kind != secrets.ErrorDeadlineExceeded {
		t.Fatalf("attempts: %#v", result.Metadata.Attempts)
	}
}

func TestResolutionReportsUnsupportedAndPreservesTerminalClassification(t *testing.T) {
	now := time.Unix(1, 0)
	ref, _ := secrets.ParseReference("op://v/i/f")
	repo := testkit.NewRepository()
	set := secrets.ReferenceSet{ID: "s", Name: "S", Purpose: "p", Scope: secrets.Scope{Kind: "host", ID: "h"}, Candidates: []secrets.Candidate{{Reference: ref, Enabled: true}}, Status: secrets.ReferenceSetActive, Revision: 1, CreatedAt: now, UpdatedAt: now}
	_ = repo.Create(context.Background(), set)
	result, err := (secrets.ResolutionService{Repository: repo, Registry: secrets.NewRegistry()}).Resolve(context.Background(), "s", set.Scope, "p")
	if !secrets.IsKind(err, secrets.ErrorUnsupportedProvider) {
		t.Fatalf("classification: %v", err)
	}
	if len(result.Metadata.Attempts) != 1 || result.Metadata.Attempts[0].Kind != secrets.ErrorUnsupportedProvider {
		t.Fatalf("attempts: %#v", result.Metadata.Attempts)
	}
}

func TestResolutionBoundsAttemptsAndUsesOneRegistrySnapshot(t *testing.T) {
	now := time.Unix(1, 0)
	one, _ := secrets.ParseReference("env://ONE")
	two, _ := secrets.ParseReference("env://TWO")
	repo := testkit.NewRepository()
	set := secrets.ReferenceSet{ID: "s", Name: "S", Purpose: "p", Scope: secrets.Scope{Kind: "host", ID: "h"}, Candidates: []secrets.Candidate{{Reference: one, Priority: 0, Enabled: true}, {Reference: two, Priority: 1, Enabled: true}}, Status: secrets.ReferenceSetActive, Revision: 1, CreatedAt: now, UpdatedAt: now}
	_ = repo.Create(context.Background(), set)
	registry := secrets.NewRegistry()
	replacement := testkit.NewProvider("env", "env")
	replacement.SetValue([]byte("replacement-secret"))
	original := &replacingProvider{registry: registry, replacement: replacement}
	_ = registry.Register(original)
	service := secrets.ResolutionService{Repository: repo, Registry: registry}
	result, err := service.Resolve(context.Background(), "s", set.Scope, "p")
	if err != nil {
		t.Fatal(err)
	}
	if string(result.Value.Bytes()) != "snapshot-secret" {
		t.Fatal("resolution observed mid-flight replacement")
	}
	result.Value.Destroy()
	failing := testkit.NewProvider("env", "env")
	failing.SetErrorKind(secrets.ErrorNotFound)
	_ = registry.Replace(failing)
	service.MaxAttempts = 1
	result, err = service.Resolve(context.Background(), "s", set.Scope, "p")
	if !secrets.IsKind(err, secrets.ErrorPolicyDenied) || len(result.Metadata.Attempts) != 1 {
		t.Fatalf("bound: %v %#v", err, result.Metadata.Attempts)
	}
}

func TestResolutionMisconfigurationReturnsTypedErrors(t *testing.T) {
	service := secrets.ResolutionService{}
	if _, err := service.Resolve(context.Background(), "s", secrets.Scope{Kind: "host", ID: "h"}, "p"); !secrets.IsKind(err, secrets.ErrorInternal) {
		t.Fatalf("repository: %v", err)
	}
	service.Repository = testkit.NewRepository()
	if _, err := service.Resolve(context.Background(), "s", secrets.Scope{Kind: "host", ID: "h"}, "p"); !secrets.IsKind(err, secrets.ErrorInternal) {
		t.Fatalf("registry: %v", err)
	}
	var typedNilRepository *testkit.Repository
	service.Repository = typedNilRepository
	service.Registry = secrets.NewRegistry()
	if _, err := service.Resolve(context.Background(), "s", secrets.Scope{Kind: "host", ID: "h"}, "p"); !secrets.IsKind(err, secrets.ErrorInternal) {
		t.Fatalf("typed nil repository: %v", err)
	}
}

func TestCheckDestroysValueAndAttemptsRemainRedacted(t *testing.T) {
	now := time.Unix(1, 0)
	ref, _ := secrets.ParseReference("env://PRIVATE_CANARY_NAME")
	repo := testkit.NewRepository()
	set := secrets.ReferenceSet{ID: "s", Name: "S", Purpose: "p", Scope: secrets.Scope{Kind: "host", ID: "h"}, Candidates: []secrets.Candidate{{Reference: ref, Enabled: true}}, Status: secrets.ReferenceSetActive, Revision: 1, CreatedAt: now, UpdatedAt: now}
	_ = repo.Create(context.Background(), set)
	var issued *secrets.Value
	provider := providerFunc{id: "env", schemes: []string{"env"}, resolve: func(context.Context, secrets.Reference) (*secrets.Value, error) {
		issued, _ = secrets.NewValue([]byte("private-canary-value"), secrets.ValueOptions{})
		return issued, nil
	}}
	registry := secrets.NewRegistry()
	_ = registry.Register(provider)
	observer := &testkit.Observer{}
	result, err := (secrets.ResolutionService{Repository: repo, Registry: registry, Observer: observer}).Check(context.Background(), "s", set.Scope, "p")
	if err != nil || !result.OK {
		t.Fatalf("check: %v", err)
	}
	if issued == nil || issued.Len() != 0 {
		t.Fatal("check did not destroy resolved value")
	}
	payload, _ := json.Marshal(struct {
		Result   secrets.CheckResult `json:"result"`
		Attempts []secrets.Attempt   `json:"attempts"`
	}{result, observer.Snapshot()})
	if strings.Contains(string(payload), "PRIVATE_CANARY_NAME") || strings.Contains(string(payload), "private-canary-value") {
		t.Fatalf("diagnostics leaked: %s", payload)
	}
}

func TestResolutionRejectsMissingDisabledAndWrongScope(t *testing.T) {
	repo := testkit.NewRepository()
	registry := secrets.NewRegistry()
	service := secrets.ResolutionService{Repository: repo, Registry: registry}
	scope := secrets.Scope{Kind: "host", ID: "h"}
	if _, err := service.Resolve(context.Background(), "missing", scope, "p"); !secrets.IsKind(err, secrets.ErrorNotFound) {
		t.Fatalf("missing: %v", err)
	}
	now := time.Unix(1, 0)
	ref, _ := secrets.ParseReference("env://ONE")
	set := secrets.ReferenceSet{ID: "s", Name: "S", Purpose: "p", Scope: scope, Candidates: []secrets.Candidate{{Reference: ref, Enabled: false}}, Status: secrets.ReferenceSetDisabled, Revision: 1, CreatedAt: now, UpdatedAt: now}
	_ = repo.Create(context.Background(), set)
	if _, err := service.Resolve(context.Background(), "s", scope, "p"); !secrets.IsKind(err, secrets.ErrorDisabled) {
		t.Fatalf("disabled: %v", err)
	}
	set.Status = secrets.ReferenceSetActive
	set.Candidates[0].Enabled = true
	set.Revision = 2
	_ = repo.Update(context.Background(), set, 1)
	if _, err := service.Resolve(context.Background(), "s", secrets.Scope{Kind: "host", ID: "other"}, "p"); !secrets.IsKind(err, secrets.ErrorPolicyDenied) {
		t.Fatalf("scope: %v", err)
	}
}
