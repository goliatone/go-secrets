package secrets_test

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	secrets "github.com/goliatone/go-secrets"
	"github.com/goliatone/go-secrets/testkit"
)

type uses struct{ items []secrets.Usage }

func (u uses) Usages(context.Context, string) ([]secrets.Usage, error) { return u.items, nil }

type events struct {
	items []secrets.Event
	err   error
}

func TestReferenceSetServiceUpdatePreservesOpaqueCandidate(t *testing.T) {
	repository := testkit.NewRepository()
	registry := secrets.NewRegistry()
	provider := testkit.NewProvider("environment", "env")
	if err := registry.Register(provider); err != nil {
		t.Fatal(err)
	}
	service := secrets.ReferenceSetService{Repository: repository, Registry: registry, Clock: &testkit.Clock{Current: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}, IDs: &testkit.IDs{Prefix: "set-"}}
	created, err := service.Create(context.Background(), secrets.CreateReferenceSetInput{Name: "Set", Purpose: "p", Scope: secrets.Scope{Kind: "host", ID: "h"}, Candidates: []secrets.CandidateInput{{URI: "env://TOP_SECRET", Enabled: true}}})
	if err != nil {
		t.Fatal(err)
	}
	fingerprint := created.Candidates[0].Reference.Fingerprint()
	updated, err := service.Update(context.Background(), secrets.UpdateReferenceSetInput{ID: created.ID, Name: "Renamed", Purpose: created.Purpose, Scope: created.Scope, Candidates: []secrets.CandidateInput{{Fingerprint: fingerprint, Enabled: true}}, ExpectedRevision: created.Revision})
	if err != nil {
		t.Fatal(err)
	}
	if updated.Candidates[0].Reference.URI() != "env://TOP_SECRET" {
		t.Fatalf("preserved candidate = %q", updated.Candidates[0].Reference.URI())
	}
	_, err = service.Update(context.Background(), secrets.UpdateReferenceSetInput{ID: created.ID, Name: "Stale", Purpose: created.Purpose, Scope: created.Scope, Candidates: []secrets.CandidateInput{{Fingerprint: "unknown", Enabled: true}}, ExpectedRevision: updated.Revision})
	if !secrets.IsKind(err, secrets.ErrorConflict) {
		t.Fatalf("unknown fingerprint returned %v", err)
	}
}

var errEventSink = errors.New("event sink failed")

func (e *events) Append(_ context.Context, event secrets.Event) error {
	if e.err != nil {
		return e.err
	}
	e.items = append(e.items, event)
	return nil
}

type rejectingPolicy struct {
	err   error
	calls int
}

func (p *rejectingPolicy) ValidateReferenceSet(context.Context, secrets.ReferenceSet) error {
	p.calls++
	return p.err
}

type validatingProvider struct {
	*testkit.Provider
	err   error
	calls int
}

func (p *validatingProvider) ValidateReference(secrets.Reference) error { p.calls++; return p.err }

type failingCommitManager struct{ repo *testkit.Repository }
type failingCommitTx struct{ inner secrets.Transaction }

func (m failingCommitManager) Begin(ctx context.Context) (context.Context, secrets.Transaction, error) {
	txctx, tx, err := m.repo.Begin(ctx)
	if err != nil {
		return nil, nil, err
	}
	return txctx, &failingCommitTx{inner: tx}, nil
}
func (tx *failingCommitTx) Commit() error   { return errors.New("commit failed") }
func (tx *failingCommitTx) Rollback() error { return tx.inner.Rollback() }

type cancelingEvents struct{ cancel context.CancelFunc }

func (e cancelingEvents) Append(context.Context, secrets.Event) error { e.cancel(); return nil }

func TestReferenceSetLifecycleAndSafeQueries(t *testing.T) {
	repo := testkit.NewRepository()
	clock := &testkit.Clock{Current: time.Unix(10, 0)}
	ids := &testkit.IDs{Prefix: "id-"}
	registry := secrets.NewRegistry()
	provider := testkit.NewProvider("env", "env")
	provider.SetValue([]byte("unused"))
	_ = registry.Register(provider)
	sink := &events{}
	service := secrets.ReferenceSetService{Repository: repo, Registry: registry, Events: sink, Transactions: repo, Clock: clock, IDs: ids}
	created, err := service.Create(context.Background(), secrets.CreateReferenceSetInput{Name: "Set", Purpose: "p", Scope: secrets.Scope{Kind: "host", ID: "h"}, Candidates: []secrets.CandidateInput{{URI: "env://TOP_SECRET", Enabled: true}}})
	if err != nil {
		t.Fatal(err)
	}
	if created.Revision != 1 || len(provider.Calls()) != 0 {
		t.Fatal("create resolved provider or bad revision")
	}
	query := secrets.QueryService{Repository: repo, Registry: registry}
	view, err := query.Get(context.Background(), created.ID)
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(view)
	if strings.Contains(string(payload), "TOP_SECRET") {
		t.Fatalf("query leaked URI: %s", payload)
	}
	clock.Advance(time.Second)
	updated, err := service.Update(context.Background(), secrets.UpdateReferenceSetInput{ID: created.ID, Name: "Updated", Purpose: "p", Scope: created.Scope, Candidates: []secrets.CandidateInput{{URI: "env://TOP_SECRET", Enabled: true}}, ExpectedRevision: 1})
	if err != nil {
		t.Fatal(err)
	}
	if updated.Revision != 2 {
		t.Fatal("revision not advanced")
	}
	if _, err := service.Disable(context.Background(), created.ID, 1, "", ""); !secrets.IsKind(err, secrets.ErrorConflict) {
		t.Fatalf("stale update: %v", err)
	}
	service.Usage = uses{items: []secrets.Usage{{Kind: "harness", ID: "one"}}}
	if err := service.Delete(context.Background(), created.ID, 2, "", ""); !secrets.IsKind(err, secrets.ErrorConflict) {
		t.Fatalf("usage guard: %v", err)
	}
	if len(sink.items) != 2 {
		t.Fatalf("events: %#v", sink.items)
	}
}

func TestLifecycleRequiresAndUsesAtomicMutationBoundary(t *testing.T) {
	registry := secrets.NewRegistry()
	provider := testkit.NewProvider("env", "env")
	provider.SetValue([]byte("unused"))
	_ = registry.Register(provider)
	input := secrets.CreateReferenceSetInput{Name: "Set", Purpose: "p", Scope: secrets.Scope{Kind: "host", ID: "h"}, Candidates: []secrets.CandidateInput{{URI: "env://TOKEN", Enabled: true}}}
	repo := testkit.NewRepository()
	service := secrets.ReferenceSetService{Repository: repo, Registry: registry, Events: &events{}, IDs: &testkit.IDs{Prefix: "id-"}}
	if _, err := service.Create(context.Background(), input); !secrets.IsKind(err, secrets.ErrorInternal) {
		t.Fatalf("missing transaction: %v", err)
	}
	failingSink := &events{err: errEventSink}
	service.Events = failingSink
	service.Transactions = repo
	if _, err := service.Create(context.Background(), input); !errors.Is(err, errEventSink) {
		t.Fatalf("event failure: %v", err)
	}
	if _, err := repo.Get(context.Background(), "id-1"); !secrets.IsKind(err, secrets.ErrorNotFound) {
		t.Fatal("event failure persisted mutation")
	}
	service.Events = &events{}
	service.Transactions = failingCommitManager{repo: repo}
	if _, err := service.Create(context.Background(), input); err == nil || err.Error() != "commit failed" {
		t.Fatalf("commit failure: %v", err)
	}
	if sets, _ := repo.List(context.Background()); len(sets) != 0 {
		t.Fatal("commit failure persisted mutation")
	}
	ctx, cancel := context.WithCancel(context.Background())
	service.Transactions = repo
	service.Events = cancelingEvents{cancel: cancel}
	if _, err := service.Create(ctx, input); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled transaction: %v", err)
	}
	if sets, _ := repo.List(context.Background()); len(sets) != 0 {
		t.Fatal("canceled transaction persisted mutation")
	}
}

func TestLifecycleEnforcesProviderAndApplicationPolicy(t *testing.T) {
	registry := secrets.NewRegistry()
	base := testkit.NewProvider("env", "env")
	validator := &validatingProvider{Provider: base, err: secrets.NewError(secrets.ErrorInvalidReference, "", "provider rejected reference")}
	_ = registry.Register(validator)
	repo := testkit.NewRepository()
	policy := &rejectingPolicy{err: secrets.NewError(secrets.ErrorPolicyDenied, "", "purpose denied")}
	service := secrets.ReferenceSetService{Repository: repo, Registry: registry, Policy: policy, IDs: &testkit.IDs{Prefix: "id-"}}
	input := secrets.CreateReferenceSetInput{Name: "Set", Purpose: "denied", Scope: secrets.Scope{Kind: "host", ID: "h"}, Candidates: []secrets.CandidateInput{{URI: "env://TOKEN", Enabled: true}}}
	if _, err := service.Create(context.Background(), input); !secrets.IsKind(err, secrets.ErrorInvalidReference) {
		t.Fatalf("provider validation: %v", err)
	}
	validator.err = nil
	if _, err := service.Create(context.Background(), input); !secrets.IsKind(err, secrets.ErrorPolicyDenied) {
		t.Fatalf("purpose policy: %v", err)
	}
	if validator.calls != 2 || policy.calls != 1 {
		t.Fatalf("validation calls provider=%d policy=%d", validator.calls, policy.calls)
	}
	if _, ok := reflect.TypeFor[secrets.CreateReferenceSetInput]().FieldByName("FallbackPolicy"); ok {
		t.Fatal("editor input can mutate fallback policy")
	}
}

func TestLifecycleRejectsInvalidTransitionsCandidatesAndComposition(t *testing.T) {
	registry := secrets.NewRegistry()
	provider := testkit.NewProvider("env", "env")
	_ = registry.Register(provider)
	repo := testkit.NewRepository()
	clock := &testkit.Clock{Current: time.Unix(10, 0)}
	service := secrets.ReferenceSetService{Repository: repo, Registry: registry, Clock: clock, IDs: &testkit.IDs{Prefix: "id-"}}
	duplicate := secrets.CreateReferenceSetInput{Name: "Set", Purpose: "p", Scope: secrets.Scope{Kind: "host", ID: "h"}, Candidates: []secrets.CandidateInput{{URI: "env://TOKEN", Priority: 0, Enabled: true}, {URI: "env://TOKEN", Priority: 1, Enabled: true}}}
	if _, err := service.Create(context.Background(), duplicate); !secrets.IsKind(err, secrets.ErrorConflict) {
		t.Fatalf("duplicate: %v", err)
	}
	unsupported := duplicate
	unsupported.Candidates = []secrets.CandidateInput{{URI: "op://v/i/f", Enabled: true}}
	if _, err := service.Create(context.Background(), unsupported); !secrets.IsKind(err, secrets.ErrorUnsupportedProvider) {
		t.Fatalf("unsupported: %v", err)
	}
	valid := duplicate
	valid.Candidates = []secrets.CandidateInput{{URI: "env://TOKEN", Enabled: true}}
	set, err := service.Create(context.Background(), valid)
	if err != nil {
		t.Fatal(err)
	}
	disabled, err := service.Disable(context.Background(), set.ID, 1, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Disable(context.Background(), disabled.ID, 2, "", ""); !secrets.IsKind(err, secrets.ErrorConflict) {
		t.Fatalf("repeat disable: %v", err)
	}
	clock.Current = time.Unix(1, 0)
	if _, err := service.Update(context.Background(), secrets.UpdateReferenceSetInput{ID: set.ID, Name: "Set", Purpose: "p", Scope: set.Scope, Candidates: valid.Candidates, ExpectedRevision: 2}); !secrets.IsKind(err, secrets.ErrorInvalidReference) {
		t.Fatalf("timestamp invariant: %v", err)
	}
	if _, err := (secrets.QueryService{}).List(context.Background()); !secrets.IsKind(err, secrets.ErrorInternal) {
		t.Fatalf("query composition: %v", err)
	}
	var typedNilRepository *testkit.Repository
	if _, err := (secrets.QueryService{Repository: typedNilRepository}).List(context.Background()); !secrets.IsKind(err, secrets.ErrorInternal) {
		t.Fatalf("typed nil query repository: %v", err)
	}
	if _, err := (secrets.ReferenceSetService{Repository: typedNilRepository, Registry: registry}).Create(context.Background(), valid); !secrets.IsKind(err, secrets.ErrorInternal) {
		t.Fatalf("typed nil lifecycle repository: %v", err)
	}
}
