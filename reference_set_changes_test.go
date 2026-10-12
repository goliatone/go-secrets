package secrets_test

import (
	"context"
	"testing"
	"time"

	secrets "github.com/goliatone/ctx/pkg/go-secrets"
	"github.com/goliatone/ctx/pkg/go-secrets/testkit"
)

func TestUpdateEmitsOnlyTheFieldsThatChanged(t *testing.T) {
	registry := secrets.NewRegistry()
	if err := registry.Register(testkit.NewProvider("environment", "env")); err != nil {
		t.Fatal(err)
	}
	repository := testkit.NewRepository()
	sink := &events{}
	service := secrets.ReferenceSetService{Repository: repository, Registry: registry, Events: sink, Transactions: repository, Clock: &testkit.Clock{Current: time.Unix(100, 0)}, IDs: &testkit.IDs{Prefix: "id-"}}
	scope := secrets.Scope{Kind: "host", ID: "h"}
	set, err := service.Create(context.Background(), secrets.CreateReferenceSetInput{ID: "set", Name: "Token", Purpose: "github-token", Scope: scope, Candidates: []secrets.CandidateInput{{URI: "env://ONE", Priority: 0, Enabled: true}}})
	if err != nil {
		t.Fatal(err)
	}
	fingerprint := set.Candidates[0].Reference.Fingerprint()
	renamed, err := service.Update(context.Background(), secrets.UpdateReferenceSetInput{ID: set.ID, Name: "Token renamed", Purpose: set.Purpose, Scope: scope, Candidates: []secrets.CandidateInput{{Fingerprint: fingerprint, Priority: 0, Enabled: true}}, ExpectedRevision: set.Revision})
	if err != nil {
		t.Fatal(err)
	}
	last := sink.items[len(sink.items)-1]
	if last.Type != "secrets.reference-set.updated.v1" || len(last.ChangedFields) != 1 || last.ChangedFields[0] != "name" {
		t.Fatalf("rename emitted %v", last.ChangedFields)
	}
	if _, err := service.Update(context.Background(), secrets.UpdateReferenceSetInput{ID: set.ID, Name: renamed.Name, Purpose: set.Purpose, Scope: scope, Candidates: []secrets.CandidateInput{{URI: "env://TWO", Priority: 0, Enabled: true}}, ExpectedRevision: renamed.Revision}); err != nil {
		t.Fatal(err)
	}
	last = sink.items[len(sink.items)-1]
	if len(last.ChangedFields) != 1 || last.ChangedFields[0] != "candidates" {
		t.Fatalf("source change emitted %v", last.ChangedFields)
	}
}
