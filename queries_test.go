package secrets_test

import (
	"context"
	"strings"
	"testing"
	"time"

	secrets "github.com/goliatone/ctx/pkg/go-secrets"
	"github.com/goliatone/ctx/pkg/go-secrets/testkit"
)

func TestQueryContractsReturnRedactedViews(t *testing.T) {
	registry := secrets.NewRegistry()
	provider := testkit.NewProvider("environment", "env")
	if err := registry.Register(provider); err != nil {
		t.Fatal(err)
	}
	repository := testkit.NewRepository()
	reference, err := secrets.ParseReference("env://QUERY_SECRET")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	set := secrets.ReferenceSet{ID: "set-1", Name: "Set", Purpose: "api-key", Scope: secrets.Scope{Kind: "host", ID: "local"}, Candidates: []secrets.Candidate{{Reference: reference, Enabled: true}}, Status: secrets.ReferenceSetActive, Revision: 1, CreatedAt: now, UpdatedAt: now}
	if err := repository.Create(context.Background(), set); err != nil {
		t.Fatal(err)
	}
	service := secrets.QueryService{Repository: repository, Registry: registry}

	get := secrets.GetReferenceSet{ID: "set-1"}
	view, err := (secrets.GetReferenceSetHandler{Service: service}).Query(context.Background(), get)
	if err != nil || get.Type() != secrets.QueryGetReferenceSet || len(view.Candidates) != 1 || strings.Contains(view.Candidates[0].Redacted, "QUERY_SECRET") {
		t.Fatalf("unsafe get result: view=%+v err=%v", view, err)
	}
	listed, err := (secrets.ListReferenceSetsHandler{Service: service}).Query(context.Background(), secrets.ListReferenceSets{})
	if err != nil || len(listed) != 1 || (secrets.ListReferenceSets{}).Type() != secrets.QueryListReferenceSets {
		t.Fatalf("list query mismatch: views=%+v err=%v", listed, err)
	}
	providers, err := (secrets.ListSecretProvidersHandler{Service: service}).Query(context.Background(), secrets.ListSecretProviders{})
	if err != nil || len(providers) != 1 || providers[0].ID != "environment" {
		t.Fatalf("provider query mismatch: providers=%+v err=%v", providers, err)
	}
}

func TestQueryValidationAndComposition(t *testing.T) {
	if err := (secrets.GetReferenceSet{}).Validate(); !secrets.IsKind(err, secrets.ErrorInvalidReference) {
		t.Fatalf("expected invalid get query, got %v", err)
	}
	_, err := (secrets.ListSecretProvidersHandler{}).Query(context.Background(), secrets.ListSecretProviders{})
	if !secrets.IsKind(err, secrets.ErrorInternal) {
		t.Fatalf("expected composition error, got %v", err)
	}

	var _ secrets.Message = secrets.GetReferenceSet{}
	var _ secrets.Validator = secrets.GetReferenceSet{}
	var _ secrets.Querier[secrets.GetReferenceSet, secrets.ReferenceSetView] = secrets.GetReferenceSetHandler{}
	var _ secrets.Querier[secrets.ListReferenceSets, []secrets.ReferenceSetView] = secrets.ListReferenceSetsHandler{}
	var _ secrets.Querier[secrets.ListSecretProviders, []secrets.ProviderDescriptor] = secrets.ListSecretProvidersHandler{}
}
