package secrets_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	secrets "github.com/goliatone/ctx/pkg/go-secrets"
)

type commandService struct {
	create  secrets.CreateReferenceSetInput
	update  secrets.UpdateReferenceSetInput
	disable struct {
		id, actor, correlation string
		revision               uint64
	}
	deleted struct {
		id, actor, correlation string
		revision               uint64
	}
	checked struct {
		id, purpose string
		scope       secrets.Scope
	}
	err error
}

func (s *commandService) Create(_ context.Context, input secrets.CreateReferenceSetInput) (secrets.ReferenceSet, error) {
	s.create = input
	return secrets.ReferenceSet{ID: "created", Revision: 1, Status: secrets.ReferenceSetActive}, s.err
}
func (s *commandService) Update(_ context.Context, input secrets.UpdateReferenceSetInput) (secrets.ReferenceSet, error) {
	s.update = input
	return secrets.ReferenceSet{ID: input.ID, Revision: input.ExpectedRevision + 1, Status: secrets.ReferenceSetActive}, s.err
}
func (s *commandService) Disable(_ context.Context, id string, revision uint64, actor, correlation string) (secrets.ReferenceSet, error) {
	s.disable.id, s.disable.revision, s.disable.actor, s.disable.correlation = id, revision, actor, correlation
	return secrets.ReferenceSet{ID: id, Revision: revision + 1, Status: secrets.ReferenceSetDisabled}, s.err
}
func (s *commandService) Delete(_ context.Context, id string, revision uint64, actor, correlation string) error {
	s.deleted.id, s.deleted.revision, s.deleted.actor, s.deleted.correlation = id, revision, actor, correlation
	return s.err
}
func (s *commandService) Check(_ context.Context, id string, scope secrets.Scope, purpose string) (secrets.CheckResult, error) {
	s.checked.id, s.checked.scope, s.checked.purpose = id, scope, purpose
	return secrets.CheckResult{OK: s.err == nil}, s.err
}

func TestCommandContractsAndDelegation(t *testing.T) {
	meta := secrets.CommandMetadata{ActorID: "operator", CorrelationID: "correlation", IdempotencyKey: "request-1"}
	scope := secrets.Scope{Kind: "host", ID: "local"}
	candidates := []secrets.CandidateInput{{URI: "env://TOKEN", Priority: 0, Enabled: true}}
	service := &commandService{}

	create := secrets.CreateReferenceSet{Meta: meta, Input: secrets.CreateReferenceSetInput{Name: "Primary", Purpose: "api-key", Scope: scope, Candidates: candidates, ActorID: "untrusted", CorrelationID: "untrusted"}}
	if create.Type() != secrets.CommandCreateReferenceSet || create.Validate() != nil {
		t.Fatalf("invalid create contract: type=%q err=%v", create.Type(), create.Validate())
	}
	created, err := (secrets.CreateReferenceSetHandler{Service: service}).Run(context.Background(), create)
	if err != nil || created.ID != "created" || service.create.ActorID != meta.ActorID || service.create.CorrelationID != meta.CorrelationID {
		t.Fatalf("create delegation mismatch: result=%+v input=%+v err=%v", created, service.create, err)
	}

	update := secrets.UpdateReferenceSet{Meta: meta, Input: secrets.UpdateReferenceSetInput{ID: "set-1", Name: "Primary", Purpose: "api-key", Scope: scope, Candidates: candidates, ExpectedRevision: 3}}
	updated, err := (secrets.UpdateReferenceSetHandler{Service: service}).Run(context.Background(), update)
	if err != nil || update.Type() != secrets.CommandUpdateReferenceSet || updated.Revision != 4 || service.update.ActorID != meta.ActorID {
		t.Fatalf("update delegation mismatch: result=%+v input=%+v err=%v", updated, service.update, err)
	}

	disable := secrets.DisableReferenceSet{Meta: meta, ID: "set-1", ExpectedRevision: 4}
	disabled, err := (secrets.DisableReferenceSetHandler{Service: service}).Run(context.Background(), disable)
	if err != nil || disable.Type() != secrets.CommandDisableReferenceSet || disabled.Status != secrets.ReferenceSetDisabled || service.disable.actor != meta.ActorID {
		t.Fatalf("disable delegation mismatch: result=%+v call=%+v err=%v", disabled, service.disable, err)
	}

	deleteMessage := secrets.DeleteReferenceSet{Meta: meta, ID: "set-1", ExpectedRevision: 5}
	deleted, err := (secrets.DeleteReferenceSetHandler{Service: service}).Run(context.Background(), deleteMessage)
	if err != nil || deleteMessage.Type() != secrets.CommandDeleteReferenceSet || !deleted.Deleted || service.deleted.correlation != meta.CorrelationID {
		t.Fatalf("delete delegation mismatch: result=%+v call=%+v err=%v", deleted, service.deleted, err)
	}

	checkMeta := meta
	checkMeta.IdempotencyKey = ""
	check := secrets.CheckReferenceSet{Meta: checkMeta, ID: "set-1", Scope: scope, Purpose: "api-key"}
	checked, err := (secrets.CheckReferenceSetHandler{Service: service}).Run(context.Background(), check)
	if err != nil || check.Type() != secrets.CommandCheckReferenceSet || !checked.OK || service.checked.scope != scope {
		t.Fatalf("check delegation mismatch: result=%+v call=%+v err=%v", checked, service.checked, err)
	}
}

func TestCommandValidationAndExecuteErrorParity(t *testing.T) {
	validMeta := secrets.CommandMetadata{ActorID: "operator", CorrelationID: "correlation", IdempotencyKey: "request-1"}
	scope := secrets.Scope{Kind: "host", ID: "local"}
	candidate := []secrets.CandidateInput{{URI: "env://TOKEN", Enabled: true}}
	cases := []struct {
		name string
		msg  secrets.Validator
	}{
		{"create metadata", secrets.CreateReferenceSet{Input: secrets.CreateReferenceSetInput{Name: "name", Purpose: "purpose", Scope: scope, Candidates: candidate}}},
		{"create candidates", secrets.CreateReferenceSet{Meta: validMeta, Input: secrets.CreateReferenceSetInput{Name: "name", Purpose: "purpose", Scope: scope}}},
		{"update revision", secrets.UpdateReferenceSet{Meta: validMeta, Input: secrets.UpdateReferenceSetInput{ID: "set", Name: "name", Purpose: "purpose", Scope: scope, Candidates: candidate}}},
		{"disable revision", secrets.DisableReferenceSet{Meta: validMeta, ID: "set"}},
		{"delete id", secrets.DeleteReferenceSet{Meta: validMeta, ExpectedRevision: 1}},
		{"check purpose", secrets.CheckReferenceSet{Meta: secrets.CommandMetadata{ActorID: "operator", CorrelationID: "correlation"}, ID: "set", Scope: scope}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.msg.Validate(); !secrets.IsKind(err, secrets.ErrorInvalidReference) {
				t.Fatalf("expected invalid-reference error, got %v", err)
			}
		})
	}

	sentinel := errors.New("service failed")
	service := &commandService{err: sentinel}
	message := secrets.DisableReferenceSet{Meta: validMeta, ID: "set", ExpectedRevision: 1}
	handler := secrets.DisableReferenceSetHandler{Service: service}
	_, runErr := handler.Run(context.Background(), message)
	executeErr := handler.Execute(context.Background(), message)
	if !errors.Is(runErr, sentinel) || !errors.Is(executeErr, sentinel) {
		t.Fatalf("Run/Execute error mismatch: run=%v execute=%v", runErr, executeErr)
	}
}

func TestCommandResultsContainNoReferenceMaterial(t *testing.T) {
	result := secrets.ReferenceSetMutationResult{ID: "set-1", Revision: 2, Status: secrets.ReferenceSetActive}
	data, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != `{"id":"set-1","revision":2,"status":"active"}` {
		t.Fatalf("unexpected safe result: %s", data)
	}
}

func TestCommandInterfacesMatchDeclaredMethodSets(t *testing.T) {
	var _ secrets.Message = secrets.CreateReferenceSet{}
	var _ secrets.Validator = secrets.CreateReferenceSet{}
	var _ secrets.Commander[secrets.CreateReferenceSet] = secrets.CreateReferenceSetHandler{}
	var _ secrets.Commander[secrets.UpdateReferenceSet] = secrets.UpdateReferenceSetHandler{}
	var _ secrets.Commander[secrets.DisableReferenceSet] = secrets.DisableReferenceSetHandler{}
	var _ secrets.Commander[secrets.DeleteReferenceSet] = secrets.DeleteReferenceSetHandler{}
	var _ secrets.Commander[secrets.CheckReferenceSet] = secrets.CheckReferenceSetHandler{}
}
