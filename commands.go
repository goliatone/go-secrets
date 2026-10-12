package secrets

import (
	"context"
	"strings"
)

const (
	CommandCreateReferenceSet  = "secrets.reference-set.create.v1"
	CommandUpdateReferenceSet  = "secrets.reference-set.update.v1"
	CommandDisableReferenceSet = "secrets.reference-set.disable.v1"
	CommandDeleteReferenceSet  = "secrets.reference-set.delete.v1"
	CommandCheckReferenceSet   = "secrets.reference-set.check.v1"
)

type Message interface{ Type() string }
type Validator interface{ Validate() error }
type Commander[T any] interface {
	Execute(context.Context, T) error
}
type Querier[T, R any] interface {
	Query(context.Context, T) (R, error)
}

// CommandMetadata is populated by a trusted host adapter, not decoded from a
// reference-set form or other caller-controlled payload.
type CommandMetadata struct {
	ActorID        string `json:"actor_id"`
	CorrelationID  string `json:"correlation_id"`
	IdempotencyKey string `json:"idempotency_key,omitempty"`
}

func (m CommandMetadata) validate(requireIdempotency bool) error {
	if invalidToken(m.ActorID) || invalidToken(m.CorrelationID) {
		return NewError(ErrorInvalidReference, "validate command metadata", "trusted command metadata is invalid")
	}
	if requireIdempotency && invalidToken(m.IdempotencyKey) {
		return NewFieldError(ErrorInvalidReference, "validate command metadata", "idempotency key is required", "idempotency_key")
	}
	if !requireIdempotency && m.IdempotencyKey != "" && invalidToken(m.IdempotencyKey) {
		return NewError(ErrorInvalidReference, "validate command metadata", "idempotency key is invalid")
	}
	return nil
}

type CreateReferenceSet struct {
	Meta  CommandMetadata
	Input CreateReferenceSetInput
}

func (CreateReferenceSet) Type() string { return CommandCreateReferenceSet }
func (m CreateReferenceSet) Validate() error {
	if err := m.Meta.validate(true); err != nil {
		return err
	}
	if m.Input.ID != "" && invalidToken(m.Input.ID) {
		return NewError(ErrorInvalidReference, "validate create command", "reference set ID is invalid")
	}
	return validateReferenceSetShape(m.Input.Name, m.Input.Purpose, m.Input.Scope, m.Input.Candidates, false, 0)
}

type UpdateReferenceSet struct {
	Meta  CommandMetadata
	Input UpdateReferenceSetInput
}

func (UpdateReferenceSet) Type() string { return CommandUpdateReferenceSet }
func (m UpdateReferenceSet) Validate() error {
	if err := m.Meta.validate(true); err != nil {
		return err
	}
	if invalidToken(m.Input.ID) {
		return NewError(ErrorInvalidReference, "validate update command", "reference set ID is invalid")
	}
	return validateReferenceSetShape(m.Input.Name, m.Input.Purpose, m.Input.Scope, m.Input.Candidates, true, m.Input.ExpectedRevision)
}

type DisableReferenceSet struct {
	Meta             CommandMetadata
	ID               string
	ExpectedRevision uint64
}

func (DisableReferenceSet) Type() string { return CommandDisableReferenceSet }
func (m DisableReferenceSet) Validate() error {
	if err := m.Meta.validate(true); err != nil {
		return err
	}
	if invalidToken(m.ID) || m.ExpectedRevision == 0 {
		return NewError(ErrorInvalidReference, "validate disable command", "reference set ID and expected revision are required")
	}
	return nil
}

type DeleteReferenceSet struct {
	Meta             CommandMetadata
	ID               string
	ExpectedRevision uint64
}

func (DeleteReferenceSet) Type() string { return CommandDeleteReferenceSet }
func (m DeleteReferenceSet) Validate() error {
	if err := m.Meta.validate(true); err != nil {
		return err
	}
	if invalidToken(m.ID) || m.ExpectedRevision == 0 {
		return NewError(ErrorInvalidReference, "validate delete command", "reference set ID and expected revision are required")
	}
	return nil
}

type CheckReferenceSet struct {
	Meta    CommandMetadata
	ID      string
	Scope   Scope
	Purpose string
}

func (CheckReferenceSet) Type() string { return CommandCheckReferenceSet }
func (m CheckReferenceSet) Validate() error {
	if err := m.Meta.validate(false); err != nil {
		return err
	}
	if invalidToken(m.ID) || !m.Scope.Valid() || invalidToken(m.Purpose) {
		return NewError(ErrorInvalidReference, "validate check command", "check request is invalid")
	}
	return nil
}

type ReferenceSetMutationResult struct {
	ID       string             `json:"id"`
	Revision uint64             `json:"revision"`
	Status   ReferenceSetStatus `json:"status"`
}

type DeleteReferenceSetResult struct {
	ID       string `json:"id"`
	Revision uint64 `json:"revision"`
	Deleted  bool   `json:"deleted"`
}

type ReferenceSetCreator interface {
	Create(context.Context, CreateReferenceSetInput) (ReferenceSet, error)
}
type ReferenceSetUpdater interface {
	Update(context.Context, UpdateReferenceSetInput) (ReferenceSet, error)
}
type ReferenceSetDisabler interface {
	Disable(context.Context, string, uint64, string, string) (ReferenceSet, error)
}
type ReferenceSetDeleter interface {
	Delete(context.Context, string, uint64, string, string) error
}
type ReferenceSetChecker interface {
	Check(context.Context, string, Scope, string) (CheckResult, error)
}

type CreateReferenceSetHandler struct{ Service ReferenceSetCreator }

func (h CreateReferenceSetHandler) Run(ctx context.Context, message CreateReferenceSet) (ReferenceSetMutationResult, error) {
	if err := message.Validate(); err != nil {
		return ReferenceSetMutationResult{}, err
	}
	if isNilInterface(h.Service) {
		return ReferenceSetMutationResult{}, NewError(ErrorInternal, "create reference set", "reference set service is not configured")
	}
	input := message.Input
	input.ActorID, input.CorrelationID = message.Meta.ActorID, message.Meta.CorrelationID
	set, err := h.Service.Create(ctx, input)
	return mutationResult(set), err
}
func (h CreateReferenceSetHandler) Execute(ctx context.Context, message CreateReferenceSet) error {
	_, err := h.Run(ctx, message)
	return err
}

type UpdateReferenceSetHandler struct{ Service ReferenceSetUpdater }

func (h UpdateReferenceSetHandler) Run(ctx context.Context, message UpdateReferenceSet) (ReferenceSetMutationResult, error) {
	if err := message.Validate(); err != nil {
		return ReferenceSetMutationResult{}, err
	}
	if isNilInterface(h.Service) {
		return ReferenceSetMutationResult{}, NewError(ErrorInternal, "update reference set", "reference set service is not configured")
	}
	input := message.Input
	input.ActorID, input.CorrelationID = message.Meta.ActorID, message.Meta.CorrelationID
	set, err := h.Service.Update(ctx, input)
	return mutationResult(set), err
}
func (h UpdateReferenceSetHandler) Execute(ctx context.Context, message UpdateReferenceSet) error {
	_, err := h.Run(ctx, message)
	return err
}

type DisableReferenceSetHandler struct{ Service ReferenceSetDisabler }

func (h DisableReferenceSetHandler) Run(ctx context.Context, message DisableReferenceSet) (ReferenceSetMutationResult, error) {
	if err := message.Validate(); err != nil {
		return ReferenceSetMutationResult{}, err
	}
	if isNilInterface(h.Service) {
		return ReferenceSetMutationResult{}, NewError(ErrorInternal, "disable reference set", "reference set service is not configured")
	}
	set, err := h.Service.Disable(ctx, message.ID, message.ExpectedRevision, message.Meta.ActorID, message.Meta.CorrelationID)
	return mutationResult(set), err
}
func (h DisableReferenceSetHandler) Execute(ctx context.Context, message DisableReferenceSet) error {
	_, err := h.Run(ctx, message)
	return err
}

type DeleteReferenceSetHandler struct{ Service ReferenceSetDeleter }

func (h DeleteReferenceSetHandler) Run(ctx context.Context, message DeleteReferenceSet) (DeleteReferenceSetResult, error) {
	if err := message.Validate(); err != nil {
		return DeleteReferenceSetResult{}, err
	}
	if isNilInterface(h.Service) {
		return DeleteReferenceSetResult{}, NewError(ErrorInternal, "delete reference set", "reference set service is not configured")
	}
	err := h.Service.Delete(ctx, message.ID, message.ExpectedRevision, message.Meta.ActorID, message.Meta.CorrelationID)
	return DeleteReferenceSetResult{ID: message.ID, Revision: message.ExpectedRevision, Deleted: err == nil}, err
}
func (h DeleteReferenceSetHandler) Execute(ctx context.Context, message DeleteReferenceSet) error {
	_, err := h.Run(ctx, message)
	return err
}

type CheckReferenceSetHandler struct{ Service ReferenceSetChecker }

func (h CheckReferenceSetHandler) Run(ctx context.Context, message CheckReferenceSet) (CheckResult, error) {
	if err := message.Validate(); err != nil {
		return CheckResult{}, err
	}
	if isNilInterface(h.Service) {
		return CheckResult{}, NewError(ErrorInternal, "check reference set", "resolution service is not configured")
	}
	return h.Service.Check(ctx, message.ID, message.Scope, message.Purpose)
}
func (h CheckReferenceSetHandler) Execute(ctx context.Context, message CheckReferenceSet) error {
	_, err := h.Run(ctx, message)
	return err
}

func mutationResult(set ReferenceSet) ReferenceSetMutationResult {
	return ReferenceSetMutationResult{ID: set.ID, Revision: set.Revision, Status: set.Status}
}

func validateReferenceSetShape(name, purpose string, scope Scope, candidates []CandidateInput, requireRevision bool, revision uint64) error {
	if strings.TrimSpace(name) == "" {
		return NewFieldError(ErrorInvalidReference, "validate reference set command", "reference set name is required", "name")
	}
	if invalidToken(purpose) {
		return NewFieldError(ErrorInvalidReference, "validate reference set command", "reference set purpose is invalid", "purpose")
	}
	if !scope.Valid() {
		return NewFieldError(ErrorInvalidReference, "validate reference set command", "reference set scope is invalid", "scope")
	}
	if len(candidates) == 0 || len(candidates) > MaxCandidates {
		return NewFieldError(ErrorInvalidReference, "validate reference set command", "reference set candidates are invalid", "candidates")
	}
	if requireRevision && revision == 0 {
		return NewFieldError(ErrorInvalidReference, "validate reference set command", "expected revision is required", "expected_revision")
	}
	for _, candidate := range candidates {
		hasURI := strings.TrimSpace(candidate.URI) == candidate.URI && candidate.URI != ""
		hasFingerprint := strings.TrimSpace(candidate.Fingerprint) == candidate.Fingerprint && candidate.Fingerprint != ""
		if candidate.Priority < 0 || hasURI == hasFingerprint || hasFingerprint && !requireRevision {
			return NewFieldError(ErrorInvalidReference, "validate reference set command", "reference candidate is invalid", "candidates")
		}
	}
	return nil
}

func invalidToken(value string) bool {
	return value == "" || strings.TrimSpace(value) != value
}
