package secrets

import (
	"context"
	"sort"
	"strings"
	"time"
)

type CandidateInput struct {
	URI         string `json:"uri,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
	Priority    int    `json:"priority"`
	Enabled     bool   `json:"enabled"`
}
type CreateReferenceSetInput struct {
	ID, Name, Purpose      string
	Scope                  Scope
	Candidates             []CandidateInput
	ActorID, CorrelationID string
}
type UpdateReferenceSetInput struct {
	ID, Name, Purpose      string
	Scope                  Scope
	Candidates             []CandidateInput
	ExpectedRevision       uint64
	ActorID, CorrelationID string
}

type ReferenceSetService struct {
	Repository   ReferenceSetRepository
	Registry     *Registry
	Usage        UsageInspector
	Events       EventSink
	Transactions TransactionManager
	Policy       ReferenceSetPolicyValidator
	Clock        Clock
	IDs          IDGenerator
}

func (s ReferenceSetService) Create(ctx context.Context, in CreateReferenceSetInput) (ReferenceSet, error) {
	if err := s.validateComposition(ctx, false); err != nil {
		return ReferenceSet{}, err
	}
	id := strings.TrimSpace(in.ID)
	if id == "" {
		if isNilInterface(s.IDs) {
			return ReferenceSet{}, NewError(ErrorInternal, "create reference set", "ID generator is not configured")
		}
		id = s.IDs.NewID()
	}
	now := s.now()
	candidates, err := s.candidates(in.Candidates, nil)
	if err != nil {
		return ReferenceSet{}, err
	}
	set := ReferenceSet{ID: id, Name: strings.TrimSpace(in.Name), Purpose: in.Purpose, Scope: in.Scope, Candidates: candidates, Status: ReferenceSetActive, Revision: 1, CreatedAt: now, UpdatedAt: now}
	if err := s.validateSet(ctx, set); err != nil {
		return ReferenceSet{}, err
	}
	err = s.within(ctx, func(txctx context.Context) error {
		if err := s.Repository.Create(txctx, set); err != nil {
			return err
		}
		return s.event(txctx, set, "secrets.reference-set.created.v1", in.ActorID, in.CorrelationID, []string{"name", "purpose", "scope", "candidates"})
	})
	if err != nil {
		return ReferenceSet{}, err
	}
	return set.Clone(), nil
}

func (s ReferenceSetService) Update(ctx context.Context, in UpdateReferenceSetInput) (ReferenceSet, error) {
	if err := s.validateComposition(ctx, false); err != nil {
		return ReferenceSet{}, err
	}
	if strings.TrimSpace(in.ID) != in.ID || in.ID == "" || in.ExpectedRevision == 0 {
		return ReferenceSet{}, NewError(ErrorInvalidReference, "update reference set", "update request is invalid")
	}
	var updated ReferenceSet
	err := s.within(ctx, func(txctx context.Context) error {
		current, err := s.Repository.Get(txctx, in.ID)
		if err != nil {
			return err
		}
		before := current.Clone()
		candidates, err := s.candidates(in.Candidates, current.Candidates)
		if err != nil {
			return err
		}
		current.Name = strings.TrimSpace(in.Name)
		current.Purpose = in.Purpose
		current.Scope = in.Scope
		current.Candidates = candidates
		current.Revision++
		current.UpdatedAt = s.now()
		if err := s.validateSet(txctx, current); err != nil {
			return err
		}
		if err := s.Repository.Update(txctx, current, in.ExpectedRevision); err != nil {
			return err
		}
		if err := s.event(txctx, current, "secrets.reference-set.updated.v1", in.ActorID, in.CorrelationID, changedReferenceSetFields(before, current)); err != nil {
			return err
		}
		updated = current.Clone()
		return nil
	})
	if err != nil {
		return ReferenceSet{}, err
	}
	return updated, nil
}

func (s ReferenceSetService) Disable(ctx context.Context, id string, expected uint64, actor, correlation string) (ReferenceSet, error) {
	if err := s.validateComposition(ctx, false); err != nil {
		return ReferenceSet{}, err
	}
	if strings.TrimSpace(id) != id || id == "" || expected == 0 {
		return ReferenceSet{}, NewError(ErrorInvalidReference, "disable reference set", "disable request is invalid")
	}
	var disabled ReferenceSet
	err := s.within(ctx, func(txctx context.Context) error {
		set, err := s.Repository.Get(txctx, id)
		if err != nil {
			return err
		}
		if set.Status == ReferenceSetDisabled {
			return NewError(ErrorConflict, "disable reference set", "reference set is already disabled")
		}
		set.Status = ReferenceSetDisabled
		set.Revision++
		set.UpdatedAt = s.now()
		if err := s.validateSet(txctx, set); err != nil {
			return err
		}
		if err := s.Repository.Update(txctx, set, expected); err != nil {
			return err
		}
		if err := s.event(txctx, set, "secrets.reference-set.disabled.v1", actor, correlation, []string{"status"}); err != nil {
			return err
		}
		disabled = set.Clone()
		return nil
	})
	if err != nil {
		return ReferenceSet{}, err
	}
	return disabled, nil
}

func (s ReferenceSetService) Delete(ctx context.Context, id string, expected uint64, actor, correlation string) error {
	hasUsage := !isNilInterface(s.Usage)
	if err := s.validateComposition(ctx, hasUsage); err != nil {
		return err
	}
	if strings.TrimSpace(id) != id || id == "" || expected == 0 {
		return NewError(ErrorInvalidReference, "delete reference set", "delete request is invalid")
	}
	return s.within(ctx, func(txctx context.Context) error {
		if hasUsage {
			uses, err := s.Usage.Usages(txctx, id)
			if err != nil {
				return err
			}
			if len(uses) > 0 {
				return NewError(ErrorConflict, "delete reference set", "reference set is in use")
			}
		}
		if err := s.Repository.Delete(txctx, id, expected); err != nil {
			return err
		}
		return s.event(txctx, ReferenceSet{ID: id, Revision: expected}, "secrets.reference-set.deleted.v1", actor, correlation, nil)
	})
}

// changedReferenceSetFields names only the fields an update changed, so a
// consumer can tell a rename from a change of secret sources.
func changedReferenceSetFields(before, after ReferenceSet) []string {
	fields := []string{}
	if before.Name != after.Name {
		fields = append(fields, "name")
	}
	if before.Purpose != after.Purpose {
		fields = append(fields, "purpose")
	}
	if before.Scope != after.Scope {
		fields = append(fields, "scope")
	}
	if !sameCandidates(before.OrderedCandidates(), after.OrderedCandidates()) {
		fields = append(fields, "candidates")
	}
	return fields
}

func sameCandidates(before, after []Candidate) bool {
	if len(before) != len(after) {
		return false
	}
	for index := range before {
		if before[index].Reference.Fingerprint() != after[index].Reference.Fingerprint() || before[index].Priority != after[index].Priority || before[index].Enabled != after[index].Enabled {
			return false
		}
	}
	return true
}

func (s ReferenceSetService) candidates(inputs []CandidateInput, existing []Candidate) ([]Candidate, error) {
	if len(inputs) > MaxCandidates {
		return nil, NewError(ErrorInvalidReference, "validate candidates", "too many reference candidates")
	}
	snapshot := s.Registry.Snapshot()
	out := make([]Candidate, 0, len(inputs))
	for _, input := range inputs {
		if strings.TrimSpace(input.URI) != input.URI || strings.TrimSpace(input.Fingerprint) != input.Fingerprint {
			return nil, NewFieldError(ErrorInvalidReference, "validate candidate", "candidate reference token is invalid", "candidates")
		}
		var ref Reference
		var err error
		switch {
		case strings.TrimSpace(input.Fingerprint) != "" && strings.TrimSpace(input.URI) == "":
			for _, candidate := range existing {
				if candidate.Reference.Fingerprint() == strings.TrimSpace(input.Fingerprint) {
					ref = candidate.Reference
					break
				}
			}
			if ref.URI() == "" {
				return nil, NewFieldError(ErrorConflict, "validate candidate", "preserved reference candidate is stale", "candidates")
			}
		case strings.TrimSpace(input.Fingerprint) == "" && strings.TrimSpace(input.URI) != "":
			ref, err = ParseReference(input.URI)
			if err != nil {
				return nil, NewFieldError(KindOf(err), "validate candidate", err.Error(), "candidates")
			}
		default:
			return nil, NewFieldError(ErrorInvalidReference, "validate candidate", "candidate must contain one reference or preserved fingerprint", "candidates")
		}
		_, provider, ok := snapshot.Lookup(ref.Scheme())
		if !ok {
			return nil, NewFieldError(ErrorUnsupportedProvider, "validate candidate", "secret provider is unsupported", "candidates")
		}
		if validator, ok := provider.(ReferenceValidator); ok {
			if err := validator.ValidateReference(ref); err != nil {
				return nil, NewFieldError(KindOf(err), "validate candidate", err.Error(), "candidates")
			}
		}
		out = append(out, Candidate{Reference: ref, Priority: input.Priority, Enabled: input.Enabled})
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Priority < out[j].Priority })
	return out, nil
}
func (s ReferenceSetService) validateSet(ctx context.Context, set ReferenceSet) error {
	if err := set.Validate(); err != nil {
		return err
	}
	if !isNilInterface(s.Policy) {
		return s.Policy.ValidateReferenceSet(ctx, set)
	}
	return nil
}
func (s ReferenceSetService) event(ctx context.Context, set ReferenceSet, eventType, actor, correlation string, fields []string) error {
	if isNilInterface(s.Events) {
		return nil
	}
	if isNilInterface(s.IDs) {
		return NewError(ErrorInternal, "emit reference set event", "ID generator is not configured")
	}
	id := s.IDs.NewID()
	if id == "" {
		return NewError(ErrorInternal, "emit reference set event", "event ID is empty")
	}
	return s.Events.Append(ctx, Event{ID: id, Type: eventType, ReferenceSetID: set.ID, Revision: set.Revision, ActorID: actor, CorrelationID: correlation, ChangedFields: append([]string(nil), fields...), OccurredAt: s.now()})
}
func (s ReferenceSetService) now() time.Time {
	if s.Clock != nil {
		return s.Clock.Now()
	}
	return time.Now()
}
func (s ReferenceSetService) validateComposition(ctx context.Context, usageGuard bool) error {
	if ctx == nil {
		return NewError(ErrorInternal, "reference set mutation", "context is required")
	}
	if isNilInterface(s.Repository) {
		return NewError(ErrorInternal, "reference set mutation", "repository is not configured")
	}
	if s.Registry == nil {
		return NewError(ErrorInternal, "reference set mutation", "provider registry is not configured")
	}
	if (!isNilInterface(s.Events) || usageGuard) && isNilInterface(s.Transactions) {
		return NewError(ErrorInternal, "reference set mutation", "transaction manager is required for atomic mutation")
	}
	if !isNilInterface(s.Events) && isNilInterface(s.IDs) {
		return NewError(ErrorInternal, "reference set mutation", "ID generator is required for events")
	}
	return nil
}
func (s ReferenceSetService) within(ctx context.Context, fn func(context.Context) error) error {
	if isNilInterface(s.Transactions) {
		return fn(ctx)
	}
	txctx, tx, err := s.Transactions.Begin(ctx)
	if err != nil {
		return err
	}
	if txctx == nil || isNilInterface(tx) {
		return NewError(ErrorInternal, "reference set mutation", "transaction manager returned nil transaction")
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()
	if err := fn(txctx); err != nil {
		return err
	}
	if err := txctx.Err(); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	committed = true
	return nil
}

type CandidateView struct {
	ProviderID  string `json:"provider_id"`
	Redacted    string `json:"reference"`
	Fingerprint string `json:"fingerprint"`
	Priority    int    `json:"priority"`
	Enabled     bool   `json:"enabled"`
}
type ReferenceSetView struct {
	ID         string             `json:"id"`
	Name       string             `json:"name"`
	Purpose    string             `json:"purpose"`
	Scope      Scope              `json:"scope"`
	Candidates []CandidateView    `json:"candidates"`
	Status     ReferenceSetStatus `json:"status"`
	Revision   uint64             `json:"revision"`
}
type QueryService struct {
	Repository ReferenceSetRepository
	Registry   *Registry
}

func (q QueryService) Get(ctx context.Context, id string) (ReferenceSetView, error) {
	if ctx == nil || isNilInterface(q.Repository) {
		return ReferenceSetView{}, NewError(ErrorInternal, "get reference set", "query service is not configured")
	}
	set, err := q.Repository.Get(ctx, id)
	if err != nil {
		return ReferenceSetView{}, err
	}
	return q.view(set), nil
}
func (q QueryService) List(ctx context.Context) ([]ReferenceSetView, error) {
	if ctx == nil || isNilInterface(q.Repository) {
		return nil, NewError(ErrorInternal, "list reference sets", "query service is not configured")
	}
	sets, err := q.Repository.List(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]ReferenceSetView, 0, len(sets))
	for _, set := range sets {
		out = append(out, q.view(set))
	}
	return out, nil
}
func (q QueryService) Providers() []ProviderDescriptor {
	if q.Registry == nil {
		return nil
	}
	return q.Registry.List()
}
func (q QueryService) view(set ReferenceSet) ReferenceSetView {
	view := ReferenceSetView{ID: set.ID, Name: set.Name, Purpose: set.Purpose, Scope: set.Scope, Status: set.Status, Revision: set.Revision}
	snapshot := q.Registry.Snapshot()
	for _, candidate := range set.OrderedCandidates() {
		providerID := ""
		if descriptor, _, ok := snapshot.Lookup(candidate.Reference.Scheme()); ok {
			providerID = descriptor.ID
		}
		view.Candidates = append(view.Candidates, CandidateView{ProviderID: providerID, Redacted: candidate.Reference.Redacted(), Fingerprint: candidate.Reference.Fingerprint(), Priority: candidate.Priority, Enabled: candidate.Enabled})
	}
	return view
}
