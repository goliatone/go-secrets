package secrets

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

type ResolutionMetadata struct {
	ReferenceSetID string    `json:"reference_set_id"`
	Revision       uint64    `json:"revision"`
	ProviderID     string    `json:"provider_id"`
	Fingerprint    string    `json:"fingerprint"`
	Attempts       []Attempt `json:"attempts"`
}
type Resolution struct {
	Value    *Value
	Metadata ResolutionMetadata
}
type CheckResult struct {
	OK       bool               `json:"ok"`
	Metadata ResolutionMetadata `json:"metadata"`
}

type ResolutionService struct {
	OnAttemptStart func(context.Context, string, int)
	Repository     ReferenceSetRepository
	Registry       *Registry
	Policies       PurposePolicyProvider
	Observer       AttemptObserver
	AttemptTimeout time.Duration
	MaxAttempts    int
	Now            func() time.Time
}

func (s ResolutionService) Resolve(ctx context.Context, setID string, scope Scope, purpose string) (Resolution, error) {
	if err := s.validateDependencies(ctx); err != nil {
		return Resolution{}, err
	}
	if strings.TrimSpace(setID) != setID || setID == "" || !scope.Valid() || strings.TrimSpace(purpose) != purpose || purpose == "" {
		return Resolution{}, NewError(ErrorInvalidReference, "resolve", "resolution request is invalid")
	}
	set, err := s.Repository.Get(ctx, setID)
	if err != nil {
		return Resolution{}, err
	}
	meta := ResolutionMetadata{ReferenceSetID: set.ID, Revision: set.Revision}
	if err := set.Validate(); err != nil {
		return Resolution{Metadata: meta}, err
	}
	if set.Status != ReferenceSetActive {
		return Resolution{Metadata: meta}, NewError(ErrorDisabled, "resolve", "reference set is disabled")
	}
	if set.Scope != scope || set.Purpose != purpose {
		return Resolution{Metadata: meta}, NewError(ErrorPolicyDenied, "resolve", "reference set is not authorized for this consumer")
	}
	policy := FallbackPolicy{}
	if !isNilInterface(s.Policies) {
		policy = s.Policies.Policy(scope, purpose)
	}
	providerSnapshot := s.Registry.Snapshot()
	maxAttempts := s.MaxAttempts
	if maxAttempts <= 0 {
		maxAttempts = MaxCandidates
	}
	var lastErr error
	for _, candidate := range set.OrderedCandidates() {
		if !candidate.Enabled {
			continue
		}
		if len(meta.Attempts) >= maxAttempts {
			lastErr = NewError(ErrorPolicyDenied, "resolve", "secret resolution attempt limit exceeded")
			return resolutionFailure(meta, lastErr)
		}
		if err := ctx.Err(); err != nil {
			return Resolution{Metadata: meta}, err
		}
		descriptor, provider, ok := providerSnapshot.Lookup(candidate.Reference.Scheme())
		if !ok {
			lastErr = NewError(ErrorUnsupportedProvider, "resolve", "secret provider is unsupported")
			attempt := Attempt{ProviderID: "unsupported", Fingerprint: candidate.Reference.Fingerprint(), Kind: ErrorUnsupportedProvider}
			meta.Attempts = append(meta.Attempts, attempt)
			s.observe(ctx, attempt)
			if !policy.ShouldContinue(ctx, lastErr) {
				return resolutionFailure(meta, lastErr)
			}
			continue
		}
		if s.OnAttemptStart != nil {
			s.OnAttemptStart(ctx, descriptor.ID, len(meta.Attempts)+1)
		}
		attemptCtx, cancel := ctx, func() {}
		if s.AttemptTimeout > 0 {
			attemptCtx, cancel = context.WithTimeout(ctx, s.AttemptTimeout)
		}
		started := time.Now()
		value, resolveErr := provider.Resolve(attemptCtx, candidate.Reference)
		attemptErr := attemptCtx.Err()
		callerErr := ctx.Err()
		cancel()
		duration := time.Since(started)
		if callerErr != nil {
			attemptErr = callerErr
		}
		if attemptErr != nil {
			if value != nil {
				value.Destroy()
			}
			attempt := Attempt{ProviderID: descriptor.ID, Fingerprint: candidate.Reference.Fingerprint(), Kind: KindOf(attemptErr), Duration: duration}
			meta.Attempts = append(meta.Attempts, attempt)
			s.observe(ctx, attempt)
			return Resolution{Metadata: meta}, attemptErr
		}
		if resolveErr == nil && value != nil && value.Len() > 0 && !value.Expired(s.now()) {
			meta.ProviderID = descriptor.ID
			meta.Fingerprint = candidate.Reference.Fingerprint()
			attempt := Attempt{ProviderID: descriptor.ID, Fingerprint: candidate.Reference.Fingerprint(), Duration: duration}
			meta.Attempts = append(meta.Attempts, attempt)
			s.observe(ctx, attempt)
			return Resolution{Value: value, Metadata: meta}, nil
		}
		if value != nil {
			value.Destroy()
		}
		if resolveErr == nil {
			resolveErr = NewError(ErrorInvalidSecret, "resolve", "provider returned an invalid secret")
		}
		lastErr = resolveErr
		attempt := Attempt{ProviderID: descriptor.ID, Fingerprint: candidate.Reference.Fingerprint(), Kind: KindOf(lastErr), Duration: duration}
		meta.Attempts = append(meta.Attempts, attempt)
		s.observe(ctx, attempt)
		if errors.Is(lastErr, context.Canceled) || errors.Is(lastErr, context.DeadlineExceeded) {
			return Resolution{Metadata: meta}, lastErr
		}
		if !policy.ShouldContinue(ctx, lastErr) {
			return resolutionFailure(meta, lastErr)
		}
	}
	if lastErr == nil {
		lastErr = NewError(ErrorNotFound, "resolve", "no enabled credential candidate is available")
	}
	return resolutionFailure(meta, lastErr)
}

func (s ResolutionService) Check(ctx context.Context, setID string, scope Scope, purpose string) (CheckResult, error) {
	resolution, err := s.Resolve(ctx, setID, scope, purpose)
	if err != nil {
		return CheckResult{Metadata: resolution.Metadata}, err
	}
	if resolution.Value == nil {
		return CheckResult{Metadata: resolution.Metadata}, NewError(ErrorInternal, "check", "resolution returned no value")
	}
	resolution.Value.Destroy()
	return CheckResult{OK: true, Metadata: resolution.Metadata}, nil
}

func (s ResolutionService) validateDependencies(ctx context.Context) error {
	if ctx == nil {
		return NewError(ErrorInternal, "resolve", "context is required")
	}
	if isNilInterface(s.Repository) {
		return NewError(ErrorInternal, "resolve", "reference set repository is not configured")
	}
	if s.Registry == nil {
		return NewError(ErrorInternal, "resolve", "provider registry is not configured")
	}
	return nil
}
func (s ResolutionService) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}
func (s ResolutionService) observe(ctx context.Context, attempt Attempt) {
	if !isNilInterface(s.Observer) {
		s.Observer.ObserveAttempt(ctx, attempt)
	}
}
func resolutionFailure(meta ResolutionMetadata, cause error) (Resolution, error) {
	kind := KindOf(cause)
	message := fmt.Sprintf("secret resolution failed after %d attempt(s): %s", len(meta.Attempts), kind)
	return Resolution{Metadata: meta}, WrapError(kind, "resolve", message, cause)
}
