package secrets

import (
	"context"
	"errors"
)

type FallbackPolicy struct {
	ContinueTemporary              bool
	ContinueAuthenticationRequired bool
	ContinueInvalidSecret          bool
}

// ShouldContinue applies cancellation/deadline precedence before typed fallback.
func (p FallbackPolicy) ShouldContinue(ctx context.Context, err error) bool {
	if err == nil || ctx == nil || ctx.Err() != nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	return p.Continue(KindOf(err))
}

func (p FallbackPolicy) Continue(kind ErrorKind) bool {
	switch kind {
	case ErrorNotFound, ErrorUnavailable:
		return true
	case ErrorTemporary:
		return p.ContinueTemporary
	case ErrorAuthenticationRequired:
		return p.ContinueAuthenticationRequired
	case ErrorInvalidSecret:
		return p.ContinueInvalidSecret
	default:
		return false
	}
}

type PurposePolicyProvider interface {
	Policy(scope Scope, purpose string) FallbackPolicy
}
