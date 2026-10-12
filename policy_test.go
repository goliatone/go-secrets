package secrets

import (
	"context"
	"testing"
)

func TestFallbackPolicyMatrix(t *testing.T) {
	base := FallbackPolicy{}
	for _, kind := range []ErrorKind{ErrorNotFound, ErrorUnavailable} {
		if !base.ShouldContinue(context.Background(), NewError(kind, "", "safe")) {
			t.Fatalf("%s should continue", kind)
		}
	}
	for _, kind := range []ErrorKind{ErrorTemporary, ErrorAuthenticationRequired, ErrorInvalidSecret, ErrorPermissionDenied, ErrorInvalidReference, ErrorPolicyDenied, ErrorDisabled, ErrorConflict, ErrorInternal, ErrorCanceled, ErrorDeadlineExceeded} {
		if base.ShouldContinue(context.Background(), NewError(kind, "", "safe")) {
			t.Fatalf("%s continued", kind)
		}
	}
	overrides := FallbackPolicy{ContinueTemporary: true, ContinueAuthenticationRequired: true, ContinueInvalidSecret: true}
	for _, kind := range []ErrorKind{ErrorTemporary, ErrorAuthenticationRequired, ErrorInvalidSecret} {
		if !overrides.ShouldContinue(context.Background(), NewError(kind, "", "safe")) {
			t.Fatalf("%s override ignored", kind)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if overrides.ShouldContinue(ctx, NewError(ErrorNotFound, "", "safe")) {
		t.Fatal("canceled context continued")
	}
	if overrides.ShouldContinue(context.Background(), context.DeadlineExceeded) {
		t.Fatal("deadline continued")
	}
}
