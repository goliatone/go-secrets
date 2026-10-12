package secrets

import (
	"context"
	"time"
)

type ReferenceSetRepository interface {
	Get(context.Context, string) (ReferenceSet, error)
	List(context.Context) ([]ReferenceSet, error)
	Create(context.Context, ReferenceSet) error
	Update(context.Context, ReferenceSet, uint64) error
	Delete(context.Context, string, uint64) error
}

type Transaction interface {
	Commit() error
	Rollback() error
}

type TransactionManager interface {
	Begin(context.Context) (context.Context, Transaction, error)
}

type Usage struct {
	Kind  string `json:"kind"`
	ID    string `json:"id"`
	Label string `json:"label,omitempty"`
}

type UsageInspector interface {
	Usages(context.Context, string) ([]Usage, error)
}

// ReferenceSetPolicyValidator is an application-owned policy boundary for
// allowed scope kinds, scope IDs, and purposes. It must not perform provider I/O.
type ReferenceSetPolicyValidator interface {
	ValidateReferenceSet(context.Context, ReferenceSet) error
}

type Clock interface{ Now() time.Time }
type IDGenerator interface{ NewID() string }
