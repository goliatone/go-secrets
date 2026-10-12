package secrets

import (
	"context"
	"time"
)

type Event struct {
	ID             string    `json:"id"`
	Type           string    `json:"type"`
	ReferenceSetID string    `json:"reference_set_id"`
	Revision       uint64    `json:"revision"`
	ActorID        string    `json:"actor_id,omitempty"`
	CorrelationID  string    `json:"correlation_id,omitempty"`
	ChangedFields  []string  `json:"changed_fields,omitempty"`
	OccurredAt     time.Time `json:"occurred_at"`
}

type EventSink interface {
	Append(context.Context, Event) error
}

type Attempt struct {
	ProviderID  string        `json:"provider_id"`
	Fingerprint string        `json:"fingerprint"`
	Kind        ErrorKind     `json:"kind,omitempty"`
	Duration    time.Duration `json:"duration"`
}

type AttemptObserver interface {
	ObserveAttempt(context.Context, Attempt)
}
