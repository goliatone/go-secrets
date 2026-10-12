package secrets

import (
	"sync"
	"time"
)

const DefaultMaxValueBytes = 64 << 10

// Value is a short-lived secret owned by its caller. Bytes returns a borrowed
// view which must not outlive the Value. Destroy is best-effort and idempotent.
type Value struct {
	mu        sync.RWMutex
	data      []byte
	expiresAt time.Time
	version   string
}

type ValueOptions struct {
	MaxBytes  int
	ExpiresAt time.Time
	Version   string
}

func NewValue(data []byte, opts ValueOptions) (*Value, error) {
	max := opts.MaxBytes
	if max <= 0 {
		max = DefaultMaxValueBytes
	}
	if len(data) == 0 {
		return nil, NewError(ErrorInvalidSecret, "create value", "secret value is empty")
	}
	if len(data) > max {
		return nil, NewError(ErrorInvalidSecret, "create value", "secret value exceeds configured limit")
	}
	owned := make([]byte, len(data))
	copy(owned, data)
	return &Value{data: owned, expiresAt: opts.ExpiresAt, version: opts.Version}, nil
}

func (v *Value) Bytes() []byte {
	if v == nil {
		return nil
	}
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.data
}
func (v *Value) Len() int {
	if v == nil {
		return 0
	}
	v.mu.RLock()
	defer v.mu.RUnlock()
	return len(v.data)
}
func (v *Value) ExpiresAt() time.Time {
	if v == nil {
		return time.Time{}
	}
	return v.expiresAt
}
func (v *Value) Version() string {
	if v == nil {
		return ""
	}
	return v.version
}
func (v *Value) Expired(now time.Time) bool {
	return v != nil && !v.expiresAt.IsZero() && !now.Before(v.expiresAt)
}
func (v *Value) Destroy() {
	if v == nil {
		return
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	for i := range v.data {
		v.data[i] = 0
	}
	v.data = nil
}
func (v *Value) String() string   { return "[secret]" }
func (v *Value) GoString() string { return "[secret]" }
func (v *Value) MarshalText() ([]byte, error) {
	return nil, NewError(ErrorPermissionDenied, "serialize value", "secret values cannot be serialized")
}
func (v *Value) MarshalJSON() ([]byte, error) {
	return nil, NewError(ErrorPermissionDenied, "serialize value", "secret values cannot be serialized")
}
