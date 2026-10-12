package testkit

import (
	"context"
	"sync"

	secrets "github.com/goliatone/go-secrets"
)

// Provider is a concurrency-safe deterministic provider fake. Configuration
// is changed through locked setters so tests may safely exercise live runtime
// replacement and concurrent resolution.
type Provider struct {
	mu                  sync.RWMutex
	providerID          string
	providerSchemes     []string
	value               []byte
	err                 error
	waitForCancellation bool
	maxBytes            int
	calls               []secrets.Reference
}

func NewProvider(id string, schemes ...string) *Provider {
	return &Provider{providerID: id, providerSchemes: append([]string(nil), schemes...)}
}

func (p *Provider) ID() string { p.mu.RLock(); defer p.mu.RUnlock(); return p.providerID }
func (p *Provider) Schemes() []string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return append([]string(nil), p.providerSchemes...)
}
func (p *Provider) SetValue(value []byte) {
	p.mu.Lock()
	p.value = append([]byte(nil), value...)
	p.err = nil
	p.mu.Unlock()
}
func (p *Provider) SetError(err error) { p.mu.Lock(); p.err = err; p.mu.Unlock() }
func (p *Provider) SetErrorKind(kind secrets.ErrorKind) {
	p.SetError(secrets.NewError(kind, "fake provider", "fake provider failure"))
}
func (p *Provider) SetWaitForCancellation(wait bool) {
	p.mu.Lock()
	p.waitForCancellation = wait
	p.mu.Unlock()
}
func (p *Provider) SetMaxBytes(max int) { p.mu.Lock(); p.maxBytes = max; p.mu.Unlock() }

func (p *Provider) Resolve(ctx context.Context, ref secrets.Reference) (*secrets.Value, error) {
	if ctx == nil {
		return nil, secrets.NewError(secrets.ErrorInternal, "fake provider", "context is required")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	p.mu.Lock()
	p.calls = append(p.calls, ref)
	value := append([]byte(nil), p.value...)
	err, wait, max := p.err, p.waitForCancellation, p.maxBytes
	p.mu.Unlock()
	if wait {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err != nil {
		return nil, err
	}
	return secrets.NewValue(value, secrets.ValueOptions{MaxBytes: max})
}

func (p *Provider) Calls() []secrets.Reference {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return append([]secrets.Reference(nil), p.calls...)
}
