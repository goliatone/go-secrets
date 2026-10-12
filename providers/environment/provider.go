package environment

import (
	"context"
	"net/url"
	"os"
	"regexp"

	secrets "github.com/goliatone/ctx/pkg/go-secrets"
)

var namePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

type LookupFunc func(string) (string, bool)

type Config struct {
	Lookup   LookupFunc
	MaxBytes int
}

type Provider struct {
	lookup   LookupFunc
	maxBytes int
}

func New(config Config) *Provider {
	lookup := config.Lookup
	if lookup == nil {
		lookup = os.LookupEnv
	}
	return &Provider{lookup: lookup, maxBytes: config.MaxBytes}
}

func (*Provider) ID() string        { return "environment" }
func (*Provider) Schemes() []string { return []string{"env"} }

func (*Provider) ValidateReference(reference secrets.Reference) error {
	if reference.Scheme() != "env" {
		return secrets.NewError(secrets.ErrorInvalidReference, "validate environment reference", "environment reference must use env scheme")
	}
	parsed, err := url.Parse(reference.URI())
	if err != nil || !namePattern.MatchString(parsed.Host) || parsed.Path != "" || parsed.RawQuery != "" {
		return secrets.NewError(secrets.ErrorInvalidReference, "validate environment reference", "environment reference must be env://NAME")
	}
	return nil
}

func (p *Provider) Resolve(ctx context.Context, reference secrets.Reference) (*secrets.Value, error) {
	if ctx == nil {
		return nil, secrets.NewError(secrets.ErrorInternal, "resolve environment reference", "context is required")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := p.ValidateReference(reference); err != nil {
		return nil, err
	}
	if p == nil || p.lookup == nil {
		return nil, secrets.NewError(secrets.ErrorUnavailable, "resolve environment reference", "environment provider is not configured")
	}
	parsed, _ := url.Parse(reference.URI())
	value, ok := p.lookup(parsed.Host)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !ok || value == "" {
		return nil, secrets.NewError(secrets.ErrorNotFound, "resolve environment reference", "environment secret is unavailable")
	}
	return secrets.NewValue([]byte(value), secrets.ValueOptions{MaxBytes: p.maxBytes})
}
