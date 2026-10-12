package onepassword

import (
	"bytes"
	"context"
	"errors"
	"net/url"
	"os/exec"
	"sort"
	"strings"
	"time"

	secrets "github.com/goliatone/ctx/pkg/go-secrets"
	"github.com/goliatone/ctx/pkg/go-secrets/providers/internal/subprocess"
)

type Mode string

const (
	ModeServiceAccount Mode = "service-account"
	ModeConnect        Mode = "connect"
	ModeDesktopSession Mode = "desktop-session"
)

type Config struct {
	Mode        Mode
	Foreground  bool
	Executable  string
	Environment map[string]string
	Timeout     time.Duration
	MaxBytes    int
	Runner      subprocess.Runner
}

type Diagnostic struct {
	ID         string   `json:"id"`
	Schemes    []string `json:"schemes"`
	Mode       Mode     `json:"mode"`
	Configured bool     `json:"configured"`
	Reason     string   `json:"reason,omitempty"`
}

type Provider struct {
	mode        Mode
	executable  string
	environment []string
	timeout     time.Duration
	maxBytes    int
	runner      subprocess.Runner
	diagnostic  Diagnostic
}

func New(config Config) (*Provider, error) {
	provider := &Provider{mode: config.Mode, timeout: config.Timeout, maxBytes: config.MaxBytes, runner: config.Runner}
	if provider.mode == "" {
		provider.mode = ModeServiceAccount
	}
	provider.diagnostic = Diagnostic{ID: "onepassword", Schemes: []string{"op"}, Mode: provider.mode}
	if provider.timeout <= 0 {
		provider.timeout = 15 * time.Second
	}
	if provider.maxBytes <= 0 {
		provider.maxBytes = secrets.DefaultMaxValueBytes
	}
	if provider.runner == nil {
		provider.runner = subprocess.ExecRunner{}
	}
	provider.executable = strings.TrimSpace(config.Executable)
	if provider.executable == "" {
		provider.executable, _ = exec.LookPath("op")
	}

	required := []string{}
	switch provider.mode {
	case ModeServiceAccount:
		required = []string{"OP_SERVICE_ACCOUNT_TOKEN"}
	case ModeConnect:
		required = []string{"OP_CONNECT_HOST", "OP_CONNECT_TOKEN"}
	case ModeDesktopSession:
		if !config.Foreground {
			return nil, secrets.NewError(secrets.ErrorPolicyDenied, "configure 1password provider", "desktop session mode is allowed only for foreground operations")
		}
	default:
		return nil, secrets.NewError(secrets.ErrorInvalidReference, "configure 1password provider", "1Password provider mode is invalid")
	}
	for _, name := range required {
		if strings.TrimSpace(config.Environment[name]) == "" {
			provider.diagnostic.Reason = "required mode configuration is missing"
			return provider, nil
		}
	}
	if provider.executable == "" {
		provider.diagnostic.Reason = "op executable is unavailable"
		return provider, nil
	}
	environment := make(map[string]string, len(config.Environment)+1)
	for name, value := range config.Environment {
		if strings.TrimSpace(name) != name || name == "" || strings.ContainsRune(name, '=') {
			return nil, secrets.NewError(secrets.ErrorInvalidReference, "configure 1password provider", "1Password environment is invalid")
		}
		environment[name] = value
	}
	environment["OP_BIOMETRIC_UNLOCK_ENABLED"] = "false"
	names := make([]string, 0, len(environment))
	for name := range environment {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		provider.environment = append(provider.environment, name+"="+environment[name])
	}
	provider.diagnostic.Configured = true
	return provider, nil
}

func (*Provider) ID() string        { return "onepassword" }
func (*Provider) Schemes() []string { return []string{"op"} }

func (p *Provider) Diagnostic() Diagnostic {
	value := p.diagnostic
	value.Schemes = append([]string(nil), value.Schemes...)
	return value
}

func (*Provider) ValidateReference(reference secrets.Reference) error {
	if reference.Scheme() != "op" {
		return secrets.NewError(secrets.ErrorInvalidReference, "validate 1password reference", "1Password reference must use op scheme")
	}
	parsed, err := url.Parse(reference.URI())
	segments := strings.Split(strings.TrimPrefix(parsed.Path, "/"), "/")
	if err != nil || parsed.Host == "" || parsed.RawQuery != "" || len(segments) < 2 || len(segments) > 3 {
		return secrets.NewError(secrets.ErrorInvalidReference, "validate 1password reference", "1Password reference must be op://vault/item/[section/]field")
	}
	for _, segment := range segments {
		if strings.TrimSpace(segment) == "" {
			return secrets.NewError(secrets.ErrorInvalidReference, "validate 1password reference", "1Password reference must be op://vault/item/[section/]field")
		}
	}
	return nil
}

func (p *Provider) Resolve(ctx context.Context, reference secrets.Reference) (*secrets.Value, error) {
	if ctx == nil {
		return nil, secrets.NewError(secrets.ErrorInternal, "resolve 1password reference", "context is required")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := p.ValidateReference(reference); err != nil {
		return nil, err
	}
	if !p.diagnostic.Configured {
		return nil, secrets.NewError(secrets.ErrorUnavailable, "resolve 1password reference", p.diagnostic.Reason)
	}
	attemptCtx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()
	result, err := p.runner.Run(attemptCtx, p.executable, []string{"read", "--no-newline", reference.URI()}, p.environment, p.maxBytes)
	if attemptErr := attemptCtx.Err(); attemptErr != nil {
		clear(result.Stdout)
		clear(result.Stderr)
		return nil, attemptErr
	}
	if err != nil {
		classified := classifyError(err, result.Stderr)
		clear(result.Stdout)
		clear(result.Stderr)
		return nil, classified
	}
	clear(result.Stderr)
	if result.OutputExceeded || len(result.Stdout) > p.maxBytes {
		clear(result.Stdout)
		return nil, secrets.NewError(secrets.ErrorInvalidSecret, "resolve 1password reference", "1Password output exceeds configured limit")
	}
	output := bytes.TrimSuffix(result.Stdout, []byte("\n"))
	output = bytes.TrimSuffix(output, []byte("\r"))
	value, valueErr := secrets.NewValue(output, secrets.ValueOptions{MaxBytes: p.maxBytes})
	clear(result.Stdout)
	clear(output)
	return value, valueErr
}

func classifyError(err error, stderr []byte) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	message := strings.ToLower(string(stderr))
	kind := secrets.ErrorUnavailable
	switch {
	case strings.Contains(message, "isn't an item in"), strings.Contains(message, "not found"), strings.Contains(message, "does not exist"):
		kind = secrets.ErrorNotFound
	case strings.Contains(message, "not signed in"), strings.Contains(message, "authentication"), strings.Contains(message, "sign in"):
		kind = secrets.ErrorAuthenticationRequired
	case strings.Contains(message, "permission"), strings.Contains(message, "forbidden"), strings.Contains(message, "unauthorized"):
		kind = secrets.ErrorPermissionDenied
	case strings.Contains(message, "timeout"), strings.Contains(message, "temporarily"), strings.Contains(message, "connection"), strings.Contains(message, "network"):
		kind = secrets.ErrorTemporary
	}
	return secrets.NewError(kind, "resolve 1password reference", "1Password secret could not be resolved")
}
