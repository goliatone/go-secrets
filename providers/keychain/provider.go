package keychain

import (
	"bytes"
	"context"
	"errors"
	"net/url"
	"os/exec"
	"strings"
	"time"

	secrets "github.com/goliatone/go-secrets"
	"github.com/goliatone/go-secrets/providers/internal/subprocess"
)

type Config struct {
	Executable  string
	Environment []string
	Timeout     time.Duration
	MaxBytes    int
	Runner      subprocess.Runner
}

type Provider struct {
	executable  string
	environment []string
	timeout     time.Duration
	maxBytes    int
	runner      subprocess.Runner
}

func New(config Config) *Provider {
	executable := strings.TrimSpace(config.Executable)
	if executable == "" && platformSupported() {
		executable, _ = exec.LookPath("security")
	}
	if config.Timeout <= 0 {
		config.Timeout = 10 * time.Second
	}
	if config.MaxBytes <= 0 {
		config.MaxBytes = secrets.DefaultMaxValueBytes
	}
	if config.Runner == nil {
		config.Runner = subprocess.ExecRunner{}
	}
	return &Provider{executable: executable, environment: append([]string(nil), config.Environment...), timeout: config.Timeout, maxBytes: config.MaxBytes, runner: config.Runner}
}

func (*Provider) ID() string        { return "keychain" }
func (*Provider) Schemes() []string { return []string{"keychain"} }

func (*Provider) ValidateReference(reference secrets.Reference) error {
	if reference.Scheme() != "keychain" {
		return secrets.NewError(secrets.ErrorInvalidReference, "validate keychain reference", "keychain reference must use keychain scheme")
	}
	parsed, err := url.Parse(reference.URI())
	account := strings.TrimPrefix(parsed.Path, "/")
	if err != nil || parsed.Host == "" || account == "" || strings.Contains(account, "/") || parsed.RawQuery != "" {
		return secrets.NewError(secrets.ErrorInvalidReference, "validate keychain reference", "keychain reference must be keychain://service/account")
	}
	return nil
}

func (p *Provider) Resolve(ctx context.Context, reference secrets.Reference) (*secrets.Value, error) {
	if ctx == nil {
		return nil, secrets.NewError(secrets.ErrorInternal, "resolve keychain reference", "context is required")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := p.ValidateReference(reference); err != nil {
		return nil, err
	}
	if !platformSupported() {
		return nil, secrets.NewError(secrets.ErrorUnavailable, "resolve keychain reference", "macOS Keychain is unavailable on this platform")
	}
	if p.executable == "" {
		return nil, secrets.NewError(secrets.ErrorUnavailable, "resolve keychain reference", "macOS security command is unavailable")
	}
	parsed, _ := url.Parse(reference.URI())
	account := strings.TrimPrefix(parsed.Path, "/")
	attemptCtx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()
	result, err := p.runner.Run(attemptCtx, p.executable, []string{"find-generic-password", "-s", parsed.Host, "-a", account, "-w"}, p.environment, p.maxBytes)
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
		return nil, secrets.NewError(secrets.ErrorInvalidSecret, "resolve keychain reference", "keychain output exceeds configured limit")
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
	case strings.Contains(message, "could not be found"), strings.Contains(message, "item not found"):
		kind = secrets.ErrorNotFound
	case strings.Contains(message, "user interaction is not allowed"):
		kind = secrets.ErrorAuthenticationRequired
	case strings.Contains(message, "authorization denied"), strings.Contains(message, "permission"):
		kind = secrets.ErrorPermissionDenied
	}
	return secrets.NewError(kind, "resolve keychain reference", "keychain secret could not be resolved")
}
