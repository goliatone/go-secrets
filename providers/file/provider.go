package file

import (
	"context"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	secrets "github.com/goliatone/go-secrets"
)

type Config struct {
	AllowedRoots        []string
	MaxBytes            int
	TrimTrailingNewline bool
}

type Provider struct {
	allowedRoots        []string
	maxBytes            int
	trimTrailingNewline bool
	configErr           error
}

func New(config Config) *Provider {
	provider := &Provider{maxBytes: config.MaxBytes, trimTrailingNewline: config.TrimTrailingNewline}
	if provider.maxBytes <= 0 {
		provider.maxBytes = secrets.DefaultMaxValueBytes
	}
	for _, root := range config.AllowedRoots {
		clean, err := filepath.Abs(strings.TrimSpace(root))
		if err != nil || !filepath.IsAbs(clean) {
			provider.configErr = secrets.NewError(secrets.ErrorPolicyDenied, "configure file provider", "allowed file root is invalid")
			return provider
		}
		if resolved, err := filepath.EvalSymlinks(clean); err == nil {
			clean = resolved
		}
		provider.allowedRoots = append(provider.allowedRoots, filepath.Clean(clean))
	}
	if len(provider.allowedRoots) == 0 {
		provider.configErr = secrets.NewError(secrets.ErrorPolicyDenied, "configure file provider", "at least one allowed file root is required")
	}
	return provider
}

func (*Provider) ID() string        { return "file" }
func (*Provider) Schemes() []string { return []string{"file-ref"} }

func (*Provider) ValidateReference(reference secrets.Reference) error {
	if reference.Scheme() != "file-ref" {
		return secrets.NewError(secrets.ErrorInvalidReference, "validate file reference", "file reference must use file-ref scheme")
	}
	parsed, err := url.Parse(reference.URI())
	if err != nil || parsed.Host != "" || parsed.RawQuery != "" || !filepath.IsAbs(parsed.Path) || filepath.Clean(parsed.Path) != parsed.Path {
		return secrets.NewError(secrets.ErrorInvalidReference, "validate file reference", "file reference must identify a clean absolute path")
	}
	return nil
}

func (p *Provider) Resolve(ctx context.Context, reference secrets.Reference) (*secrets.Value, error) {
	if ctx == nil {
		return nil, secrets.NewError(secrets.ErrorInternal, "resolve file reference", "context is required")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if p.configErr != nil {
		return nil, p.configErr
	}
	if err := p.ValidateReference(reference); err != nil {
		return nil, err
	}
	parsed, _ := url.Parse(reference.URI())
	resolved, err := filepath.EvalSymlinks(parsed.Path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, secrets.NewError(secrets.ErrorNotFound, "resolve file reference", "secret file is unavailable")
		}
		if os.IsPermission(err) {
			return nil, secrets.NewError(secrets.ErrorPermissionDenied, "resolve file reference", "secret file is not readable")
		}
		return nil, secrets.NewError(secrets.ErrorUnavailable, "resolve file reference", "secret file is unavailable")
	}
	if !p.allowed(resolved) {
		return nil, secrets.NewError(secrets.ErrorPolicyDenied, "resolve file reference", "secret file is outside allowed roots")
	}
	handle, err := openAllowedFile(resolved, p.allowedRoots)
	if err != nil {
		if os.IsPermission(err) {
			return nil, secrets.NewError(secrets.ErrorPermissionDenied, "resolve file reference", "secret file is not readable")
		}
		return nil, secrets.NewError(secrets.ErrorUnavailable, "resolve file reference", "secret file is unavailable")
	}
	defer func() { _ = handle.Close() }()
	info, err := handle.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, secrets.NewError(secrets.ErrorPolicyDenied, "resolve file reference", "secret file must be a regular file")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, secrets.NewError(secrets.ErrorPermissionDenied, "resolve file reference", "secret file permissions are not private")
	}
	if info.Size() > int64(p.maxBytes) {
		return nil, secrets.NewError(secrets.ErrorInvalidSecret, "resolve file reference", "secret file exceeds configured limit")
	}
	data, err := readBounded(ctx, handle, int64(p.maxBytes)+1)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		return nil, secrets.NewError(secrets.ErrorUnavailable, "resolve file reference", "secret file could not be read")
	}
	if err := ctx.Err(); err != nil {
		clear(data)
		return nil, err
	}
	if len(data) > p.maxBytes {
		clear(data)
		return nil, secrets.NewError(secrets.ErrorInvalidSecret, "resolve file reference", "secret file exceeds configured limit")
	}
	if p.trimTrailingNewline {
		data = trimOneLineEnding(data)
	}
	value, valueErr := secrets.NewValue(data, secrets.ValueOptions{MaxBytes: p.maxBytes})
	clear(data)
	return value, valueErr
}

type readResult struct {
	data []byte
	err  error
}

func readBounded(ctx context.Context, handle *os.File, limit int64) ([]byte, error) {
	result := make(chan readResult)
	go func() {
		data, err := io.ReadAll(io.LimitReader(handle, limit))
		select {
		case result <- readResult{data: data, err: err}:
		case <-ctx.Done():
			clear(data)
		}
	}()
	select {
	case value := <-result:
		return value.data, value.err
	case <-ctx.Done():
		_ = handle.Close()
		return nil, ctx.Err()
	}
}

func (p *Provider) allowed(path string) bool {
	path = filepath.Clean(path)
	for _, root := range p.allowedRoots {
		relative, err := filepath.Rel(root, path)
		if err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

// trimOneLineEnding removes one final LF or CRLF and preserves all other bytes.
func trimOneLineEnding(value []byte) []byte {
	if len(value) > 0 && value[len(value)-1] == '\n' {
		value = value[:len(value)-1]
		if len(value) > 0 && value[len(value)-1] == '\r' {
			value = value[:len(value)-1]
		}
	}
	return value
}
