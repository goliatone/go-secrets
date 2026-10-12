package secrets

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"unicode"
)

const MaxReferenceBytes = 4096

var schemePattern = regexp.MustCompile(`^[a-z][a-z0-9+.-]*$`)

// Reference contains confidential provider metadata. URI is intentionally an
// explicit accessor; normal formatting returns only a stable fingerprint.
type Reference struct {
	raw         string
	scheme      string
	fingerprint string
}

func ParseReference(raw string) (Reference, error) {
	const op = "parse reference"
	if raw == "" || len(raw) > MaxReferenceBytes || strings.TrimSpace(raw) != raw {
		return Reference{}, NewError(ErrorInvalidReference, op, "invalid secret reference")
	}
	for _, r := range raw {
		if r == 0 || unicode.IsControl(r) {
			return Reference{}, NewError(ErrorInvalidReference, op, "invalid secret reference")
		}
	}
	lower := strings.ToLower(raw)
	if strings.Contains(lower, "%2f") || strings.Contains(lower, "%5c") {
		return Reference{}, NewError(ErrorInvalidReference, op, "ambiguous secret reference")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || !schemePattern.MatchString(u.Scheme) || u.User != nil || u.Fragment != "" || u.Opaque != "" {
		return Reference{}, NewError(ErrorInvalidReference, op, "invalid secret reference")
	}
	// Provider-specific host/path/query rules remain provider-owned, but a
	// reference must carry some opaque locator after its scheme.
	if u.Host == "" && u.Path == "" && u.RawQuery == "" {
		return Reference{}, NewError(ErrorInvalidReference, op, "secret reference has no locator")
	}
	sum := sha256.Sum256([]byte(raw))
	return Reference{raw: raw, scheme: u.Scheme, fingerprint: hex.EncodeToString(sum[:8])}, nil
}

func (r Reference) Scheme() string      { return r.scheme }
func (r Reference) URI() string         { return r.raw }
func (r Reference) Fingerprint() string { return r.fingerprint }
func (r Reference) Redacted() string {
	if r.scheme == "" || r.fingerprint == "" {
		return "secret-ref:[invalid]"
	}
	return fmt.Sprintf("%s://[redacted]#%s", r.scheme, r.fingerprint)
}
func (r Reference) String() string               { return r.Redacted() }
func (r Reference) GoString() string             { return r.Redacted() }
func (r Reference) MarshalText() ([]byte, error) { return []byte(r.Redacted()), nil }
func (r Reference) MarshalJSON() ([]byte, error) {
	return nil, NewError(ErrorPermissionDenied, "serialize reference", "raw secret references cannot be serialized")
}
