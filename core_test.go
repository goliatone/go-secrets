package secrets

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestParseReferenceSafetyAndRedaction(t *testing.T) {
	raw := "op://vault/item/section/field"
	r, err := ParseReference(raw)
	if err != nil {
		t.Fatal(err)
	}
	if r.Scheme() != "op" || r.URI() != raw {
		t.Fatalf("unexpected reference: %#v", r)
	}
	for _, rendered := range []string{r.String(), r.String(), fmt.Sprintf("%#v", r)} {
		if strings.Contains(rendered, "vault") {
			t.Fatalf("reference leaked: %s", rendered)
		}
	}
	if _, err := json.Marshal(r); err == nil {
		t.Fatal("reference JSON serialization succeeded")
	}
}

func TestParseReferenceRejectsUnsafeGenericForms(t *testing.T) {
	bad := []string{"", " env://NAME", "env://", "1env://NAME", "env://user:pass@NAME", "env://NAME#frag", "env://NA%2fME", "env://NA%5CME", "env://NA\nME", "env:\\opaque"}
	for _, input := range bad {
		t.Run(fmt.Sprintf("%x", input), func(t *testing.T) {
			if _, err := ParseReference(input); !IsKind(err, ErrorInvalidReference) {
				t.Fatalf("got %v", err)
			}
		})
	}
	if _, err := ParseReference("custom://provider/opaque/path?mode=one"); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseReference("env://" + strings.Repeat("a", MaxReferenceBytes)); err == nil {
		t.Fatal("overlong reference accepted")
	}
}

func TestValueOwnershipBoundsDestructionAndSerialization(t *testing.T) {
	source := []byte("canary-secret")
	v, err := NewValue(source, ValueOptions{ExpiresAt: time.Unix(10, 0), Version: "v1"})
	if err != nil {
		t.Fatal(err)
	}
	source[0] = 'X'
	if string(v.Bytes()) != "canary-secret" {
		t.Fatal("value did not copy input")
	}
	if !v.Expired(time.Unix(10, 0)) || v.Version() != "v1" {
		t.Fatal("metadata mismatch")
	}
	if strings.Contains(fmt.Sprintf("%v %#v", v, v), "canary") {
		t.Fatal("value leaked while formatting")
	}
	if _, err := json.Marshal(v); err == nil {
		t.Fatal("value JSON serialization succeeded")
	}
	v.Destroy()
	v.Destroy()
	if v.Len() != 0 || v.Bytes() != nil {
		t.Fatal("value not destroyed")
	}
	if _, err := NewValue(nil, ValueOptions{}); !IsKind(err, ErrorInvalidSecret) {
		t.Fatalf("empty value: %v", err)
	}
	if _, err := NewValue([]byte("too big"), ValueOptions{MaxBytes: 2}); !IsKind(err, ErrorInvalidSecret) {
		t.Fatalf("large value: %v", err)
	}
}

func TestErrorClassificationAndSanitizedMessage(t *testing.T) {
	cause := errors.New("sanitized provider failure")
	err := WrapError(ErrorUnavailable, "resolve", "provider unavailable", cause)
	if !IsKind(err, ErrorUnavailable) || !errors.Is(err, cause) {
		t.Fatal("classification or unwrap failed")
	}
	if err.Error() != "provider unavailable" {
		t.Fatalf("unsafe error rendering: %q", err)
	}
}
