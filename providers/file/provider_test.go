package file

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	secrets "github.com/goliatone/go-secrets"
	"github.com/goliatone/go-secrets/testkit"
)

func TestProviderConformance(t *testing.T) {
	root := t.TempDir()
	valid := filepath.Join(root, "token")
	if err := os.WriteFile(valid, []byte("value\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	provider := New(Config{AllowedRoots: []string{root}, TrimTrailingNewline: true})
	testkit.RunProviderConformance(t, provider, "file-ref://"+valid, "file-ref://"+filepath.Join(root, "missing"))
}

func TestFilePolicyAndLineEnding(t *testing.T) {
	root, outside := t.TempDir(), t.TempDir()
	private := filepath.Join(root, "token")
	if err := os.WriteFile(private, []byte(" value \r\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	provider := New(Config{AllowedRoots: []string{root}, TrimTrailingNewline: true})
	reference, _ := secrets.ParseReference("file-ref://" + private)
	value, err := provider.Resolve(context.Background(), reference)
	if err != nil || string(value.Bytes()) != " value " {
		t.Fatalf("line ending handling = %q, %v", value.Bytes(), err)
	}
	value.Destroy()

	outsideFile := filepath.Join(outside, "token")
	if err := os.WriteFile(outsideFile, []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	outsideReference, _ := secrets.ParseReference("file-ref://" + outsideFile)
	if _, err := provider.Resolve(context.Background(), outsideReference); !secrets.IsKind(err, secrets.ErrorPolicyDenied) {
		t.Fatalf("outside root returned %v", err)
	}
	link := filepath.Join(root, "outside-link")
	if err := os.Symlink(outsideFile, link); err == nil {
		linkReference, _ := secrets.ParseReference("file-ref://" + link)
		if _, err := provider.Resolve(context.Background(), linkReference); !secrets.IsKind(err, secrets.ErrorPolicyDenied) {
			t.Fatalf("symlink escape returned %v", err)
		}
	}

	if runtime.GOOS != "windows" {
		if err := os.Chmod(private, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := provider.Resolve(context.Background(), reference); !secrets.IsKind(err, secrets.ErrorPermissionDenied) {
			t.Fatalf("public file returned %v", err)
		}
	}
}

func TestFileBoundsAndGrammar(t *testing.T) {
	root := t.TempDir()
	filename := filepath.Join(root, "token")
	if err := os.WriteFile(filename, []byte("oversized"), 0o600); err != nil {
		t.Fatal(err)
	}
	provider := New(Config{AllowedRoots: []string{root}, MaxBytes: 3})
	reference, _ := secrets.ParseReference("file-ref://" + filename)
	if _, err := provider.Resolve(context.Background(), reference); !secrets.IsKind(err, secrets.ErrorInvalidSecret) || strings.Contains(err.Error(), "oversized") {
		t.Fatalf("oversized file returned unsafe error %v", err)
	}
	for _, raw := range []string{"file-ref://relative", "file-ref:///tmp/../tmp/token", "file-ref:///tmp/token?x=1", "env://TOKEN"} {
		reference, err := secrets.ParseReference(raw)
		if err == nil {
			err = provider.ValidateReference(reference)
		}
		if !secrets.IsKind(err, secrets.ErrorInvalidReference) {
			t.Fatalf("reference %q returned %v", raw, err)
		}
	}
}
