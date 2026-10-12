//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package file

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	secrets "github.com/goliatone/go-secrets"
	"golang.org/x/sys/unix"
)

func TestFileProviderRejectsFIFOWithoutBlocking(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "secret-pipe")
	if err := unix.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	reference, err := secrets.ParseReference("file-ref://" + path)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	started := time.Now()
	_, err = New(Config{AllowedRoots: []string{root}}).Resolve(ctx, reference)
	if !secrets.IsKind(err, secrets.ErrorPolicyDenied) {
		t.Fatalf("FIFO returned %v", err)
	}
	if elapsed := time.Since(started); elapsed >= 200*time.Millisecond {
		t.Fatalf("FIFO open blocked for %s", elapsed)
	}
}
