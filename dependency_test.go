package secrets

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestCoreDependencyBoundary(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), filepath.Join(".", entry.Name()), nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, spec := range file.Imports {
			path, _ := strconv.Unquote(spec.Path.Value)
			forbidden := strings.Contains(path, "/internal/") || strings.Contains(path, "go-command") || strings.Contains(path, "modernc.org/sqlite") || strings.Contains(path, "pkg/go-secrets/providers")
			if forbidden {
				t.Fatalf("core file %s imports forbidden dependency %s", entry.Name(), path)
			}
		}
	}
}
