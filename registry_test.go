package secrets

import (
	"context"
	"fmt"
	"sync"
	"testing"
)

type registryProvider struct {
	id      string
	schemes []string
	value   string
}

func (p *registryProvider) ID() string        { return p.id }
func (p *registryProvider) Schemes() []string { return append([]string(nil), p.schemes...) }
func (p *registryProvider) Resolve(context.Context, Reference) (*Value, error) {
	return NewValue([]byte(p.value), ValueOptions{})
}

func TestRegistryConflictsReplacementAndUnregister(t *testing.T) {
	r := NewRegistry()
	one := &registryProvider{id: "one", schemes: []string{"env", "custom"}, value: "one"}
	if err := r.Register(one); err != nil {
		t.Fatal(err)
	}
	if err := r.Register(one); !IsKind(err, ErrorConflict) {
		t.Fatalf("duplicate ID: %v", err)
	}
	if err := r.Register(&registryProvider{id: "two", schemes: []string{"env"}}); !IsKind(err, ErrorConflict) {
		t.Fatalf("duplicate scheme: %v", err)
	}
	snapshot, _ := r.ProviderForScheme("env")
	two := &registryProvider{id: "one", schemes: []string{"op"}, value: "two"}
	if err := r.Replace(two); err != nil {
		t.Fatal(err)
	}
	if got, ok := r.ProviderForScheme("env"); ok || got != nil {
		t.Fatal("old scheme retained")
	}
	if got, ok := r.ProviderForScheme("op"); !ok || got != two {
		t.Fatal("replacement missing")
	}
	if value, _ := snapshot.Resolve(context.Background(), Reference{}); string(value.Bytes()) != "one" {
		t.Fatal("in-flight snapshot changed")
	}
	if !r.Unregister("one") || r.Unregister("one") {
		t.Fatal("unexpected unregister result")
	}
}

func TestRegistryValidationAndDeterministicListing(t *testing.T) {
	r := NewRegistry()
	var typedNil *registryProvider
	for _, p := range []Provider{nil, typedNil, &registryProvider{id: "", schemes: []string{"env"}}, &registryProvider{id: "x", schemes: nil}, &registryProvider{id: "x", schemes: []string{"ENV"}}, &registryProvider{id: "x", schemes: []string{"env", "env"}}} {
		if err := r.Register(p); err == nil {
			t.Fatalf("accepted invalid provider %#v", p)
		}
	}
	if err := r.Register(&registryProvider{id: "z", schemes: []string{"z"}}); err != nil {
		t.Fatal(err)
	}
	if err := r.Register(&registryProvider{id: "a", schemes: []string{"b", "a"}}); err != nil {
		t.Fatal(err)
	}
	list := r.List()
	if fmt.Sprint(list[0].ID, list[0].Schemes, list[1].ID) != "a[a b]z" {
		t.Fatalf("nondeterministic list: %#v", list)
	}
	list[0].Schemes[0] = "mutated"
	if r.List()[0].Schemes[0] != "a" {
		t.Fatal("listing was mutable")
	}
}

func TestRegistryConcurrentReadsAndWrites(t *testing.T) {
	r := NewRegistry()
	if err := r.Register(&registryProvider{id: "p", schemes: []string{"env"}}); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 20 {
		wg.Add(2)
		go func() {
			defer wg.Done()
			for range 100 {
				r.ProviderForScheme("env")
				r.List()
			}
		}()
		go func() {
			defer wg.Done()
			for j := range 100 {
				_ = r.Replace(&registryProvider{id: "p", schemes: []string{"env"}, value: fmt.Sprint(j)})
			}
		}()
	}
	wg.Wait()
}

func TestRegistryCapturesImmutableRoutingMetadata(t *testing.T) {
	r := NewRegistry()
	mutable := &registryProvider{id: "one", schemes: []string{"env"}, value: "one"}
	if err := r.Register(mutable); err != nil {
		t.Fatal(err)
	}
	mutable.id = "mutated"
	mutable.schemes[0] = "op"
	if provider, ok := r.ProviderForScheme("env"); !ok || provider != mutable {
		t.Fatal("captured route changed with provider")
	}
	if _, ok := r.ProviderForScheme("op"); ok {
		t.Fatal("mutable scheme leaked into routing")
	}
	if got := r.List(); got[0].ID != "one" || got[0].Schemes[0] != "env" {
		t.Fatalf("metadata changed: %#v", got)
	}
	if err := r.Register(&registryProvider{id: "two", schemes: []string{"env"}}); !IsKind(err, ErrorConflict) {
		t.Fatalf("captured collision missed: %v", err)
	}
}

func TestNilRegistryMutationsFailSafely(t *testing.T) {
	var registry *Registry
	if err := registry.Register(&registryProvider{id: "one", schemes: []string{"env"}}); !IsKind(err, ErrorInternal) {
		t.Fatalf("register: %v", err)
	}
	if registry.Unregister("one") {
		t.Fatal("nil registry unregistered provider")
	}
}

func TestReplaceRequiresExistingProvider(t *testing.T) {
	r := NewRegistry()
	if err := r.Replace(&registryProvider{id: "missing", schemes: []string{"env"}}); !IsKind(err, ErrorNotFound) {
		t.Fatalf("replace: %v", err)
	}
}
