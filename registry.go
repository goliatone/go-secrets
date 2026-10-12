package secrets

import (
	"maps"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
)

type registryEntry struct {
	provider   Provider
	descriptor ProviderDescriptor
}

type registryState struct {
	byID        map[string]registryEntry
	byScheme    map[string]registryEntry
	descriptors []ProviderDescriptor
}

// Registry publishes immutable routing metadata snapshots. Provider objects
// remain owned by their implementations, while IDs and schemes are captured
// once at registration and never re-read for routing or conflict detection.
type Registry struct {
	writeMu sync.Mutex
	state   atomic.Pointer[registryState]
}

// ProviderSnapshot is an immutable routing view retained for one operation.
// Later registry replacements do not affect lookups through this snapshot.
type ProviderSnapshot struct{ state *registryState }

func (r *Registry) Snapshot() ProviderSnapshot { return ProviderSnapshot{state: r.snapshot()} }
func (s ProviderSnapshot) ProviderForScheme(scheme string) (Provider, bool) {
	_, provider, ok := s.Lookup(scheme)
	return provider, ok
}
func (s ProviderSnapshot) Lookup(scheme string) (ProviderDescriptor, Provider, bool) {
	if s.state == nil {
		return ProviderDescriptor{}, nil, false
	}
	entry, ok := s.state.byScheme[strings.ToLower(strings.TrimSpace(scheme))]
	if !ok {
		return ProviderDescriptor{}, nil, false
	}
	descriptor := entry.descriptor
	descriptor.Schemes = append([]string(nil), descriptor.Schemes...)
	return descriptor, entry.provider, true
}

func NewRegistry() *Registry {
	r := &Registry{}
	r.state.Store(buildRegistryState(nil))
	return r
}

func (r *Registry) snapshot() *registryState {
	if r == nil {
		return buildRegistryState(nil)
	}
	if state := r.state.Load(); state != nil {
		return state
	}
	empty := buildRegistryState(nil)
	r.state.CompareAndSwap(nil, empty)
	return r.state.Load()
}

func (r *Registry) Register(provider Provider) error { return r.store(provider, false) }
func (r *Registry) Replace(provider Provider) error  { return r.store(provider, true) }

func (r *Registry) store(provider Provider, replace bool) error {
	const op = "register provider"
	if r == nil {
		return NewError(ErrorInternal, op, "provider registry is not configured")
	}
	entry, err := newRegistryEntry(provider)
	if err != nil {
		return err
	}
	r.writeMu.Lock()
	defer r.writeMu.Unlock()
	current := r.snapshot()
	entries := cloneRegistryEntries(current.byID)
	id := entry.descriptor.ID
	_, exists := entries[id]
	if exists && !replace {
		return NewError(ErrorConflict, op, "provider ID is already registered")
	}
	if replace && !exists {
		return NewError(ErrorNotFound, op, "provider ID is not registered")
	}
	if replace {
		delete(entries, id)
	}
	for _, scheme := range entry.descriptor.Schemes {
		if owner, exists := current.byScheme[scheme]; exists && owner.descriptor.ID != id {
			return NewError(ErrorConflict, op, "provider scheme is already registered")
		}
	}
	entries[id] = entry
	r.state.Store(buildRegistryState(entries))
	return nil
}

func (r *Registry) Unregister(id string) bool {
	if r == nil {
		return false
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return false
	}
	r.writeMu.Lock()
	defer r.writeMu.Unlock()
	current := r.snapshot()
	if _, exists := current.byID[id]; !exists {
		return false
	}
	entries := cloneRegistryEntries(current.byID)
	delete(entries, id)
	r.state.Store(buildRegistryState(entries))
	return true
}

func (r *Registry) Provider(id string) (Provider, bool) {
	entry, ok := r.snapshot().byID[id]
	return entry.provider, ok
}
func (r *Registry) ProviderForScheme(scheme string) (Provider, bool) {
	return r.Snapshot().ProviderForScheme(scheme)
}
func (r *Registry) List() []ProviderDescriptor {
	descriptors := r.snapshot().descriptors
	out := make([]ProviderDescriptor, len(descriptors))
	for i, descriptor := range descriptors {
		out[i] = descriptor
		out[i].Schemes = append([]string(nil), descriptor.Schemes...)
	}
	return out
}

func newRegistryEntry(provider Provider) (registryEntry, error) {
	const op = "register provider"
	if isNilProvider(provider) {
		return registryEntry{}, NewError(ErrorInvalidReference, op, "provider is nil")
	}
	id := strings.TrimSpace(provider.ID())
	if id == "" || id != provider.ID() {
		return registryEntry{}, NewError(ErrorInvalidReference, op, "provider ID is invalid")
	}
	rawSchemes := provider.Schemes()
	if len(rawSchemes) == 0 {
		return registryEntry{}, NewError(ErrorInvalidReference, op, "provider has no schemes")
	}
	seen := map[string]struct{}{}
	schemes := make([]string, 0, len(rawSchemes))
	for _, raw := range rawSchemes {
		scheme := strings.ToLower(strings.TrimSpace(raw))
		if scheme != raw || !schemePattern.MatchString(scheme) {
			return registryEntry{}, NewError(ErrorInvalidReference, op, "provider scheme is invalid")
		}
		if _, exists := seen[scheme]; exists {
			return registryEntry{}, NewError(ErrorInvalidReference, op, "provider scheme is duplicated")
		}
		seen[scheme] = struct{}{}
		schemes = append(schemes, scheme)
	}
	sort.Strings(schemes)
	_, canValidate := provider.(ReferenceValidator)
	_, canList := provider.(ReferenceDescriptorLister)
	_, canWrite := provider.(SecretWriter)
	return registryEntry{provider: provider, descriptor: ProviderDescriptor{ID: id, Schemes: schemes, CanValidate: canValidate, CanList: canList, CanWrite: canWrite}}, nil
}

func isNilProvider(provider Provider) bool {
	return isNilInterface(provider)
}

func cloneRegistryEntries(source map[string]registryEntry) map[string]registryEntry {
	out := make(map[string]registryEntry, len(source))
	maps.Copy(out, source)
	return out
}

func buildRegistryState(entries map[string]registryEntry) *registryState {
	state := &registryState{byID: map[string]registryEntry{}, byScheme: map[string]registryEntry{}}
	for id, entry := range entries {
		state.byID[id] = entry
		for _, scheme := range entry.descriptor.Schemes {
			state.byScheme[scheme] = entry
		}
		descriptor := entry.descriptor
		descriptor.Schemes = append([]string(nil), descriptor.Schemes...)
		state.descriptors = append(state.descriptors, descriptor)
	}
	sort.Slice(state.descriptors, func(i, j int) bool { return state.descriptors[i].ID < state.descriptors[j].ID })
	return state
}
