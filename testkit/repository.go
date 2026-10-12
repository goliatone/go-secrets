package testkit

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	secrets "github.com/goliatone/ctx/pkg/go-secrets"
)

type Repository struct {
	mu   sync.RWMutex
	sets map[string]secrets.ReferenceSet
}

func NewRepository() *Repository { return &Repository{sets: map[string]secrets.ReferenceSet{}} }

type repositoryTxKey struct{}
type repositoryTx struct {
	repo *Repository
	sets map[string]secrets.ReferenceSet
	done bool
}

func (r *Repository) Begin(ctx context.Context) (context.Context, secrets.Transaction, error) {
	if ctx == nil {
		return nil, nil, secrets.NewError(secrets.ErrorInternal, "begin transaction", "context is required")
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	r.mu.Lock()
	staged := cloneSets(r.sets)
	tx := &repositoryTx{repo: r, sets: staged}
	return context.WithValue(ctx, repositoryTxKey{}, tx), tx, nil
}
func (tx *repositoryTx) Commit() error {
	if tx.done {
		return secrets.NewError(secrets.ErrorConflict, "commit transaction", "transaction is closed")
	}
	tx.repo.sets = cloneSets(tx.sets)
	tx.done = true
	tx.repo.mu.Unlock()
	return nil
}
func (tx *repositoryTx) Rollback() error {
	if tx.done {
		return nil
	}
	tx.done = true
	tx.repo.mu.Unlock()
	return nil
}

func (r *Repository) Get(ctx context.Context, id string) (secrets.ReferenceSet, error) {
	if tx := transactionFrom(ctx, r); tx != nil {
		return getSet(tx.sets, id)
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return getSet(r.sets, id)
}
func (r *Repository) List(ctx context.Context) ([]secrets.ReferenceSet, error) {
	if tx := transactionFrom(ctx, r); tx != nil {
		return listSets(tx.sets), nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return listSets(r.sets), nil
}
func (r *Repository) Create(ctx context.Context, set secrets.ReferenceSet) error {
	if tx := transactionFrom(ctx, r); tx != nil {
		return createSet(tx.sets, set)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return createSet(r.sets, set)
}
func (r *Repository) Update(ctx context.Context, set secrets.ReferenceSet, expected uint64) error {
	if tx := transactionFrom(ctx, r); tx != nil {
		return updateSet(tx.sets, set, expected)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return updateSet(r.sets, set, expected)
}
func (r *Repository) Delete(ctx context.Context, id string, expected uint64) error {
	if tx := transactionFrom(ctx, r); tx != nil {
		return deleteSet(tx.sets, id, expected)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return deleteSet(r.sets, id, expected)
}

func transactionFrom(ctx context.Context, repo *Repository) *repositoryTx {
	if ctx == nil {
		return nil
	}
	tx, _ := ctx.Value(repositoryTxKey{}).(*repositoryTx)
	if tx == nil || tx.repo != repo || tx.done {
		return nil
	}
	return tx
}
func cloneSets(source map[string]secrets.ReferenceSet) map[string]secrets.ReferenceSet {
	out := make(map[string]secrets.ReferenceSet, len(source))
	for id, set := range source {
		out[id] = set.Clone()
	}
	return out
}
func getSet(sets map[string]secrets.ReferenceSet, id string) (secrets.ReferenceSet, error) {
	set, ok := sets[id]
	if !ok {
		return secrets.ReferenceSet{}, secrets.NewError(secrets.ErrorNotFound, "get reference set", "reference set not found")
	}
	return set.Clone(), nil
}
func listSets(sets map[string]secrets.ReferenceSet) []secrets.ReferenceSet {
	out := make([]secrets.ReferenceSet, 0, len(sets))
	for _, set := range sets {
		out = append(out, set.Clone())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
func createSet(sets map[string]secrets.ReferenceSet, set secrets.ReferenceSet) error {
	if _, ok := sets[set.ID]; ok {
		return secrets.NewError(secrets.ErrorConflict, "create reference set", "reference set exists")
	}
	sets[set.ID] = set.Clone()
	return nil
}
func updateSet(sets map[string]secrets.ReferenceSet, set secrets.ReferenceSet, expected uint64) error {
	current, ok := sets[set.ID]
	if !ok {
		return secrets.NewError(secrets.ErrorNotFound, "update reference set", "reference set not found")
	}
	if current.Revision != expected {
		return secrets.NewError(secrets.ErrorConflict, "update reference set", "reference set revision conflict")
	}
	sets[set.ID] = set.Clone()
	return nil
}
func deleteSet(sets map[string]secrets.ReferenceSet, id string, expected uint64) error {
	current, ok := sets[id]
	if !ok {
		return secrets.NewError(secrets.ErrorNotFound, "delete reference set", "reference set not found")
	}
	if current.Revision != expected {
		return secrets.NewError(secrets.ErrorConflict, "delete reference set", "reference set revision conflict")
	}
	delete(sets, id)
	return nil
}

type Clock struct {
	mu      sync.Mutex
	Current time.Time
}

func (c *Clock) Now() time.Time          { c.mu.Lock(); defer c.mu.Unlock(); return c.Current }
func (c *Clock) Advance(d time.Duration) { c.mu.Lock(); c.Current = c.Current.Add(d); c.mu.Unlock() }

type IDs struct {
	mu     sync.Mutex
	Prefix string
	next   int
}

func (g *IDs) NewID() string {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.next++
	return fmt.Sprintf("%s%d", g.Prefix, g.next)
}

type Observer struct {
	mu       sync.Mutex
	attempts []secrets.Attempt
}

func (o *Observer) ObserveAttempt(_ context.Context, attempt secrets.Attempt) {
	o.mu.Lock()
	o.attempts = append(o.attempts, attempt)
	o.mu.Unlock()
}
func (o *Observer) Snapshot() []secrets.Attempt {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]secrets.Attempt(nil), o.attempts...)
}
