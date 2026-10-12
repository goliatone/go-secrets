package secrets

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func validSet(t *testing.T) ReferenceSet {
	t.Helper()
	ref, err := ParseReference("env://CANARY")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(10, 0)
	return ReferenceSet{ID: "set-1", Name: "Canary", Purpose: "test", Scope: Scope{Kind: "host", ID: "one"}, Candidates: []Candidate{{Reference: ref, Priority: 0, Enabled: true}}, Status: ReferenceSetActive, Revision: 1, CreatedAt: now, UpdatedAt: now}
}

func TestReferenceSetInvariantsAndOrdering(t *testing.T) {
	set := validSet(t)
	if err := set.Validate(); err != nil {
		t.Fatal(err)
	}
	second, _ := ParseReference("op://vault/item/field")
	set.Candidates = append(set.Candidates, Candidate{Reference: second, Priority: 2, Enabled: true})
	set.Candidates[0].Priority = 4
	ordered := set.OrderedCandidates()
	if ordered[0].Reference.Scheme() != "op" {
		t.Fatal("candidates not ordered")
	}
	duplicate := set
	duplicate.Candidates[1].Reference = duplicate.Candidates[0].Reference
	if !IsKind(duplicate.Validate(), ErrorConflict) {
		t.Fatal("duplicate accepted")
	}
	disabled := validSet(t)
	disabled.Candidates[0].Enabled = false
	if !IsKind(disabled.Validate(), ErrorDisabled) {
		t.Fatal("active empty set accepted")
	}
	disabled.Status = ReferenceSetDisabled
	if err := disabled.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestEventsAndAttemptsAreSafeToSerialize(t *testing.T) {
	set := validSet(t)
	payload, err := json.Marshal(struct {
		SetID   string  `json:"set_id"`
		Event   Event   `json:"event"`
		Attempt Attempt `json:"attempt"`
	}{set.ID, Event{ID: "e", Type: "updated", ReferenceSetID: set.ID, ChangedFields: []string{"name"}}, Attempt{ProviderID: "env", Fingerprint: set.Candidates[0].Reference.Fingerprint()}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(payload), "CANARY") {
		t.Fatalf("event leaked URI: %s", payload)
	}
}
