package secrets

import (
	"sort"
	"strings"
	"time"
)

type ReferenceSetStatus string

const MaxCandidates = 32

const (
	ReferenceSetActive   ReferenceSetStatus = "active"
	ReferenceSetDisabled ReferenceSetStatus = "disabled"
)

type Scope struct {
	Kind string `json:"kind"`
	ID   string `json:"id"`
}

func (s Scope) Valid() bool {
	return strings.TrimSpace(s.Kind) == s.Kind && s.Kind != "" && strings.TrimSpace(s.ID) == s.ID && s.ID != ""
}

type Candidate struct {
	Reference Reference
	Priority  int
	Enabled   bool
}

type ReferenceSet struct {
	ID         string
	Name       string
	Purpose    string
	Scope      Scope
	Candidates []Candidate
	Status     ReferenceSetStatus
	Revision   uint64
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

func (s ReferenceSet) Validate() error {
	if strings.TrimSpace(s.ID) != s.ID || s.ID == "" || strings.TrimSpace(s.Name) == "" || strings.TrimSpace(s.Purpose) != s.Purpose || s.Purpose == "" || !s.Scope.Valid() || s.Revision == 0 || s.CreatedAt.IsZero() || s.UpdatedAt.IsZero() || s.UpdatedAt.Before(s.CreatedAt) {
		return NewError(ErrorInvalidReference, "validate reference set", "reference set metadata is invalid")
	}
	if s.Status != ReferenceSetActive && s.Status != ReferenceSetDisabled {
		return NewError(ErrorInvalidReference, "validate reference set", "reference set status is invalid")
	}
	if len(s.Candidates) > MaxCandidates {
		return NewError(ErrorInvalidReference, "validate reference set", "reference set has too many candidates")
	}
	seenReferences, seenPriorities := map[string]struct{}{}, map[int]struct{}{}
	enabled := 0
	for _, candidate := range s.Candidates {
		if candidate.Reference.URI() == "" || candidate.Priority < 0 {
			return NewError(ErrorInvalidReference, "validate reference set", "reference candidate is invalid")
		}
		if _, exists := seenReferences[candidate.Reference.Fingerprint()]; exists {
			return NewError(ErrorConflict, "validate reference set", "reference candidate is duplicated")
		}
		if _, exists := seenPriorities[candidate.Priority]; exists {
			return NewError(ErrorConflict, "validate reference set", "reference priority is duplicated")
		}
		seenReferences[candidate.Reference.Fingerprint()] = struct{}{}
		seenPriorities[candidate.Priority] = struct{}{}
		if candidate.Enabled {
			enabled++
		}
	}
	if s.Status == ReferenceSetActive && enabled == 0 {
		return NewError(ErrorDisabled, "validate reference set", "active reference set has no enabled candidates")
	}
	return nil
}

func (s ReferenceSet) OrderedCandidates() []Candidate {
	out := append([]Candidate(nil), s.Candidates...)
	sort.SliceStable(out, func(i, j int) bool { return out[i].Priority < out[j].Priority })
	return out
}

func (s ReferenceSet) Clone() ReferenceSet {
	s.Candidates = append([]Candidate(nil), s.Candidates...)
	return s
}
