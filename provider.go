package secrets

import "context"

// Provider resolves references for one or more URI schemes.
type Provider interface {
	ID() string
	Schemes() []string
	Resolve(context.Context, Reference) (*Value, error)
}

// ReferenceValidator is an optional parse-only provider capability.
type ReferenceValidator interface{ ValidateReference(Reference) error }

// ReferenceDescriptorLister is an optional capability for safe, redacted
// operator choices. Returned descriptors must never contain raw references.
type ReferenceDescriptorLister interface {
	ListReferenceDescriptors(context.Context) ([]ReferenceDescriptor, error)
}

// SecretWriter is an optional capability reserved for providers that manage
// values. Applications must separately authorize its use.
type SecretWriter interface {
	Write(context.Context, Reference, *Value) error
}

type ReferenceDescriptor struct {
	ID    string `json:"id"`
	Label string `json:"label"`
}

type ProviderDescriptor struct {
	ID          string   `json:"id"`
	Schemes     []string `json:"schemes"`
	CanValidate bool     `json:"can_validate"`
	CanList     bool     `json:"can_list"`
	CanWrite    bool     `json:"can_write"`
}
