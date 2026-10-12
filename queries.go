package secrets

import "context"

const (
	QueryGetReferenceSet     = "secrets.reference-set.get.v1"
	QueryListReferenceSets   = "secrets.reference-set.list.v1"
	QueryListSecretProviders = "secrets.providers.list.v1"
)

type GetReferenceSet struct{ ID string }

func (GetReferenceSet) Type() string { return QueryGetReferenceSet }
func (q GetReferenceSet) Validate() error {
	if invalidToken(q.ID) {
		return NewError(ErrorInvalidReference, "validate get query", "reference set ID is required")
	}
	return nil
}

type ListReferenceSets struct{}

func (ListReferenceSets) Type() string    { return QueryListReferenceSets }
func (ListReferenceSets) Validate() error { return nil }

type ListSecretProviders struct{}

func (ListSecretProviders) Type() string    { return QueryListSecretProviders }
func (ListSecretProviders) Validate() error { return nil }

type GetReferenceSetHandler struct{ Service QueryService }

func (h GetReferenceSetHandler) Query(ctx context.Context, query GetReferenceSet) (ReferenceSetView, error) {
	if err := query.Validate(); err != nil {
		return ReferenceSetView{}, err
	}
	return h.Service.Get(ctx, query.ID)
}

type ListReferenceSetsHandler struct{ Service QueryService }

func (h ListReferenceSetsHandler) Query(ctx context.Context, query ListReferenceSets) ([]ReferenceSetView, error) {
	if err := query.Validate(); err != nil {
		return nil, err
	}
	return h.Service.List(ctx)
}

type ListSecretProvidersHandler struct{ Service QueryService }

func (h ListSecretProvidersHandler) Query(ctx context.Context, query ListSecretProviders) ([]ProviderDescriptor, error) {
	if err := query.Validate(); err != nil {
		return nil, err
	}
	if h.Service.Registry == nil {
		return nil, NewError(ErrorInternal, "list providers", "query service is not configured")
	}
	return h.Service.Providers(), nil
}
