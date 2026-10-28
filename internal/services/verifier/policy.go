package verifier

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/eclipse-xfsc/oid4-vci-credential-verification-service/internal/services/common"
	"github.com/eclipse-xfsc/oid4-vci-vp-library/model/presentation"
)

type PresentationPolicy struct {
	ID        string                 `json:"id"`
	DCQLQuery presentation.DCQLQuery `json:"dcqlQuery"`
}

func ResolvePresentationPolicy(ctx context.Context, tenant, group, interaction, permissionSet string) (*PresentationPolicy, *common.PresentationProfile, error) {
	if permissionSet == "" {
		return nil, nil, errors.New("permissionSet required")
	}
	profile, err := common.GetPresentationProfile(ctx, tenant, group, "verifier", interaction)
	if err != nil {
		return nil, nil, err
	}
	raw, ok := profile.PresentationPolicies[permissionSet]
	if !ok {
		return nil, nil, fmt.Errorf("permission set %q not found", permissionSet)
	}
	var dcql presentation.DCQLQuery
	if err := json.Unmarshal([]byte(raw), &dcql); err != nil {
		return nil, nil, fmt.Errorf("decode DCQL: %w", err)
	}
	if err := dcql.Validate(); err != nil {
		return nil, nil, fmt.Errorf("invalid DCQL: %w", err)
	}
	return &PresentationPolicy{ID: permissionSet, DCQLQuery: dcql}, profile, nil
}
