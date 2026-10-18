package holder

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/eclipse-xfsc/oid4-vci-credential-verification-service/internal/model"
	shared "github.com/eclipse-xfsc/oid4-vci-credential-verification-service/internal/services/common"
)

// AutoConsent delegates the entire decision to the external policy endpoint.
// Contract: {tenantId,groupId,clientId,dcqlQuery,credentials:[{queryId,credentialId}]}
// -> {approved:boolean,selections:[{queryId,credentialId,claimIds?}]}.
func AutoConsent(ctx context.Context, cfg *model.Config, row *model.VerificationEntry, sign model.FulfillPresentationRequest) error {
	if row.ConsentMode != model.ConsentAuto {
		return errors.New("auto consent is not enabled for this request")
	}
	if cfg.ExternalPresentation.CredentialSelectionPolicy == "" {
		return errors.New("auto consent policy endpoint not configured")
	}
	groups, err := resolveCredentials(ctx, cfg, row)
	if err != nil {
		return err
	}
	ids := []CredentialSelection{}
	for _, g := range groups {
		for id := range g.Credentials {
			ids = append(ids, CredentialSelection{QueryId: g.Id, CredentialID: id})
		}
	}
	result, err := GetPolicyResult(map[string]interface{}{"tenantId": row.TenantId, "groupId": row.GroupId, "clientId": row.ClientId, "dcqlQuery": row.DCQLQuery, "credentials": ids}, cfg.ExternalPresentation.CredentialSelectionPolicy)
	if err != nil {
		return err
	}
	approved, ok := result["approved"].(bool)
	if !ok {
		return errors.New("policy response missing approved boolean")
	}
	if !approved {
		changed, err := shared.TransitionPresentation(ctx, row, model.StatusPending, model.StatusRejected)
		if err != nil {
			return err
		}
		if !changed {
			return errors.New("request no longer pending")
		}
		return nil
	}
	raw, err := json.Marshal(result)
	if err != nil {
		return err
	}
	var selection PresentationSelection
	if err = json.Unmarshal(raw, &selection); err != nil {
		return err
	}
	if len(selection.Selections) == 0 {
		return fmt.Errorf("policy approved without a selection")
	}
	return FulfillSelected(ctx, cfg, row, sign, selection)
}
