package holder

import (
	"context"
	"errors"
	"fmt"

	commonTypes "github.com/eclipse-xfsc/oid4-vci-credential-verification-service/internal/common"
	"github.com/eclipse-xfsc/oid4-vci-credential-verification-service/internal/model"
	shared "github.com/eclipse-xfsc/oid4-vci-credential-verification-service/internal/services/common"
)

// FulfillSelected is shared by manual HTTP approval and automated NATS processing.
func FulfillSelected(ctx context.Context, cfg *model.Config, row *model.VerificationEntry, sign model.FulfillPresentationRequest, selection PresentationSelection) error {
	if sign.HolderDid == "" || sign.SignKey == "" {
		return errors.New("signing identity is required")
	}
	// Namespace and key group are independent of tenantId and holder groupId.
	// HTTP callers receive them from trusted gateway headers; NATS from its
	// separately configured machine account context.
	if sign.SignNamespace == "" || sign.SignGroup == "" {
		return errors.New("signing namespace and key group are required")
	}
	acquired, err := shared.TransitionPresentation(ctx, row, model.StatusPending, model.StatusProcessing)
	if err != nil {
		return err
	}
	if !acquired {
		return errors.New("request is not pending")
	}
	transmitted := false
	defer func() {
		if !transmitted {
			_, _ = shared.TransitionPresentation(ctx, row, model.StatusProcessing, model.StatusFailed)
		}
	}()
	groups, err := resolveCredentials(ctx, cfg, row)
	if err != nil {
		return err
	}
	selectedResult, err := FilterSelectedCredentials(groups, selection)
	if err != nil {
		return err
	}
	proof := ProofModel{Payload: selectedResult, SignNamespace: sign.SignNamespace, SignGroup: sign.SignGroup, SignKey: sign.SignKey, HolderDid: sign.HolderDid}
	logger := commonTypes.GetEnvironment().GetLogger()
	token, err := signerServiceSignPresentations(proof, row, logger, cfg)
	if err != nil {
		return err
	}
	if err = token.ValidateAgainst(&row.DCQLQuery); err != nil {
		return fmt.Errorf("DCQL selection invalid: %w", err)
	}
	if err = postResponse(ctx, token, row, logger); err != nil {
		return err
	}
	transmitted = true
	_, err = shared.TransitionPresentation(ctx, row, model.StatusProcessing, model.StatusCompleted)
	return err
}
