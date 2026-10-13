package model

import "github.com/eclipse-xfsc/oid4-vci-vp-library/model/presentation"

type ProofModel struct {
	Payload       []presentation.FilterResult
	SignNamespace string
	SignKey       string
	SignGroup     string
	HolderDid     string
}

// FulfillPresentationRequest contains only holder signing material. Credentials
// are deliberately not accepted here: they are resolved server-side from the
// Credential Storage Service using the transaction's persisted DCQL snapshot.
type FulfillPresentationRequest struct {
	SignNamespace string `json:"signNamespace"`
	SignKey       string `json:"signKey"`
	SignGroup     string `json:"signGroup"`
	HolderDid     string `json:"holderDid"`
}
