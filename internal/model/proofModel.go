package model

// FulfillPresentationRequest contains only holder signing material. Credentials
// are deliberately not accepted here: they are resolved server-side from the
// Credential Storage Service using the transaction's persisted DCQL snapshot.
type FulfillPresentationRequest struct {
	SignNamespace string `json:"signNamespace"`
	SignKey       string `json:"signKey"`
	SignGroup     string `json:"signGroup"`
	HolderDid     string `json:"holderDid"`
}
