package holder

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/eclipse-xfsc/oid4-vci-vp-library/model/presentation"
)

type ProofModel struct {
	Payload       *SelectedCredentialResult `json:"payload"`
	SignNamespace string                    `json:"signNamespace"`
	SignKey       string                    `json:"signKey"`
	SignGroup     string                    `json:"signGroup"`
	HolderDid     string                    `json:"holderDid"`
}
type CredentialSelection struct {
	QueryId      string   `json:"queryId"`
	CredentialID string   `json:"credentialId"`
	ClaimIDs     []string `json:"claimIds,omitempty"`
	Disclosures  []string `json:"disclosures,omitempty"`
}

type SelectedCredentialResult struct {
	Groups      []presentation.FilterResult `json:"groups"`
	Disclosures []CredentialDisclosure      `json:"disclosures"`
}

type CredentialDisclosure struct {
	QueryId      string   `json:"queryId"`
	CredentialID string   `json:"credentialId"`
	Disclosures  []string `json:"disclosures"`
}

type PresentationSelection struct {
	Selections []CredentialSelection `json:"selections"`
}

// FilterSelectedCredentials ensures each selected credential exists in the server-side Storage results.
// Claim-level SD-JWT disclosure must be enforced by the signing layer; unsupported claimIds fail closed.
func FilterSelectedCredentials(
	groups []presentation.FilterResult,
	selection PresentationSelection,
) (*SelectedCredentialResult, error) {

	if len(selection.Selections) == 0 {
		return nil, errors.New("empty selection")
	}

	selected := map[string]map[string]CredentialSelection{}

	for _, s := range selection.Selections {
		if s.QueryId == "" || s.CredentialID == "" {
			return nil, errors.New("queryId and credentialId required")
		}

		if len(s.ClaimIDs) > 0 {
			return nil, errors.New("claim-level selection is not yet supported by the signer")
		}

		if selected[s.QueryId] == nil {
			selected[s.QueryId] = map[string]CredentialSelection{}
		}

		if _, exists := selected[s.QueryId][s.CredentialID]; exists {
			return nil, fmt.Errorf(
				"duplicate credential %s in query %s",
				s.CredentialID,
				s.QueryId,
			)
		}

		selected[s.QueryId][s.CredentialID] = s
	}

	raw, err := json.Marshal(groups)
	if err != nil {
		return nil, err
	}

	var generic []map[string]interface{}
	if err := json.Unmarshal(raw, &generic); err != nil {
		return nil, err
	}

	filtered := []map[string]interface{}{}
	disclosures := []CredentialDisclosure{}

	for i, g := range generic {
		id := groups[i].Id

		wanted, ok := selected[id]
		if !ok {
			continue
		}

		creds, ok := g["credentials"].(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("invalid storage result for %s", id)
		}

		matches := map[string]interface{}{}

		for key, value := range creds {
			s, exists := wanted[key]
			if !exists {
				continue
			}

			matches[key] = value

			disclosures = append(disclosures, CredentialDisclosure{
				QueryId:      id,
				CredentialID: key,
				Disclosures:  append([]string(nil), s.Disclosures...),
			})

			delete(wanted, key)
		}

		if len(wanted) > 0 {
			return nil, fmt.Errorf("unknown credential in query %s", id)
		}

		if len(matches) > 0 {
			g["credentials"] = matches
			filtered = append(filtered, g)
		}

		delete(selected, id)
	}

	if len(selected) > 0 {
		return nil, errors.New("unknown query IDs in selection")
	}

	raw, err = json.Marshal(filtered)
	if err != nil {
		return nil, err
	}

	var result []presentation.FilterResult
	if err := json.Unmarshal(raw, &result); err != nil {
		return nil, err
	}

	return &SelectedCredentialResult{
		Groups:      result,
		Disclosures: disclosures,
	}, nil
}
