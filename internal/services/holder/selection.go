package holder

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/eclipse-xfsc/oid4-vci-vp-library/model/presentation"
)

type CredentialSelection struct {
	QueryID      string   `json:"queryId"`
	CredentialID string   `json:"credentialId"`
	ClaimIDs     []string `json:"claimIds,omitempty"`
}
type PresentationSelection struct {
	Selections []CredentialSelection `json:"selections"`
}

// FilterSelectedCredentials ensures each selected credential exists in the server-side Storage results.
// Claim-level SD-JWT disclosure must be enforced by the signing layer; unsupported claimIds fail closed.
func FilterSelectedCredentials(groups []presentation.FilterResult, selection PresentationSelection) ([]presentation.FilterResult, error) {
	if len(selection.Selections) == 0 {
		return nil, errors.New("empty selection")
	}
	selected := map[string]map[string]bool{}
	for _, s := range selection.Selections {
		if s.QueryID == "" || s.CredentialID == "" {
			return nil, errors.New("queryId and credentialId required")
		}
		if len(s.ClaimIDs) > 0 {
			return nil, errors.New("claim-level selection is not yet supported by the signer")
		}
		if selected[s.QueryID] == nil {
			selected[s.QueryID] = map[string]bool{}
		}
		selected[s.QueryID][s.CredentialID] = true
	}
	raw, err := json.Marshal(groups)
	if err != nil {
		return nil, err
	}
	var generic []map[string]interface{}
	if err = json.Unmarshal(raw, &generic); err != nil {
		return nil, err
	}
	filtered := []map[string]interface{}{}
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
			if wanted[key] {
				matches[key] = value
				delete(wanted, key)
			}
		}
		if len(matches) > 0 {
			g["credentials"] = matches
			filtered = append(filtered, g)
		}
		delete(selected, id)
		if len(wanted) > 0 {
			return nil, fmt.Errorf("unknown credential in query %s", id)
		}
	}
	if len(selected) > 0 {
		return nil, errors.New("unknown query IDs in selection")
	}
	raw, err = json.Marshal(filtered)
	if err != nil {
		return nil, err
	}
	var result []presentation.FilterResult
	if err = json.Unmarshal(raw, &result); err != nil {
		return nil, err
	}
	return result, nil
}
