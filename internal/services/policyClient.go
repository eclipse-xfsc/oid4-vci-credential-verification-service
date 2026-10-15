package services

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/eclipse-xfsc/oid4-vci-credential-verification-service/internal/common"
	"github.com/eclipse-xfsc/oid4-vci-vp-library/model/presentation"
)

func GetPolicyResult(input interface{}, policy string) (map[string]interface{}, error) {
	cfg := common.GetEnvironment().GetConfig()
	endpoint, err := validateOutboundURL(policy, cfg, false)
	if err != nil {
		return nil, fmt.Errorf("invalid policy URL: %w", err)
	}
	body, err := json.Marshal(input)
	if err != nil {
		return nil, err
	}
	r, err := http.NewRequest(http.MethodPost, endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json")
	res, err := secureHTTPClient().Do(r)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, maxHTTPResponseBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > maxHTTPResponseBytes {
		return nil, errors.New("policy response exceeds size limit")
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return nil, fmt.Errorf("policy returned HTTP %d: %s", res.StatusCode, strings.TrimSpace(string(raw)))
	}
	var post map[string]interface{}
	if err := json.Unmarshal(raw, &post); err != nil {
		return nil, fmt.Errorf("invalid policy response: %w", err)
	}
	return post, nil
}

func policyAllows(result map[string]interface{}) bool {
	switch v := result["allow"].(type) {
	case bool:
		return v
	case string:
		return strings.EqualFold(v, "true")
	default:
		return false
	}
}

// applyCredentialSelectionPolicy delegates consent/credential selection to the
// configured policy service. Contract:
// request: {tenantId, groupId, clientId, dcqlQuery, candidates}
// response: {"allow":true,"selection":{"<query-id>":["<credential-key>"]}}
// Empty selection means "use all matched candidates" when allow=true.
func applyCredentialSelectionPolicy(rowTenant, groupID, clientID string, query presentation.DCQLQuery, candidates []presentation.FilterResult, policy string) ([]presentation.FilterResult, error) {
	if strings.TrimSpace(policy) == "" {
		return candidates, nil
	}
	result, err := GetPolicyResult(map[string]interface{}{
		"tenantId": rowTenant, "groupId": groupID, "clientId": clientID,
		"dcqlQuery": query, "candidates": candidates,
	}, policy)
	if err != nil {
		return nil, err
	}
	if !policyAllows(result) {
		return nil, errors.New("credential selection policy denied disclosure")
	}
	selection, ok := result["selection"].(map[string]interface{})
	if !ok || len(selection) == 0 {
		return candidates, nil
	}

	raw, err := json.Marshal(candidates)
	if err != nil {
		return nil, err
	}
	var generic []map[string]interface{}
	if err := json.Unmarshal(raw, &generic); err != nil {
		return nil, err
	}
	selectedGroups := make([]map[string]interface{}, 0, len(generic))
	for i, group := range generic {
		id := candidates[i].Id
		wantedRaw, exists := selection[id]
		if !exists {
			continue
		}
		wantedList, ok := wantedRaw.([]interface{})
		if !ok {
			return nil, fmt.Errorf("policy selection for %s must be an array", id)
		}
		wanted := map[string]bool{}
		for _, x := range wantedList {
			if k, ok := x.(string); ok {
				wanted[k] = true
			}
		}
		creds, _ := group["credentials"].(map[string]interface{})
		filtered := map[string]interface{}{}
		for k, v := range creds {
			if wanted[k] {
				filtered[k] = v
			}
		}
		if len(filtered) == 0 {
			return nil, fmt.Errorf("policy selected no valid credential for query %s", id)
		}
		group["credentials"] = filtered
		selectedGroups = append(selectedGroups, group)
	}
	if len(selectedGroups) == 0 {
		return nil, errors.New("policy selected no credential groups")
	}
	raw, err = json.Marshal(selectedGroups)
	if err != nil {
		return nil, err
	}
	var selected []presentation.FilterResult
	if err := json.Unmarshal(raw, &selected); err != nil {
		return nil, err
	}
	return selected, nil
}
