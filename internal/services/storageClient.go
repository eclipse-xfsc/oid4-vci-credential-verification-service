package services

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/eclipse-xfsc/oid4-vci-credential-verification-service/internal/model"
	"github.com/eclipse-xfsc/oid4-vci-vp-library/model/presentation"
)

type storageCredentialResponse struct {
	Credentials map[string]interface{}      `json:"credentials,omitempty"`
	Receipt     string                      `json:"receipt,omitempty"`
	Groups      []presentation.FilterResult `json:"groups,omitempty"`
}

// resolveCredentials asks Credential Storage Service to evaluate the persisted
// DCQL snapshot. groupId is the holder account identifier in the current
// deployment model. Region and country are intentionally read from static
// service configuration for now; a future tenant service can replace only
// this resolution without changing the holder flow.
func resolveCredentials(ctx context.Context, cfg *model.Config, row *model.VerificationEntry) ([]presentation.FilterResult, error) {
	if cfg.StorageServiceURL == "" {
		return nil, errors.New("storage service URL is not configured")
	}
	if row == nil || row.TenantId == "" || row.GroupId == "" {
		return nil, errors.New("tenant and account/group are required for credential lookup")
	}

	body, err := json.Marshal(row.DCQLQuery)
	if err != nil {
		return nil, err
	}

	base := strings.TrimRight(cfg.StorageServiceURL, "/")
	endpoint := fmt.Sprintf("%s/v1/tenants/%s/storage/%s/%s/%s/credentials",
		base,
		url.PathEscape(row.TenantId),
		url.PathEscape(cfg.Region),
		url.PathEscape(cfg.Country),
		url.PathEscape(row.GroupId),
	)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := GetHttpClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("credential storage request failed: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("credential storage returned %d: %s", resp.StatusCode, string(raw))
	}

	var result storageCredentialResponse
	if err := json.Unmarshal(raw, &result); err != nil {
		return nil, fmt.Errorf("invalid credential storage response: %w", err)
	}
	if len(result.Groups) == 0 {
		return nil, errors.New("no credentials satisfy the DCQL query")
	}
	return result.Groups, nil
}
