package verifier

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/eclipse-xfsc/oid4-vci-credential-verification-service/internal/model"
	"github.com/eclipse-xfsc/oid4-vci-vp-library/model/presentation"
)

// PresentationPolicy is an internal, tenant/group-scoped DCQL template.
// Its identifier is NOT added as a proprietary field to the OID4VP request object.
type PresentationPolicy struct {
	ID        string                 `json:"id"`
	Version   string                 `json:"version"`
	DCQLQuery presentation.DCQLQuery `json:"dcqlQuery"`
}

func ResolvePresentationPolicy(ctx context.Context, cfg *model.Config, tenant, group, id string) (*PresentationPolicy, error) {
	if tenant == "" || group == "" || id == "" {
		return nil, errors.New("tenant, group and presentationPolicyId required")
	}
	if cfg.PresentationPolicy.URL == "" {
		return nil, errors.New("PRESENTATIONPOLICY_URL not configured")
	}
	base, err := url.Parse(cfg.PresentationPolicy.URL)
	if err != nil || (base.Scheme != "http" && base.Scheme != "https") || base.Host == "" || base.User != nil {
		return nil, errors.New("invalid policy service URL")
	}
	base.Path = strings.TrimRight(base.Path, "/") + "/v1/presentation-policies/" + url.PathEscape(id)
	q := base.Query()
	q.Set("tenantId", tenant)
	q.Set("groupId", group)
	base.RawQuery = q.Encode()
	timeout := cfg.PresentationPolicy.TimeoutSeconds
	if timeout <= 0 {
		timeout = 10
	}
	client := &http.Client{Timeout: time.Duration(timeout) * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base.String(), nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("policy service: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("policy service returned HTTP %d", resp.StatusCode)
	}
	var p PresentationPolicy
	decoder := json.NewDecoder(io.LimitReader(resp.Body, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&p); err != nil {
		return nil, fmt.Errorf("decode presentation policy: %w", err)
	}
	if p.ID != id || p.Version == "" {
		return nil, errors.New("policy ID/version mismatch")
	}
	if err := p.DCQLQuery.Validate(); err != nil {
		return nil, fmt.Errorf("invalid policy DCQL: %w", err)
	}
	return &p, nil
}
