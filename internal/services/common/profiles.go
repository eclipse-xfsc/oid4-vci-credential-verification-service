package common

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/eclipse-xfsc/oid4-vci-vp-library/model/presentation"

	app "github.com/eclipse-xfsc/oid4-vci-credential-verification-service/internal/common"
	"github.com/gocql/gocql"
	"github.com/google/uuid"
)

const HolderAuthorizePath = "/api/holder/authorize"
const VerifierRequestObjectPath = "/api/verifier/presentation/proof"

type PresentationProfile struct {
	TenantID                     string                     `json:"tenantId"`
	GroupID                      string                     `json:"groupId"`
	ProfileType                  string                     `json:"profileType"`
	InteractionType              string                     `json:"interactionType"`
	ProfileID                    uuid.UUID                  `json:"profileId"`
	Enabled                      bool                       `json:"enabled"`
	DID                          string                     `json:"did"`
	Origin                       string                     `json:"origin"`
	KeyNamespace                 string                     `json:"keyNamespace"`
	KeyID                        string                     `json:"keyId"`
	SigningAlgorithm             string                     `json:"signingAlgorithm"`
	ResponseMode                 string                     `json:"responseMode"`
	RequestObjectTTLSeconds      int                        `json:"requestObjectTtlSeconds"`
	RequestObjectPolicyURL       string                     `json:"requestObjectPolicyUrl"`
	CredentialSelectionPolicyURL string                     `json:"credentialSelectionPolicyUrl"`
	PresentationPolicies         map[string]json.RawMessage `json:"presentationPolicies"`
	CreatedAt                    time.Time                  `json:"createdAt"`
	UpdatedAt                    time.Time                  `json:"updatedAt"`
}

func ValidProfileType(v string) bool     { return v == "verifier" || v == "holder" }
func ValidInteractionType(v string) bool { return v == "human" || v == "machine" }

func ValidateProfile(p *PresentationProfile) error {
	if p.TenantID == "" || p.GroupID == "" || !ValidProfileType(p.ProfileType) || !ValidInteractionType(p.InteractionType) {
		return errors.New("invalid tenant, group, profile type or interaction type")
	}
	if p.ProfileID == uuid.Nil {
		return errors.New("profileId required")
	}
	u, err := url.Parse(p.Origin)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("origin must be a HTTPS origin without path")
	}
	if p.DID == "" || !strings.HasPrefix(p.DID, "did:") {
		return errors.New("DID required")
	}
	if p.KeyNamespace == "" || p.KeyID == "" {
		return errors.New("key namespace and key ID required")
	}
	if p.SigningAlgorithm == "" {
		return errors.New("signing algorithm required")
	}
	if p.ProfileType == "verifier" {
		if p.ResponseMode != "direct_post" {
			return errors.New("only direct_post response mode supported")
		}
		if p.RequestObjectTTLSeconds <= 0 || p.RequestObjectTTLSeconds > 86400 {
			return errors.New("invalid request object TTL")
		}
		if len(p.PresentationPolicies) == 0 {
			return errors.New("verifier must have at least one permission set")
		}
		for name, raw := range p.PresentationPolicies {
			if strings.TrimSpace(name) == "" {
				return errors.New("permission set name required")
			}
			var query presentation.DCQLQuery
			if err := json.Unmarshal([]byte(raw), &query); err != nil {
				return fmt.Errorf("invalid DCQL JSON for %s: %w", name, err)
			}
			if err := query.Validate(); err != nil {
				return fmt.Errorf("invalid DCQL for %s: %w", name, err)
			}
		}
	} else if len(p.PresentationPolicies) > 0 {
		return errors.New("holder must not contain presentation policies")
	}
	return nil
}

func GetPresentationProfile(ctx context.Context, tenant, group, kind, interaction string) (*PresentationProfile, error) {
	p, err := GetPresentationProfileForAdmin(ctx, tenant, group, kind, interaction)
	if err != nil {
		return nil, err
	}
	if !p.Enabled {
		return nil, errors.New("presentation profile disabled")
	}
	return p, nil
}

// GetPresentationProfileForAdmin includes disabled profiles, preserving identity on updates.
func GetPresentationProfileForAdmin(ctx context.Context, tenant, group, kind, interaction string) (*PresentationProfile, error) {
	if tenant == "" || group == "" || !ValidProfileType(kind) || !ValidInteractionType(interaction) {
		return nil, errors.New("invalid profile key")
	}
	p := &PresentationProfile{TenantID: tenant, GroupID: group, ProfileType: kind, InteractionType: interaction}
	var dbProfileID gocql.UUID
	err := app.GetEnvironment().GetSession().Query(`SELECT profile_id,enabled,did,origin,key_namespace,key_id,signing_algorithm,response_mode,request_object_ttl_seconds,request_object_policy_url,credential_selection_policy_url,presentation_policies,created_at,updated_at FROM ocm.presentation_profiles WHERE tenant_id=? AND group_id=? AND profile_type=? AND interaction_type=?`, tenant, group, kind, interaction).WithContext(ctx).Consistency(gocql.LocalQuorum).Scan(&dbProfileID, &p.Enabled, &p.DID, &p.Origin, &p.KeyNamespace, &p.KeyID, &p.SigningAlgorithm, &p.ResponseMode, &p.RequestObjectTTLSeconds, &p.RequestObjectPolicyURL, &p.CredentialSelectionPolicyURL, &p.PresentationPolicies, &p.CreatedAt, &p.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("load presentation profile: %w", err)
	}
	p.ProfileID = uuid.UUID(dbProfileID)
	return p, nil
}

func SavePresentationProfile(ctx context.Context, p *PresentationProfile) error {
	if err := ValidateProfile(p); err != nil {
		return err
	}
	if p.CreatedAt.IsZero() {
		p.CreatedAt = time.Now().UTC()
	}
	p.UpdatedAt = time.Now().UTC()
	return app.GetEnvironment().GetSession().Query(`INSERT INTO ocm.presentation_profiles (tenant_id,group_id,profile_type,interaction_type,profile_id,enabled,did,origin,key_namespace,key_id,signing_algorithm,response_mode,request_object_ttl_seconds,request_object_policy_url,credential_selection_policy_url,presentation_policies,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, p.TenantID, p.GroupID, p.ProfileType, p.InteractionType, gocql.UUID(p.ProfileID), p.Enabled, p.DID, p.Origin, p.KeyNamespace, p.KeyID, p.SigningAlgorithm, p.ResponseMode, p.RequestObjectTTLSeconds, p.RequestObjectPolicyURL, p.CredentialSelectionPolicyURL, p.PresentationPolicies, p.CreatedAt, p.UpdatedAt).WithContext(ctx).Exec()
}

// ListPresentationProfilesForAdmin lists all profiles within a tenant/group partition,
// including disabled profiles. The API never scans other tenant/group partitions.
func ListPresentationProfilesForAdmin(ctx context.Context, tenant, group string) ([]PresentationProfile, error) {
	if tenant == "" || group == "" {
		return nil, errors.New("tenant and group required")
	}
	iter := app.GetEnvironment().GetSession().Query(`SELECT profile_type,interaction_type,profile_id,enabled,did,origin,key_namespace,key_id,signing_algorithm,response_mode,request_object_ttl_seconds,request_object_policy_url,credential_selection_policy_url,presentation_policies,created_at,updated_at FROM ocm.presentation_profiles WHERE tenant_id=? AND group_id=?`, tenant, group).WithContext(ctx).Consistency(gocql.LocalQuorum).Iter()
	profiles := make([]PresentationProfile, 0)
	for {
		profile := PresentationProfile{TenantID: tenant, GroupID: group}
		var dbProfileID gocql.UUID
		if !iter.Scan(&profile.ProfileType, &profile.InteractionType, &dbProfileID, &profile.Enabled, &profile.DID, &profile.Origin, &profile.KeyNamespace, &profile.KeyID, &profile.SigningAlgorithm, &profile.ResponseMode, &profile.RequestObjectTTLSeconds, &profile.RequestObjectPolicyURL, &profile.CredentialSelectionPolicyURL, &profile.PresentationPolicies, &profile.CreatedAt, &profile.UpdatedAt) {
			break
		}
		profile.ProfileID = uuid.UUID(dbProfileID)
		profiles = append(profiles, profile)
	}
	if err := iter.Close(); err != nil {
		return nil, fmt.Errorf("list presentation profiles: %w", err)
	}
	return profiles, nil
}

// DeletePresentationProfileForAdmin deletes exactly one profile, including disabled profiles.
// Cassandra DELETE is idempotent: deleting an absent profile also succeeds.
func DeletePresentationProfileForAdmin(ctx context.Context, tenant, group, kind, interaction string) error {
	if tenant == "" || group == "" || !ValidProfileType(kind) || !ValidInteractionType(interaction) {
		return errors.New("invalid profile key")
	}
	return app.GetEnvironment().GetSession().Query(`DELETE FROM ocm.presentation_profiles WHERE tenant_id=? AND group_id=? AND profile_type=? AND interaction_type=?`, tenant, group, kind, interaction).WithContext(ctx).Consistency(gocql.LocalQuorum).Exec()
}
