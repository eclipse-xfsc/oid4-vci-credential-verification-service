package common

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	appCommon "github.com/eclipse-xfsc/oid4-vci-credential-verification-service/internal/common"
	"github.com/eclipse-xfsc/oid4-vci-credential-verification-service/internal/connection"
	"github.com/eclipse-xfsc/oid4-vci-credential-verification-service/internal/model"
	"github.com/eclipse-xfsc/oid4-vci-vp-library/model/presentation"
	"github.com/gocql/gocql"
)

const presentationsTable = "ocm.presentations"

func scanEntries(iter connection.IterInterface) ([]model.VerificationEntry, error) {
	ret := make([]model.VerificationEntry, 0)
	for {
		var partition, region, country, tenantId, groupId, requestId string
		var definition, pres, redirectURI, status, nonce, responseURI, responseMode, responseType, clientID, authorizationState, clientMetadata, consentMode string
		var profileInteraction, profileKeyNamespace, profileKeyGroup, profileKeyID, profileOrigin string
		var lastUpdate time.Time
		if !iter.Scan(&partition, &region, &country, &tenantId, &groupId, &requestId, &definition, &pres, &redirectURI, &status, &lastUpdate, &nonce, &responseURI, &responseMode, &responseType, &clientID, &authorizationState, &clientMetadata, &consentMode, &profileInteraction, &profileKeyNamespace, &profileKeyGroup, &profileKeyID, &profileOrigin) {
			break
		}
		row := model.VerificationEntry{ProfileOrigin: profileOrigin, ProfileInteraction: profileInteraction, ProfileKeyNamespace: profileKeyNamespace, ProfileKeyGroup: profileKeyGroup, ProfileKeyID: profileKeyID, ConsentMode: consentMode, Partition: partition, Region: region, Country: country, TenantId: tenantId, GroupId: groupId, RequestId: requestId, RedirectUri: redirectURI, State: status, LastUpdateTimeStamp: lastUpdate, Nonce: nonce, ResponseUri: responseURI, ResponseMode: responseMode, ResponseType: responseType, ClientId: clientID, AuthorizationState: authorizationState}
		if definition != "" {
			b, err := base64.RawStdEncoding.DecodeString(definition)
			if err != nil {
				_ = iter.Close()
				return nil, fmt.Errorf("decode DCQL query for request %s: %w", requestId, err)
			}
			if err := json.Unmarshal(b, &row.DCQLQuery); err != nil {
				_ = iter.Close()
				return nil, fmt.Errorf("unmarshal DCQL query for request %s: %w", requestId, err)
			}
		}
		if pres != "" {
			b, err := base64.RawStdEncoding.DecodeString(pres)
			if err != nil {
				_ = iter.Close()
				return nil, fmt.Errorf("decode presentation for request %s: %w", requestId, err)
			}
			if err := json.Unmarshal(b, &row.Presentation); err != nil {
				_ = iter.Close()
				return nil, fmt.Errorf("unmarshal presentation for request %s: %w", requestId, err)
			}
		}
		if clientMetadata != "" {
			b, err := base64.RawStdEncoding.DecodeString(clientMetadata)
			if err != nil {
				_ = iter.Close()
				return nil, fmt.Errorf("decode client metadata for request %s: %w", requestId, err)
			}
			var metadata presentation.VerifierMetadata
			if err := json.Unmarshal(b, &metadata); err != nil {
				_ = iter.Close()
				return nil, fmt.Errorf("unmarshal client metadata for request %s: %w", requestId, err)
			}
			row.ClientMetadata = &metadata
		}
		ret = append(ret, row)
	}
	if err := iter.Close(); err != nil {
		return nil, err
	}
	return ret, nil
}

func getEntryByKey(ctx context.Context, tenantId, groupId, requestId string) (*model.VerificationEntry, error) {
	if tenantId == "" || groupId == "" || requestId == "" {
		return nil, errors.New("tenantId, groupId and requestId must not be empty")
	}
	env := appCommon.GetEnvironment()
	partition := env.GetAccountPartition(groupId)
	selectCols := `partition,region,country,tenantId,groupId,requestId,dcqlQuery,presentation,redirectUri,status,last_update_timestamp,nonce,responseUri,responseMode,responseType,clientId,authorizationState,clientMetadata,consent_mode,profile_interaction,profile_key_namespace,profile_key_group,profile_key_id,profile_origin`
	q := fmt.Sprintf(`SELECT %s FROM %s WHERE partition=? AND region=? AND country=? AND tenantId=? AND groupId=? AND requestId=?`, selectCols, presentationsTable)
	rows, err := scanEntries(env.GetSession().Query(q, partition, env.GetRegion(), env.GetCountry(), tenantId, groupId, requestId).WithContext(ctx).Consistency(gocql.LocalQuorum).Iter())
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, fmt.Errorf("no row found for tenantId %s groupId %s requestId %s", tenantId, groupId, requestId)
	}
	return &rows[0], nil
}

func GetEntryFromDb(ctx context.Context, tenantId, state string) (*model.VerificationEntry, error) {
	key, err := DecodeVerificationState(state)
	if err != nil {
		return nil, err
	}
	return getEntryByKey(ctx, tenantId, key.GroupId, key.RequestId)
}

func GetEntryFromDbByRequestId(ctx context.Context, tenantId, requestId string) (*model.VerificationEntry, error) {
	return nil, errors.New("requestId-only lookup is not supported; groupId is required (use verification state)")
}

func GetEntriesFromDb(ctx context.Context, tenantId, groupId string) ([]model.VerificationEntry, error) {
	if tenantId == "" || groupId == "" {
		return nil, errors.New("tenantId and groupId must not be empty")
	}
	env := appCommon.GetEnvironment()
	partition := env.GetAccountPartition(groupId)
	selectCols := `partition,region,country,tenantId,groupId,requestId,dcqlQuery,presentation,redirectUri,status,last_update_timestamp,nonce,responseUri,responseMode,responseType,clientId,authorizationState,clientMetadata,consent_mode,profile_interaction,profile_key_namespace,profile_key_group,profile_key_id,profile_origin`
	q := fmt.Sprintf(`SELECT %s FROM %s WHERE partition=? AND region=? AND country=? AND tenantId=? AND groupId=?`, selectCols, presentationsTable)
	return scanEntries(env.GetSession().Query(q, partition, env.GetRegion(), env.GetCountry(), tenantId, groupId).WithContext(ctx).Consistency(gocql.LocalQuorum).Iter())
}

type PresentationRequestOptions struct {
	TenantId            string `json:"tenantId"`
	RequestId           string `json:"requestId"`
	GroupId             string `json:"groupId"`
	Ttl                 int    `json:"ttl"`
	ClientId            string `json:"clientId"`
	ProfileOrigin       string
	ProfileInteraction  string
	ProfileKeyNamespace string
	ProfileKeyGroup     string
	ProfileKeyID        string
}

func AddDCQLQueryToDb(pd presentation.DCQLQuery, options PresentationRequestOptions, ctx context.Context) error {
	if options.TenantId == "" || options.GroupId == "" || options.RequestId == "" {
		return errors.New("tenantId, groupId and requestId must not be empty")
	}
	if options.Ttl <= 0 {
		return errors.New("positive TTL required")
	}
	env := appCommon.GetEnvironment()
	partition := env.GetAccountPartition(options.GroupId)
	bpd, err := json.Marshal(pd)
	if err != nil {
		return err
	}
	nonce := make([]byte, 32)
	if _, err = rand.Read(nonce); err != nil {
		return err
	}
	q := `INSERT INTO ocm.presentations (partition,region,country,tenantId,groupId,requestId,dcqlQuery,status,last_update_timestamp,nonce,clientId,consent_mode,profile_interaction,profile_key_namespace,profile_key_group,profile_key_id,profile_origin) VALUES(?,?,?,?,?,?,?,?,toTimestamp(now()),?,?,?,?,?,?,?,?) USING TTL ?`
	return env.GetSession().Query(q, partition, env.GetRegion(), env.GetCountry(), options.TenantId, options.GroupId, options.RequestId, base64.RawStdEncoding.EncodeToString(bpd), model.PresentationRequested, base64.RawURLEncoding.EncodeToString(nonce), options.ClientId, model.ConsentManual, options.ProfileInteraction, options.ProfileKeyNamespace, options.ProfileKeyGroup, options.ProfileKeyID, options.ProfileOrigin, options.Ttl).WithContext(ctx).Exec()
}

func updateKey(ctx context.Context, tenantId, id string) (*model.VerificationEntry, error) {
	return GetEntryFromDb(ctx, tenantId, id)
}

func AssignEntryToGroup(ctx context.Context, tenantId, id, groupId string) error {
	if groupId == "" {
		return errors.New("groupId must not be empty")
	}
	row, err := updateKey(ctx, tenantId, id)
	if err != nil {
		return err
	}
	if row.GroupId == groupId {
		return nil
	}
	return fmt.Errorf("groupId is part of the Cassandra primary key and must be supplied when the presentation is created (current=%q requested=%q)", row.GroupId, groupId)
}

func UpdateDbStatus(ctx context.Context, tenantId, status, id string) error {
	row, err := updateKey(ctx, tenantId, id)
	if err != nil {
		return err
	}
	ttl, err := RemainingTTL(ctx, row)
	if err != nil {
		return err
	}
	env := appCommon.GetEnvironment()
	q := `UPDATE ocm.presentations USING TTL ? SET status=?,last_update_timestamp=toTimestamp(now()) WHERE partition=? AND region=? AND country=? AND tenantId=? AND groupId=? AND requestId=?`
	return env.GetSession().Query(q, ttl, status, row.Partition, row.Region, row.Country, row.TenantId, row.GroupId, row.RequestId).WithContext(ctx).Exec()
}

func StorePresentation(ctx context.Context, id, tenantId string, proof []byte) error {
	row, err := updateKey(ctx, tenantId, id)
	if err != nil {
		return err
	}
	ttl, err := RemainingTTL(ctx, row)
	if err != nil {
		return err
	}
	env := appCommon.GetEnvironment()
	q := `UPDATE ocm.presentations USING TTL ? SET status=?,last_update_timestamp=toTimestamp(now()),presentation=? WHERE partition=? AND region=? AND country=? AND tenantId=? AND groupId=? AND requestId=?`
	return env.GetSession().Query(q, ttl, model.PresentationReceived, base64.RawStdEncoding.EncodeToString(proof), row.Partition, row.Region, row.Country, row.TenantId, row.GroupId, row.RequestId).WithContext(ctx).Exec()
}

func StoreRequest(ctx context.Context, requestId, tenantId, groupId, consentMode string, ttl int, requestObject *presentation.RequestObject) error {
	if consentMode != model.ConsentManual && consentMode != model.ConsentAuto {
		return errors.New("invalid consent mode")
	}
	if ttl <= 0 {
		return errors.New("positive TTL required")
	}
	if tenantId == "" || groupId == "" || requestId == "" {
		return errors.New("tenantId, groupId and requestId must not be empty")
	}
	if requestObject == nil {
		return errors.New("request object must not be nil")
	}
	env := appCommon.GetEnvironment()
	partition := env.GetAccountPartition(groupId)
	b, err := json.Marshal(requestObject.DCQLQuery)
	if err != nil {
		return err
	}
	metadata, err := json.Marshal(requestObject.ClientMetadata)
	if err != nil {
		return err
	}
	q := `INSERT INTO ocm.presentations (partition,region,country,tenantId,groupId,requestId,status,last_update_timestamp,dcqlQuery,redirectUri,nonce,responseUri,responseMode,responseType,clientId,authorizationState,clientMetadata,consent_mode) VALUES(?,?,?,?,?,?,?,toTimestamp(now()),?,?,?,?,?,?,?,?,?,?) USING TTL ?`
	return env.GetSession().Query(q, partition, env.GetRegion(), env.GetCountry(), tenantId, groupId, requestId, model.StatusPending, base64.RawStdEncoding.EncodeToString(b), requestObject.RedirectURI, requestObject.Nonce, requestObject.ResponseURI, requestObject.ResponseMode, requestObject.ResponseType, requestObject.ClientID, requestObject.State, base64.RawStdEncoding.EncodeToString(metadata), consentMode, ttl).WithContext(ctx).Exec()
}

// TryBeginFulfillment checks the current state before a non-atomic update.
func TryBeginFulfillment(ctx context.Context, row *model.VerificationEntry) (bool, error) {
	// Best effort only: the read and write are NOT atomic without Cassandra LWT.
	if row == nil {
		return false, errors.New("presentation entry must not be nil")
	}
	current, err := getEntryByKey(ctx, row.TenantId, row.GroupId, row.RequestId)
	if err != nil {
		return false, err
	}
	if current.State != string(model.PresentationRequested) {
		return false, nil
	}
	ttl, err := RemainingTTL(ctx, row)
	if err != nil {
		return false, err
	}
	env := appCommon.GetEnvironment()
	q := `UPDATE ocm.presentations USING TTL ? SET status=?,last_update_timestamp=toTimestamp(now()) WHERE partition=? AND region=? AND country=? AND tenantId=? AND groupId=? AND requestId=?`
	err = env.GetSession().Query(q, ttl, model.PresentationFulfilling, row.Partition, row.Region, row.Country, row.TenantId, row.GroupId, row.RequestId).WithContext(ctx).Exec()
	return err == nil, err
}

// ReleaseFulfillment reopens a request if it currently appears fulfilling.
func ReleaseFulfillment(ctx context.Context, row *model.VerificationEntry) error {
	// Best effort only: concurrent state changes are not protected.
	if row == nil {
		return errors.New("presentation entry must not be nil")
	}
	current, err := getEntryByKey(ctx, row.TenantId, row.GroupId, row.RequestId)
	if err != nil {
		return err
	}
	if current.State != string(model.PresentationFulfilling) {
		return errors.New("cannot release fulfillment: presentation status has changed")
	}
	ttl, err := RemainingTTL(ctx, row)
	if err != nil {
		return err
	}
	env := appCommon.GetEnvironment()
	q := `UPDATE ocm.presentations USING TTL ? SET status=? WHERE partition=? AND region=? AND country=? AND tenantId=? AND groupId=? AND requestId=?`
	return env.GetSession().Query(q, ttl, model.PresentationRequested, row.Partition, row.Region, row.Country, row.TenantId, row.GroupId, row.RequestId).WithContext(ctx).Exec()
}

// RemainingTTL reads the TTL of the immutable consent_mode cell.
// Requests created without consent_mode have no TTL anchor and cannot be updated using this helper.
func RemainingTTL(ctx context.Context, row *model.VerificationEntry) (int, error) {
	if row == nil {
		return 0, errors.New("presentation entry must not be nil")
	}
	env := appCommon.GetEnvironment()
	var ttl int
	err := env.GetSession().Query(`SELECT TTL(consent_mode) FROM ocm.presentations WHERE partition=? AND region=? AND country=? AND tenantId=? AND groupId=? AND requestId=?`, row.Partition, row.Region, row.Country, row.TenantId, row.GroupId, row.RequestId).WithContext(ctx).Scan(&ttl)
	if errors.Is(err, gocql.ErrNotFound) {
		return 0, errors.New("presentation request expired or not found")
	}
	if err != nil {
		return 0, err
	}
	if ttl <= 0 {
		return 0, errors.New("presentation request expired or has no TTL")
	}
	return ttl, nil
}

// TransitionPresentation checks the previous status before a non-atomic update.
func TransitionPresentation(ctx context.Context, row *model.VerificationEntry, from, to string) (bool, error) {
	// Best effort only: SELECT + UPDATE does not guarantee an atomic transition.
	if row == nil {
		return false, errors.New("presentation entry must not be nil")
	}
	current, err := getEntryByKey(ctx, row.TenantId, row.GroupId, row.RequestId)
	if err != nil {
		return false, err
	}
	if current.State != from {
		return false, nil
	}
	ttl, err := RemainingTTL(ctx, row)
	if err != nil {
		return false, err
	}
	env := appCommon.GetEnvironment()
	q := `UPDATE ocm.presentations USING TTL ? SET status=?,last_update_timestamp=toTimestamp(now()) WHERE partition=? AND region=? AND country=? AND tenantId=? AND groupId=? AND requestId=?`
	err = env.GetSession().Query(q, ttl, to, row.Partition, row.Region, row.Country, row.TenantId, row.GroupId, row.RequestId).WithContext(ctx).Exec()
	return err == nil, err
}

func IsVerifierBlocked(ctx context.Context, tenant, group, client string) (bool, error) {
	if tenant == "" || group == "" || client == "" {
		return false, errors.New("missing tenant, group or verifier")
	}
	env := appCommon.GetEnvironment()
	q := `SELECT clientId FROM ocm.blocked_verifiers WHERE partition=? AND region=? AND country=? AND tenantId=? AND groupId=? AND clientId=?`
	var found string
	err := env.GetSession().Query(q, env.GetAccountPartition(group), env.GetRegion(), env.GetCountry(), tenant, group, client).WithContext(ctx).Scan(&found)
	if errors.Is(err, gocql.ErrNotFound) {
		return false, nil
	}
	return found != "", err
}

func SetVerifierBlocked(ctx context.Context, tenant, group, client string, blocked bool) error {
	if tenant == "" || group == "" || client == "" {
		return errors.New("missing tenant, group or verifier")
	}
	env := appCommon.GetEnvironment()
	key := []interface{}{env.GetAccountPartition(group), env.GetRegion(), env.GetCountry(), tenant, group, client}
	if !blocked {
		return env.GetSession().Query(`DELETE FROM ocm.blocked_verifiers WHERE partition=? AND region=? AND country=? AND tenantId=? AND groupId=? AND clientId=?`, key...).WithContext(ctx).Exec()
	}
	return env.GetSession().Query(`INSERT INTO ocm.blocked_verifiers (partition,region,country,tenantId,groupId,clientId,created_at) VALUES (?,?,?,?,?,?,toTimestamp(now()))`, key...).WithContext(ctx).Exec()
}

func ListBlockedVerifiers(ctx context.Context, tenant, group string) ([]string, error) {
	if tenant == "" || group == "" {
		return nil, errors.New("missing tenant or group")
	}
	env := appCommon.GetEnvironment()
	q := `SELECT clientId FROM ocm.blocked_verifiers WHERE partition=? AND region=? AND country=? AND tenantId=? AND groupId=?`
	iter := env.GetSession().Query(q, env.GetAccountPartition(group), env.GetRegion(), env.GetCountry(), tenant, group).WithContext(ctx).Iter()
	out := []string{}
	var id string
	for iter.Scan(&id) {
		out = append(out, id)
	}
	return out, iter.Close()
}
