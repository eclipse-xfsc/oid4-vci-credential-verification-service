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
	var partition, region, country, tenantId, groupId, requestId string
	var definition, pres, redirectURI, status, nonce, responseURI, responseMode, responseType, clientID, authorizationState, clientMetadata string
	var lastUpdate time.Time
	ret := make([]model.VerificationEntry, 0)
	for iter.Scan(&partition, &region, &country, &tenantId, &groupId, &requestId, &definition, &pres, &redirectURI, &status, &lastUpdate, &nonce, &responseURI, &responseMode, &responseType, &clientID, &authorizationState, &clientMetadata) {
		row := model.VerificationEntry{Partition: partition, Region: region, Country: country, TenantId: tenantId, GroupId: groupId, RequestId: requestId, RedirectUri: redirectURI, State: status, LastUpdateTimeStamp: lastUpdate, Nonce: nonce, ResponseUri: responseURI, ResponseMode: responseMode, ResponseType: responseType, ClientId: clientID, AuthorizationState: authorizationState}
		b, err := base64.RawStdEncoding.DecodeString(definition)
		if err != nil {
			return nil, err
		}
		if len(b) > 0 {
			if err = json.Unmarshal(b, &row.DCQLQuery); err != nil {
				return nil, err
			}
		}
		b, err = base64.RawStdEncoding.DecodeString(pres)
		if err != nil {
			return nil, err
		}
		if len(b) > 0 {
			if err = json.Unmarshal(b, &row.Presentation); err != nil {
				return nil, err
			}
		}
		if clientMetadata != "" {
			b, err = base64.RawStdEncoding.DecodeString(clientMetadata)
			if err != nil {
				return nil, err
			}
			if len(b) > 0 {
				var metadata presentation.VerifierMetadata
				if err = json.Unmarshal(b, &metadata); err != nil {
					return nil, err
				}
				row.ClientMetadata = &metadata
			}
		}
		ret = append(ret, row)
	}
	if err := iter.Close(); err != nil {
		return nil, err
	}
	return ret, nil
}

func getEntryByKey(ctx context.Context, tenantId, groupId, requestId string) (*model.VerificationEntry, error) {
	env := appCommon.GetEnvironment()
	if tenantId == "" || groupId == "" || requestId == "" {
		return nil, errors.New("tenantId, groupId and requestId must not be empty")
	}
	partition := env.GetAccountPartition(groupId)
	selectCols := `partition,region,country,tenantId,groupId,requestId,dcqlQuery,presentation,redirectUri,status,last_update_timestamp,nonce,responseUri,responseMode,responseType,clientId,authorizationState,clientMetadata`
	q := fmt.Sprintf(`SELECT %s FROM %s WHERE partition=? AND region=? AND country=? AND tenantId=? AND groupId=? AND requestId=?`, selectCols, presentationsTable)
	rows, err := scanEntries(env.GetSession().Query(q, partition, env.GetRegion(), env.GetCountry(), tenantId, groupId, requestId).WithContext(ctx).Consistency(gocql.LocalQuorum).Iter())
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, fmt.Errorf("no row found for groupId %s requestId %s", groupId, requestId)
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
	env := appCommon.GetEnvironment()
	partition := env.GetAccountPartition(groupId)
	selectCols := `partition,region,country,tenantId,groupId,requestId,dcqlQuery,presentation,redirectUri,status,last_update_timestamp,nonce,responseUri,responseMode,responseType,clientId,authorizationState,clientMetadata`
	q := fmt.Sprintf(`SELECT %s FROM %s WHERE partition=? AND region=? AND country=? AND tenantId=? AND groupId=?`, selectCols, presentationsTable)
	return scanEntries(env.GetSession().Query(q, partition, env.GetRegion(), env.GetCountry(), tenantId, groupId).WithContext(ctx).Consistency(gocql.LocalQuorum).Iter())
}

type PresentationRequestOptions struct {
	TenantId  string `json:"tenantId"`
	RequestId string `json:"requestId"`
	GroupId   string `json:"groupId"`
	Ttl       int    `json:"ttl"`
	ClientId  string `json:"clientId"`
}

func AddDCQLQueryToDb(pd presentation.DCQLQuery, options PresentationRequestOptions, ctx context.Context) error {
	if options.TenantId == "" {
		return errors.New("tenantId must not be empty")
	}
	if options.GroupId == "" {
		return errors.New("groupId must not be empty")
	}
	if options.RequestId == "" {
		return errors.New("requestId must not be empty")
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
	q := `INSERT INTO ocm.presentations (partition,region,country,tenantId,groupId,requestId,dcqlQuery,status,last_update_timestamp,nonce,clientId) VALUES(?,?,?,?,?,?,?,?,toTimestamp(now()),?,?) USING TTL ?`
	return env.GetSession().Query(q, partition, env.GetRegion(), env.GetCountry(), options.TenantId, options.GroupId, options.RequestId, base64.RawStdEncoding.EncodeToString(bpd), model.PresentationRequested, base64.RawURLEncoding.EncodeToString(nonce), options.ClientId, options.Ttl).WithContext(ctx).Exec()
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
	// groupId is a clustering key and cannot be updated in place. Reinsert under the new key, then remove the old row.
	if row.GroupId == groupId {
		return nil
	}
	return fmt.Errorf("groupId is part of the Cassandra primary key and must be supplied when the presentation is created (current=%q requested=%q)", row.GroupId, groupId)
}

func UpdateDbStatus(ctx context.Context, tenantId, status, id string) error {
	env := appCommon.GetEnvironment()
	row, err := updateKey(ctx, tenantId, id)
	if err != nil {
		return err
	}
	q := `UPDATE ocm.presentations SET status=?,last_update_timestamp=toTimestamp(now()) WHERE partition=? AND region=? AND country=? AND tenantId=? AND groupId=? AND requestId=?`
	return env.GetSession().Query(q, status, row.Partition, row.Region, row.Country, row.TenantId, row.GroupId, row.RequestId).WithContext(ctx).Exec()
}
func StorePresentation(ctx context.Context, id, tenantId string, proof []byte) error {
	env := appCommon.GetEnvironment()
	row, err := updateKey(ctx, tenantId, id)
	if err != nil {
		return err
	}
	q := `UPDATE ocm.presentations SET status=?,last_update_timestamp=toTimestamp(now()),presentation=? WHERE partition=? AND region=? AND country=? AND tenantId=? AND groupId=? AND requestId=?`
	return env.GetSession().Query(q, model.PresentationReceived, base64.RawStdEncoding.EncodeToString(proof), row.Partition, row.Region, row.Country, row.TenantId, row.GroupId, row.RequestId).WithContext(ctx).Exec()
}
func StoreRequest(ctx context.Context, requestId, tenantId, groupId string, requestObject *presentation.RequestObject) error {
	if tenantId == "" {
		return errors.New("tenantId must not be empty")
	}
	if groupId == "" {
		return errors.New("groupId must not be empty")
	}
	if requestId == "" {
		return errors.New("requestId must not be empty")
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
	q := `INSERT INTO ocm.presentations (partition,region,country,tenantId,groupId,requestId,status,last_update_timestamp,dcqlQuery,redirectUri,nonce,responseUri,responseMode,responseType,clientId,authorizationState,clientMetadata) VALUES(?,?,?,?,?,?,?,toTimestamp(now()),?,?,?,?,?,?,?,?,?)`
	return env.GetSession().Query(q, partition, env.GetRegion(), env.GetCountry(), tenantId, groupId, requestId, model.PresentationRequested, base64.RawStdEncoding.EncodeToString(b), requestObject.RedirectURI, requestObject.Nonce, requestObject.ResponseURI, requestObject.ResponseMode, requestObject.ResponseType, requestObject.ClientID, requestObject.State, base64.RawStdEncoding.EncodeToString(metadata)).WithContext(ctx).Exec()
}

// TryBeginFulfillment uses a Cassandra lightweight transaction to ensure that
// concurrent requests cannot send the same presentation twice.
func TryBeginFulfillment(ctx context.Context, row *model.VerificationEntry) (bool, error) {
	env := appCommon.GetEnvironment()
	q := `UPDATE ocm.presentations SET status=?,last_update_timestamp=toTimestamp(now()) WHERE partition=? AND region=? AND country=? AND tenantId=? AND groupId=? AND requestId=? IF status=?`
	var applied bool
	var currentStatus string
	err := env.GetSession().Query(q, model.PresentationFulfilling, row.Partition, row.Region, row.Country, row.TenantId, row.GroupId, row.RequestId, model.PresentationRequested).WithContext(ctx).Scan(&applied, &currentStatus)
	return applied, err
}

// ReleaseFulfillment only reopens a transaction that has not yet been transmitted.
func ReleaseFulfillment(ctx context.Context, row *model.VerificationEntry) error {
	env := appCommon.GetEnvironment()
	q := `UPDATE ocm.presentations SET status=? WHERE partition=? AND region=? AND country=? AND tenantId=? AND groupId=? AND requestId=? IF status=?`
	var applied bool
	var currentStatus string
	return env.GetSession().Query(q, model.PresentationRequested, row.Partition, row.Region, row.Country, row.TenantId, row.GroupId, row.RequestId, model.PresentationFulfilling).WithContext(ctx).Scan(&applied, &currentStatus)
}
