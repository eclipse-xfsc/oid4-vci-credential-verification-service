package common

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/gocql/gocql"
	"gitlab.eclipse.org/eclipse/xfsc/libraries/ssi/oid4vip/model/presentation"
	"github.com/eclipse-xfsc/oid4-vci-credential-verification-service/internal/common"
	"github.com/eclipse-xfsc/oid4-vci-credential-verification-service/internal/model"
)

func getEntriesFromDb(ctx context.Context, tenantId string, id string, searchField string) ([]model.VerificationEntry, error) {
	env := common.GetEnvironment()
	session := env.GetSession()
	var dregion string
	var dcountry string
	var did string
	var drId string
	var ddefinition string
	var dpresentation string
	var dredirectUri string
	var dstate string
	var dlastUpdateTimeStamp time.Time
	var dnonce string
	var dresponseUri string
	var dresponseMode string
	var dresponseType string
	var dclientId string
	var dgroupId string

	queryString := fmt.Sprintf(`SELECT region,country,id,requestid,presentationdefinition,presentation,redirecturi,state,last_update_timestamp,nonce,responseuri,responsemode,responsetype,clientid,groupid FROM %s.presentations WHERE region=? AND
																																												country=? AND
																																												%s=?;`, tenantId, searchField)

	query := session.Query(queryString,
		env.GetRegion(),
		env.GetCountry(),
		id).Consistency(gocql.LocalQuorum).Iter()

	ret := make([]model.VerificationEntry, 0)

	for query.Scan(
		&dregion,
		&dcountry,
		&did,
		&drId,
		&ddefinition,
		&dpresentation,
		&dredirectUri,
		&dstate,
		&dlastUpdateTimeStamp,
		&dnonce,
		&dresponseUri,
		&dresponseMode,
		&dresponseType,
		&dclientId,
		&dgroupId) {

		row := model.VerificationEntry{
			Region:              dregion,
			Country:             dcountry,
			Id:                  did,
			RequestId:           drId,
			RedirectUri:         dredirectUri,
			State:               dstate,
			LastUpdateTimeStamp: dlastUpdateTimeStamp,
			Nonce:               dnonce,
			ResponseUri:         dresponseUri,
			ResponseMode:        dresponseMode,
			ResponseType:        dresponseType,
			ClientId:            dclientId,
			GroupId:             dgroupId,
		}

		bpresentatioDefinition, err := base64.RawStdEncoding.DecodeString(ddefinition)

		if err != nil {
			return nil, err
		}

		if len(bpresentatioDefinition) > 0 {
			var pD presentation.PresentationDefinition

			err = json.Unmarshal(bpresentatioDefinition, &pD)

			if err != nil {
				return nil, err
			}

			row.PresentationDefinition = pD

		}

		bPresentation, err := base64.RawStdEncoding.DecodeString(dpresentation)

		if err != nil {
			return nil, err
		}

		if len(bPresentation) > 0 {

			var p []interface{}

			err = json.Unmarshal(bPresentation, &p)

			if err != nil {
				return nil, err
			}
			row.Presentation = p
		}

		ret = append(ret, row)
	}

	if err := query.Close(); err != nil {
		return nil, err
	}

	return ret, nil
}

func GetEntryFromDb(ctx context.Context, tenantId string, id string) (*model.VerificationEntry, error) {
	rows, err := getEntriesFromDb(ctx, tenantId, id, "id")
	if len(rows) > 0 {
		return &rows[0], err
	} else {
		return nil, errors.Join(fmt.Errorf("no rows found for id %s", id), err)
	}
}

func GetEntryFromDbByRequestId(ctx context.Context, tenantId string, requestId string) (*model.VerificationEntry, error) {
	rows, err := getEntriesFromDb(ctx, tenantId, requestId, "requestId")
	if len(rows) > 0 {
		return &rows[0], err
	} else {
		return nil, errors.Join(fmt.Errorf("no rows found for requestId %s", requestId), err)
	}
}

type PresentationRequestOptions struct {
	TenantId  string `json:"tenantId"`
	Id        string `json:"id"`
	RequestId string `json:"requestId"`
	GroupId   string `json:"groupId"`
	// in seconds
	Ttl int `json:"ttl"`
}

func AddPresentationDefinitonToDb(presentationDefinition presentation.PresentationDefinition, options PresentationRequestOptions, ctx context.Context) error {
	env := common.GetEnvironment()
	session := env.GetSession()

	queryString := fmt.Sprintf(`INSERT INTO %s.presentations (region,country,id,presentationDefinition,state,last_update_timestamp,requestId,nonce, groupid) VALUES(?,?,?,?,?,toTimestamp(now()),?,?,?) USING TTL ?;`, options.TenantId)

	pD, err := json.Marshal(presentationDefinition)

	if err != nil {
		env.GetLogger().Error(err, "Error marshalling definition.")
		return err
	}

	b := make([]byte, 32)
	_, err = rand.Read(b)

	if err != nil {
		env.GetLogger().Error(err, "Error creating rand")
		return err
	}

	err = session.Query(queryString,
		env.GetRegion(),  // region
		env.GetCountry(), //country
		options.Id,
		base64.RawStdEncoding.EncodeToString(pD), //presentation Definition
		model.PresentationRequested,              //status
		options.RequestId,
		base64.RawStdEncoding.EncodeToString(b), //nonce
		options.GroupId,
		options.Ttl, //TTL
	).WithContext(ctx).Exec()

	if err != nil {
		env.GetLogger().Error(err, "Error during db update.")
		return err
	}

	return nil
}

func GetEntriesFromDb(ctx context.Context, tenantId string, id string) ([]model.VerificationEntry, error) {
	return getEntriesFromDb(ctx, tenantId, id, "groupId")
}

func AssignEntryToGroup(ctx context.Context, tenantId string, id string, groupId string) error {
	env := common.GetEnvironment()
	session := env.GetSession()

	queryString := fmt.Sprintf(`UPDATE %s.presentations SET groupId=?,last_update_timestamp=toTimestamp(now()) WHERE 
		region=? AND 
		country=? AND
		id=?;`, tenantId)

	err := session.Query(queryString,
		groupId,          //groupId
		env.GetRegion(),  // region
		env.GetCountry(), //country
		id).WithContext(ctx).Exec()

	if err != nil {
		env.GetLogger().Error(err, "Error during db update.")
		return err
	}
	return nil
}

func UpdateDbStatus(ctx context.Context, tenantId string, status string, id string) error {
	env := common.GetEnvironment()
	session := env.GetSession()

	queryString := fmt.Sprintf(`UPDATE %s.presentations SET state=?,last_update_timestamp=toTimestamp(now()) WHERE 
		region=? AND 
		country=? AND
		id=?;`, tenantId)

	err := session.Query(queryString,
		status,           //status
		env.GetRegion(),  // region
		env.GetCountry(), //country
		id).WithContext(ctx).Exec()

	if err != nil {
		env.GetLogger().Error(err, "Error during db update.")
		return err
	}
	return nil
}

func StorePresentation(ctx context.Context, id string, tenantId string, proof []byte) error {
	env := common.GetEnvironment()
	session := env.GetSession()

	queryString := fmt.Sprintf(`UPDATE %s.presentations SET state=?,last_update_timestamp=toTimestamp(now()),presentation=? WHERE
		region=? AND
		country=? AND
		id=?;`, tenantId)

	err := session.Query(queryString,
		model.PresentationReceived, //status
		base64.RawStdEncoding.EncodeToString(proof),
		env.GetRegion(),  // region
		env.GetCountry(), //country
		id).WithContext(ctx).Exec()

	if err != nil {
		env.GetLogger().Error(err, "Error during db update.")
		return err
	}
	return nil
}

func StoreRequest(ctx context.Context, requestId string, tenantId string, id string, requestObject *presentation.RequestObject) error {
	env := common.GetEnvironment()
	session := env.GetSession()

	queryString := fmt.Sprintf(`UPDATE %s.presentations SET state=?,last_update_timestamp=toTimestamp(now()),presentationDefinition=?,redirectUri=?,nonce=?,requestId=?,responseUri=?,responseMode=?,responseType=?,ClientId=? WHERE 
		region=? AND 
		country=? AND
		id=?;`, tenantId)

	b, err := json.Marshal(requestObject.PresentationDefinition)

	if err != nil {
		env.GetLogger().Logger.Error(err, "Error during db update.")
		return err
	}

	err = session.Query(queryString,
		model.PresentationRequested, //status
		base64.RawStdEncoding.EncodeToString(b),
		requestObject.RedirectUri,
		requestObject.Nonce,
		requestId,
		requestObject.ResponseUri,
		requestObject.ResponseMode,
		requestObject.ResponseType,
		requestObject.ClientID,
		env.GetRegion(),  // region
		env.GetCountry(), //country
		id).WithContext(ctx).Exec()

	if err != nil {
		env.GetLogger().Logger.Error(err, "Error during db update.")
		return err
	}
	return nil
}
