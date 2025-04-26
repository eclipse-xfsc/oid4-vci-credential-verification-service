package model

import (
	"time"

	"gitlab.eclipse.org/eclipse/xfsc/libraries/ssi/oid4vip/model/presentation"
)

type VerificationEntry struct {
	Region                 string                              `json:"region"`
	Country                string                              `json:"country"`
	Id                     string                              `json:"id"`
	RequestId              string                              `json:"requestId"`
	GroupId                string                              `json:"groupid"`
	PresentationDefinition presentation.PresentationDefinition `json:"presentationDefinition"`
	Presentation           []interface{}                       `json:"presentation"`
	RedirectUri            string                              `json:"redirectUri"`
	ResponseUri            string                              `json:"responseUri"`
	ResponseMode           string                              `json:"responseMode"`
	ResponseType           string                              `json:"responseType"`
	State                  string                              `json:"state"`
	LastUpdateTimeStamp    time.Time                           `json:"lastUpdateTimeStamp"`
	Nonce                  string                              `json:"nonce"`
	ClientId               string                              `json:"clientId"`
}
