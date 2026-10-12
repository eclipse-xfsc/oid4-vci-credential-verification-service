package model

import (
	"time"

	"github.com/eclipse-xfsc/oid4-vci-vp-library/model/presentation"
)

type VerificationEntry struct {
	Partition           string                 `json:"partition"`
	TenantId            string                 `json:"tenantId"`
	Region              string                 `json:"region"`
	Country             string                 `json:"country"`
	RequestId           string                 `json:"requestId"`
	GroupId             string                 `json:"groupid"`
	DCQLQuery           presentation.DCQLQuery `json:"dcqlQuery"`
	Presentation        presentation.VPToken   `json:"presentation"`
	RedirectUri         string                 `json:"redirectUri"`
	ResponseUri         string                 `json:"responseUri"`
	ResponseMode        string                 `json:"responseMode"`
	ResponseType        string                 `json:"responseType"`
	State               string                 `json:"state"`
	LastUpdateTimeStamp time.Time              `json:"lastUpdateTimeStamp"`
	Nonce               string                 `json:"nonce"`
	ClientId            string                 `json:"clientId"`
}
