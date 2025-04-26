package model

import (
	"gitlab.eclipse.org/eclipse/xfsc/libraries/messaging/cloudeventprovider"
	config "gitlab.eclipse.org/eclipse/xfsc/libraries/microservice/core/pkg/config"
)

type Config struct {
	config.BaseConfig    `mapstructure:",squash"`
	ServingPort          string `mapstructure:"servingPort" envconfig:"SERVINGPORT" default:"8080"`
	PublicBasePath       string `mapstructure:"publicBasePath" envconfig:"PUBLICBASEPATH" default:"/api/presentation/proof"`
	CassandraHosts       string `mapstructure:"cassandraHosts" envconfig:"CASSANDRAHOSTS"`
	CassandraUser        string `mapstructure:"cassandraUser" envconfig:"CASSANDRAUSER"`
	CassandraPassword    string `mapstructure:"cassandraPassword" envconfig:"CASSANDRAPASSWORD"`
	Country              string `mapstructure:"country" envconfig:"COUNTRY"`
	Region               string `mapstructure:"region" envconfig:"REGION"`
	SigningKey           string `mapstructure:"signingKey" envconfig:"SIGNINGKEY"`
	ExternalPresentation struct {
		Enabled             bool   `mapstructure:"enabled" envconfig:"ENABLED"`
		AuthorizeEndpoint   string `mapstructure:"authorizeEndpoint" envconfig:"AUTHORIZEENDPOINT"`
		RequestObjectPolicy string `mapstructure:"requestObjectPolicy" envconfig:"REQUESTOBJECTPOLICY"`
		ClientIdPolicy      string `mapstructure:"clientIdPolicy"  envconfig:"CLIENTIDPOLICY"`
		ClientUrlSchema     string `mapstructure:"clientUrlSchema" envconfig:"CLIENTURLSCHEMA" default:"https"`
	} `mapstructure:"externalpresentation"`
	SignerService struct {
		PresentationVerifyUrl string `mapstructure:"presentationVerifyUrl" envconfig:"PRESENTATIONVERIFYURL"`
		PresentationSignUrl   string `mapstructure:"presentationSignUrl" envconfig:"PRESENTATIONSIGNURL"`
		SignerTopic           string `mapstructure:"signerTopic" envconfig:"SIGNERTOPIC"`
	} `mapstructure:"signerService"`
	Topics struct {
		Authorization       string `mapstructure:"authorization" envconfig:"AUTHORIZATION"`
		AuthorizationReply  string `mapstructure:"authorizationReply" envconfig:"AUTHORIZATIONREPLY"`
		ProofNotify         string `mapstructure:"proofNotify" envconfig:"PROOFNOTIFY"`
		PresentationRequest string `mapstructure:"presentationRequest" envconfig:"PRESENTATINREQUEST"`
		StorageRequest      string `mapstructure:"storageRequest" envconfig:"STORAGEREQUEST"`
	} `mapstructure:"topics"`
	Messaging struct {
		Protocol cloudeventprovider.ProtocolType `mapstructure:"protocol" envconfig:"PROTOCOL" default:"nats"`
		Nats     cloudeventprovider.NatsConfig   `mapstructure:"nats" envconfig:"NATS"`
	} `mapstructure:"messaging"`
}
