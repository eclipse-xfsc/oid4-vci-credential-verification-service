package model

import (
	"time"

	config "github.com/eclipse-xfsc/microservice-core-go/pkg/config"

	cloudeventprovider "github.com/eclipse-xfsc/cloud-event-provider"
)

type Config struct {
	config.BaseConfig `mapstructure:",squash"`
	ServingPort       string `mapstructure:"servingPort" envconfig:"SERVINGPORT" default:"8080"`
	PublicBasePath    string `mapstructure:"publicBasePath" envconfig:"PUBLICBASEPATH" default:"/api/presentation/proof"`
	Cassandra         struct {
		Host     string `mapstructure:"host" envconfig:"HOST"`
		KeySpace string `mapstructure:"keyspace" envconfig:"KEYSPACE"`
		User     string `mapstructure:"user" envconfig:"USER"`
		Password string `mapstructure:"password" envconfig:"PASSWORD"`
	} `mapstructure:"cassandra" envconfig:"CASSANDRA"`
	Country    string `mapstructure:"country" envconfig:"COUNTRY"`
	Region     string `mapstructure:"region" envconfig:"REGION"`
	Migrations struct {
		Enabled bool          `mapstructure:"enabled" envconfig:"ENABLED" default:"true"`
		Table   string        `mapstructure:"table" envconfig:"TABLE" default:"verification_schema_migration"`
		Timeout time.Duration `mapstructure:"timeout" envconfig:"TIMEOUT" default:"2m"`
	} `mapstructure:"migrations" envconfig:"MIGRATIONS"`
	StateSigningKey      string `mapstructure:"stateSigningKey" envconfig:"STATESIGNINGKEY" json:"-"`
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
		SignerTopic           string `mapstructure:"signerTopic" envconfig:"TOPIC"`
	} `mapstructure:"signerService" envconfig:"SIGNER"`
	Authorization       string                          `mapstructure:"authorization" envconfig:"AUTHORIZATION"`
	AuthorizationReply  string                          `mapstructure:"authorizationReply" envconfig:"AUTHORIZATIONREPLY"`
	ProofNotify         string                          `mapstructure:"proofNotify" envconfig:"PROOFNOTIFY"`
	PresentationRequest string                          `mapstructure:"presentationRequest" envconfig:"PRESENTATIONREQUEST"`
	StorageRequest      string                          `mapstructure:"storageRequest" envconfig:"STORAGE_TOPIC"`
	StorageServiceURL   string                          `mapstructure:"storageServiceUrl" envconfig:"STORAGE_URL"`
	Protocol            cloudeventprovider.ProtocolType `mapstructure:"protocol" envconfig:"PROTOCOL" default:"nats"`
	Nats                cloudeventprovider.NatsConfig   `mapstructure:"nats" envconfig:"NATS"`
}
