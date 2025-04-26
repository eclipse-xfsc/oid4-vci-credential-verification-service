package common

import (
	"github.com/gocql/gocql"
	ginSwagger "github.com/swaggo/gin-swagger"
	logr "gitlab.eclipse.org/eclipse/xfsc/libraries/microservice/core/pkg/logr"
	"github.com/eclipse-xfsc/oid4-vci-credential-verification-service/docs"
	"github.com/eclipse-xfsc/oid4-vci-credential-verification-service/internal/model"
)

type Environment struct {
	session         *gocql.Session
	mode            string
	cryptoNamespace string
	logger          logr.Logger
	config          *model.Config
}

var env *Environment

func init() {
	env = new(Environment)
}

func (e *Environment) SetLogger(logger logr.Logger) {
	e.logger = logger
}

func (e *Environment) GetLogger() logr.Logger {
	return e.logger
}

func (e *Environment) IsHealthy() bool {
	if e.session != nil {
		return !e.session.Closed()
	}
	return false
}

func (e *Environment) SetConfig(config *model.Config) {
	e.config = config
}

func (e *Environment) GetConfig() *model.Config {
	return e.config
}

func GetEnvironment() *Environment {
	return env
}

func (e *Environment) SetSession(session *gocql.Session) {
	e.session = session
}

func (e *Environment) GetSession() *gocql.Session {
	return e.session
}

func (e *Environment) GetRegion() string {
	return e.config.Region
}

func (e *Environment) GetCountry() string {
	return e.config.Country
}

func (e *Environment) SetCryptoNamespace(namespace string) {
	e.cryptoNamespace = namespace
}

func (e *Environment) GetCryptoNamespace() string {
	return e.cryptoNamespace
}

func (e *Environment) SetMode(mode string) {
	e.mode = mode
}

func (e *Environment) GetMode() string {
	return e.mode
}

// SetSwaggerBasePath sets the base path that will be used by swagger ui for requests url generation
func (env *Environment) SetSwaggerBasePath(path string) {
	docs.SwaggerInfo.BasePath = path
}

// SwaggerOptions swagger config options. See https://github.com/swaggo/gin-swagger?tab=readme-ov-file#configuration
func (env *Environment) SwaggerOptions() []func(config *ginSwagger.Config) {
	return []func(config *ginSwagger.Config){
		ginSwagger.DefaultModelsExpandDepth(10),
	}
}
