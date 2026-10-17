package main

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"time"

	conf "github.com/eclipse-xfsc/microservice-core-go/pkg/config"
	logr "github.com/eclipse-xfsc/microservice-core-go/pkg/logr"
	server "github.com/eclipse-xfsc/microservice-core-go/pkg/server"

	"github.com/eclipse-xfsc/oid4-vci-credential-verification-service/internal/api"
	"github.com/eclipse-xfsc/oid4-vci-credential-verification-service/internal/common"
	"github.com/eclipse-xfsc/oid4-vci-credential-verification-service/internal/connection"
	"github.com/eclipse-xfsc/oid4-vci-credential-verification-service/internal/messaging"
	"github.com/eclipse-xfsc/oid4-vci-credential-verification-service/internal/migration"
	"github.com/eclipse-xfsc/oid4-vci-credential-verification-service/internal/model"
	"github.com/eclipse-xfsc/oid4-vci-credential-verification-service/internal/services"
	"github.com/kelseyhightower/envconfig"
)

var env *common.Environment

func connectDb() error {
	// Establish connections
	cfg := env.GetConfig()
	dbSession, err := connection.Connection(cfg.Cassandra.Host, cfg.Cassandra.User, cfg.Cassandra.Password)
	if err != nil {
		env.GetLogger().Error(err, "Database could not be connected")
		return err
	} else {
		env.SetSession(dbSession)
		env.GetLogger().Info("Database connected")
	}
	return nil
}

// @title			Credential verification service API
// @version		1.0
// @description	Service for handling credentials proofs (presentations)
// @license.name	Apache 2.0
// @license.url	http://www.apache.org/licenses/LICENSE-2.0.html
// @host			localhost:8080

func main() {
	// The DID library expects the unprefixed variable. Preserve an explicit
	// DID_RESOLVER override, otherwise use the injected provider output.
	injected, ok := os.LookupEnv("CREDENTIALVERIFICATION_DID_RESOLVER")

	if !ok {
		log.Fatalf("did resolver required  %t", "CREDENTIALVERIFICATION_DID_RESOLVER not set")
	}

	_ = os.Setenv("DID_RESOLVER", injected)

	env = common.GetEnvironment()
	var config model.Config
	err := conf.LoadConfig("CREDENTIALVERIFICATION", &config, nil)
	if err == nil {

		err = envconfig.Process("CREDENTIALVERIFICATION", &config)

		if err != nil {
			log.Fatalf("envconfig was not loaded: %t", err)
		}

		tmpLogger, err := logr.New(config.BaseConfig.LogLevel, true, nil)

		if err != nil {
			log.Fatalf("failed to init logger: %t", err)
		}

		logger := *tmpLogger

		configDebug, _ := json.MarshalIndent(config, "", "  ")
		logger.Debug("initialised", "configuration", string(configDebug))

		env.SetLogger(logger)
		env.SetConfig(&config)
		err = connectDb()
		if err == nil {
			migrationTimeout := config.Migrations.Timeout
			if migrationTimeout <= 0 {
				migrationTimeout = 2 * time.Minute
			}
			if err := migration.Run(context.Background(), env.GetSession(), migration.Config{
				Enabled: config.Migrations.Enabled,
				Table:   config.Migrations.Table,
				Timeout: migrationTimeout,
			}); err != nil {
				logger.Error(err, "Failed applying Cassandra migrations")
				return
			}

			server := server.New(env, config.BaseConfig.ServerMode)

			logger.Debug("Start Server")

			var authHandler = new(services.AuthorizationHandler)
			var requestor = new(services.PresentationRequestor)

			err := messaging.StartCloudEvents(&config, logger, authHandler, requestor)

			if err != nil {
				logger.Error(err, "Cloud Events couldnt start properly.")
				return
			}

			api.AddExternalRoutes(server, authHandler, requestor)
			api.AddInternalRoutes(server, requestor)

			err = server.Run(config.BaseConfig.ListenPort)
			if err != nil {
				logger.Error(err, "Server couldn't start.")
				return
			}

			messaging.StopCloudEvents()
		}
	} else {
		log.Fatal(err)
	}
}
