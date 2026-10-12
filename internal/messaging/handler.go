package messaging

import (
	"github.com/eclipse-xfsc/oid4-vci-credential-verification-service/internal/model"
	"gitlab.eclipse.org/eclipse/xfsc/libraries/microservice/core/pkg/logr"
)

type EventHandler interface {
	Listen()
	Close()
	Alive() bool
	Initialize(*model.Config, logr.Logger) error
}

func StartCloudEvents(config *model.Config, logger logr.Logger, eventHandler ...EventHandler) error {
	for _, evH := range eventHandler {
		err := evH.Initialize(config, logger)

		if err != nil {
			logger.Error(err, "Failed to initialze the Eventhandler.")
			return err
		}
		go evH.Listen()
	}

	return nil
}

func StopCloudEvents(eventHandler ...EventHandler) {
	for _, evH := range eventHandler {
		evH.Close()
	}
}

func GetAlive(eventHandler ...EventHandler) bool {
	var alive = true
	for _, evH := range eventHandler {
		alive = alive && evH.Alive()
	}

	return alive
}
