package connection

import (
	"github.com/gocql/gocql"
	"github.com/sirupsen/logrus"
	"github.com/eclipse-xfsc/oid4-vci-credential-verification-service/internal/common"
)

type DBConnection interface {
	Connection() (*gocql.Session, error)
}

func Connection(env *common.Environment) (*gocql.Session, error) {
	config := env.GetConfig()
	host := config.CassandraHosts
	cluster := gocql.NewCluster(host)

	if config.CassandraUser != "" && config.CassandraPassword != "" {
		cluster.Authenticator = gocql.PasswordAuthenticator{
			Username: config.CassandraUser,
			Password: config.CassandraPassword,
		}
	}

	cluster.Consistency = gocql.Quorum
	cluster.ProtoVersion = 4

	session, err := cluster.CreateSession()
	if err != nil {
		return nil, err
	}

	if err != nil {
		defer logrus.Info("Connection to database failed")
		logrus.Fatal(err.Error())
	} else {
		logrus.Info("Connection to database successful")
	}

	return session, err
}
