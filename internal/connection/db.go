package connection

import (
	"context"

	"github.com/gocql/gocql"
	"github.com/sirupsen/logrus"
)

type SessionInterface interface {
	Query(string, ...interface{}) QueryInterface
	Closed() bool
	Close()
}

type QueryInterface interface {
	Scan(...interface{}) error
	Exec() error
	Iter() IterInterface
	WithContext(ctx context.Context) QueryInterface
	Consistency(consistency gocql.Consistency) QueryInterface
}

type IterInterface interface {
	Scan(...interface{}) bool
	Close() error
}

type Session struct{ session *gocql.Session }

func (s *Session) Closed() bool { return s.session.Closed() }
func (s *Session) Close()       { s.session.Close() }
func (s *Session) Query(stmt string, values ...interface{}) QueryInterface {
	return NewQuery(s.session.Query(stmt, values...))
}

type Query struct{ query *gocql.Query }

func (q *Query) Consistency(c gocql.Consistency) QueryInterface {
	return NewQuery(q.query.Consistency(c))
}
func (q *Query) Exec() error                    { return q.query.Exec() }
func (q *Query) Iter() IterInterface            { return q.query.Iter() }
func (q *Query) Scan(dest ...interface{}) error { return q.query.Scan(dest...) }
func (q *Query) WithContext(c context.Context) QueryInterface {
	return NewQuery(q.query.WithContext(c))
}
func NewSession(session *gocql.Session) SessionInterface { return &Session{session: session} }
func NewQuery(query *gocql.Query) QueryInterface         { return &Query{query: query} }

func Connection(host, user, password string) (SessionInterface, error) {
	cluster := gocql.NewCluster(host)
	if user != "" && password != "" {
		cluster.Authenticator = gocql.PasswordAuthenticator{Username: user, Password: password}
	}
	cluster.Consistency = gocql.Quorum
	cluster.ProtoVersion = 4
	session, err := cluster.CreateSession()
	if err != nil {
		return nil, err
	}
	logrus.Info("Connection to database successful")
	return NewSession(session), nil
}
