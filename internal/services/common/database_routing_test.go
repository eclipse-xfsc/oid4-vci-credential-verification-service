package common

import "testing"

// Match the explicit SELECT column order, using distinct routing values so a
// namespace/account-group/key-group swap cannot pass unnoticed.
type routingIter struct{ done bool }

func (i *routingIter) Scan(dest ...interface{}) bool {
	if i.done {
		return false
	}
	i.done = true
	for index, value := range map[int]string{3: "tenant", 4: "account-group", 5: "request", 20: "crypto-namespace", 21: "crypto-group", 22: "key"} {
		*dest[index].(*string) = value
	}
	return true
}
func (i *routingIter) Close() error { return nil }
func TestCassandraRoutingSnapshot(t *testing.T) {
	rows, err := scanEntries(&routingIter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("got %d rows", len(rows))
	}
	row := rows[0]
	if row.TenantId != "tenant" || row.GroupId != "account-group" || row.RequestId != "request" || row.ProfileKeyNamespace != "crypto-namespace" || row.ProfileKeyGroup != "crypto-group" || row.ProfileKeyID != "key" {
		t.Fatal("Cassandra routing snapshot was mixed up")
	}
}
