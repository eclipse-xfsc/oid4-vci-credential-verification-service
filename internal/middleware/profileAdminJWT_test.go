package middleware

import (
 "testing"
 "github.com/golang-jwt/jwt/v5"
)

func TestHasProfileAdminScope(t *testing.T) {
 cases := []struct{ name string; claims jwt.MapClaims; want bool }{
  {"missing", jwt.MapClaims{}, false},
  {"correct scope", jwt.MapClaims{"scope":"openid presentation-profiles:write"}, true},
  {"partial scope", jwt.MapClaims{"scope":"presentation-profiles:writer"}, false},
  {"scp array", jwt.MapClaims{"scp":[]interface{}{"presentation-profiles:write"}}, true},
  {"wrong scope", jwt.MapClaims{"scope":"presentation-profiles:read"}, false},
 }
 for _, tc := range cases { t.Run(tc.name,func(t *testing.T){ if got:=hasProfileAdminScope(tc.claims,"presentation-profiles:write");got!=tc.want { t.Fatalf("got %v, want %v",got,tc.want) } }) }
}
