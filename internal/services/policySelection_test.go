package services

import "testing"

func TestPolicyAllowsBooleanAndLegacyString(t *testing.T) {
	cases := []struct {
		value interface{}
		allow bool
	}{
		{true, true}, {false, false}, {"true", true}, {"false", false}, {nil, false},
	}
	for _, tc := range cases {
		if policyAllows(map[string]interface{}{"allow": tc.value}) != tc.allow {
			t.Errorf("unexpected policy decision for %v", tc.value)
		}
	}
}
