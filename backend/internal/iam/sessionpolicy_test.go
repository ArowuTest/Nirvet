package iam

import "testing"

func TestValidIPEntry(t *testing.T) {
	for _, e := range []string{"10.0.0.0/8", "192.168.1.1", "2001:db8::/32", "::1"} {
		if !validIPEntry(e) {
			t.Errorf("expected %q to be a valid allow-list entry", e)
		}
	}
	for _, e := range []string{"", "not-an-ip", "10.0.0.0/99", "999.1.1.1", "10.0.0.0/"} {
		if validIPEntry(e) {
			t.Errorf("expected %q to be rejected", e)
		}
	}
}

func TestIPAllowed(t *testing.T) {
	allow := []string{"10.0.0.0/8", "192.168.1.5"}
	cases := []struct {
		ip   string
		want bool
	}{
		{"10.1.2.3", true},     // inside CIDR
		{"192.168.1.5", true},  // exact match
		{"192.168.1.6", false}, // near-miss exact
		{"8.8.8.8", false},     // outside
		{"not-an-ip", false},   // unparseable fails closed
	}
	for _, c := range cases {
		if got := ipAllowed(c.ip, allow); got != c.want {
			t.Errorf("ipAllowed(%q) = %v, want %v", c.ip, got, c.want)
		}
	}
	// Empty allow-list is only meaningful via CheckSession (no restriction); ipAllowed itself
	// returns false for an empty list, which is why CheckSession short-circuits on len==0.
	if ipAllowed("10.1.2.3", nil) {
		t.Error("ipAllowed against an empty list must be false (CheckSession handles the no-restriction case)")
	}
}
