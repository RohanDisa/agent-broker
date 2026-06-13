package revocation

import "testing"

func TestRevokeIsVisibleImmediately(t *testing.T) {
	l := New()
	if l.Revoked("g1") {
		t.Fatal("fresh ledger")
	}
	l.Revoke("g1")
	if !l.Revoked("g1") {
		t.Fatal("revoke must take effect on the next check")
	}
}
