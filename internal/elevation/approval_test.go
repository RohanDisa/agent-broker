package elevation

import "testing"

func TestApprovalSingleUse(t *testing.T) {
	s := New()
	r := s.Enqueue("t1", "payments", "charge", "payments://acct/1", "high-risk")
	if _, err := s.Approve(r.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.Consume(r.ID, "t1", "payments", "charge", "payments://acct/1"); err != nil {
		t.Fatal(err)
	}
	if err := s.Consume(r.ID, "t1", "payments", "charge", "payments://acct/1"); err == nil {
		t.Fatal("approval reuse must fail")
	}
}

func TestDeniedCannotProceed(t *testing.T) {
	s := New()
	r := s.Enqueue("t1", "payments", "charge", "payments://acct/1", "no")
	if _, err := s.Deny(r.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.Consume(r.ID, "t1", "payments", "charge", "payments://acct/1"); err == nil {
		t.Fatal("denied elevation must not consume")
	}
}

func TestApproveWrongCallRejected(t *testing.T) {
	s := New()
	r := s.Enqueue("t1", "payments", "charge", "payments://acct/1", "x")
	_, _ = s.Approve(r.ID)
	if err := s.Consume(r.ID, "t1", "payments", "charge", "payments://acct/2"); err == nil {
		t.Fatal("approval is scoped to one call")
	}
}
