package elevation

import "testing"

func TestPendingGetAndTaskMismatch(t *testing.T) {
	s := New()
	r := s.Enqueue("t1", "payments", "charge", "payments://acct/1", "x")
	if len(s.Pending()) != 1 {
		t.Fatal("pending")
	}
	got, err := s.Get(r.ID)
	if err != nil || got.ID != r.ID {
		t.Fatal(err)
	}
	if _, err := s.Get("nope"); err == nil {
		t.Fatal("missing")
	}
	_, _ = s.Approve(r.ID)
	if err := s.Consume(r.ID, "other", "payments", "charge", "payments://acct/1"); err == nil {
		t.Fatal("task mismatch")
	}
	if _, err := s.Approve(r.ID); err == nil {
		t.Fatal("not pending")
	}
}
