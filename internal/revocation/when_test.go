package revocation

import "testing"

func TestWhen(t *testing.T) {
	l := New()
	if _, ok := l.When("g"); ok {
		t.Fatal("empty")
	}
	ts := l.Revoke("g")
	got, ok := l.When("g")
	if !ok || got.IsZero() || ts.IsZero() {
		t.Fatal(got, ok)
	}
}
