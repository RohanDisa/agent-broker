package capability

import (
	"testing"
	"time"
)

func TestMatchPattern(t *testing.T) {
	cases := []struct {
		pat, val string
		want     bool
	}{
		{"db://customers/123/*", "db://customers/123/profile", true},
		{"db://customers/123/*", "db://customers/123", true},
		{"db://customers/123/*", "db://customers/124", false},
		{"db://customers/123/*", "db://customers/124/profile", false},
		{"db://customers/123/*", "db://customers/123/orders/99", true},
		{"email://*@ourco.com", "email://alice@ourco.com", true},
		{"email://*@ourco.com", "email://alice@evil.com", false},
		{"http://api.internal/*", "http://api.internal/users", true},
		{"http://api.internal/*", "http://evil.example/x", false},
		{"*", "anything", true},
		{"exact", "exact", true},
		{"exact", "other", false},
	}
	for _, tc := range cases {
		if got := MatchPattern(tc.pat, tc.val); got != tc.want {
			t.Errorf("MatchPattern(%q, %q) = %v, want %v", tc.pat, tc.val, got, tc.want)
		}
	}
}

func TestMatchHostPattern(t *testing.T) {
	if !MatchHostPattern("*@ourco.com", "alice@ourco.com") {
		t.Fatal("expected allowlist match")
	}
	if MatchHostPattern("*@ourco.com", "attacker@evil.com") {
		t.Fatal("external dest must not match")
	}
	if !MatchHostPattern("*@ourco.com", "email://bob@ourco.com") {
		t.Fatal("uri dest should strip scheme")
	}
}

func TestIsNarrowerOrEqual(t *testing.T) {
	if !IsNarrowerOrEqual("db://customers/123/profile", "db://customers/123/*") {
		t.Fatal("concrete child must be narrower")
	}
	if IsNarrowerOrEqual("db://customers/124/profile", "db://customers/123/*") {
		t.Fatal("sibling must not be narrower")
	}
	if IsNarrowerOrEqual("db://customers/*", "db://customers/123/*") {
		t.Fatal("widening pattern must fail")
	}
	if !IsNarrowerOrEqual("db://customers/123/orders/*", "db://customers/123/*") {
		t.Fatal("deeper pattern should be narrower")
	}
}

func TestGrantCanAttenuateTo(t *testing.T) {
	g := Grant{
		ID: "g1", TaskID: "t1",
		Tool: "db", Operation: "read",
		ResourcePattern: "db://customers/123/*",
		IssuedAt:        time.Now(),
	}
	if err := g.CanAttenuateTo("db", "read", "db://customers/123/profile"); err != nil {
		t.Fatalf("narrowing should succeed: %v", err)
	}
	if err := g.CanAttenuateTo("db", "read", "db://customers/124/profile"); err == nil {
		t.Fatal("widening resource should fail")
	}
	if err := g.CanAttenuateTo("email", "send", "email://a@ourco.com"); err == nil {
		t.Fatal("different tool should fail")
	}
}
