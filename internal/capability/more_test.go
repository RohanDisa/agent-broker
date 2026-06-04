package capability

import (
	"testing"
	"time"
)

func TestGrantCoversAndDestinationAllowed(t *testing.T) {
	g := Grant{
		Tool: "email", Operation: "send", ResourcePattern: "email://*",
		Constraints: Constraints{DestinationAllowlist: []string{"*@ourco.com"}},
	}
	if !g.Covers("email", "send", "email://a@ourco.com") {
		t.Fatal("covers")
	}
	if !g.DestinationAllowed("alice@ourco.com") {
		t.Fatal("allowlist")
	}
	if g.DestinationAllowed("evil@x.com") {
		t.Fatal("external")
	}
	open := Grant{Tool: "db", Operation: "read", ResourcePattern: "db://x"}
	if !open.DestinationAllowed("anywhere") {
		t.Fatal("empty allowlist is open")
	}
}

func TestDecodeMalformed(t *testing.T) {
	if _, err := DecodeCredential("not-base64%%%"); err == nil {
		t.Fatal("expected error")
	}
	if _, err := DecodeCredential(""); err == nil {
		t.Fatal("expected error")
	}
}

func TestCaveatHelpers(t *testing.T) {
	c := Caveat{Type: CaveatTool, Value: "db"}
	if c.String() == "" || c.Canonical() != "tool:db" {
		t.Fatal(c)
	}
	existing := []Caveat{{Type: CaveatTool, Value: "db"}}
	if _, err := Attenuate(existing, []Caveat{{Type: CaveatTool, Value: "email"}}); err == nil {
		t.Fatal("cannot change tool")
	}
}

func TestMatchHostWildcardDomain(t *testing.T) {
	if !MatchHostPattern("*.ourco.com", "api.ourco.com") {
		t.Fatal("subdomain")
	}
	if MatchPattern("", "x") {
		t.Fatal("empty pattern")
	}
	if !MatchPattern("", "") {
		t.Fatal("empty both")
	}
}

func TestMinterFromKeyRoundTrip(t *testing.T) {
	m, _ := NewMinter(time.Second)
	m2 := MinterFromKey(m.Private, 0)
	c, err := m2.Mint(testGrant(), MintRequest{Tool: "db", Operation: "read", Resource: "db://customers/123/x"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Encode(); err != nil {
		t.Fatal(err)
	}
}
