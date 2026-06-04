package capability

import (
	"testing"
	"time"
)

func testGrant() Grant {
	return Grant{
		ID:              "grant-1",
		TaskID:          "task-1",
		Tool:            "db",
		Operation:       "read",
		ResourcePattern: "db://customers/123/*",
		IssuedAt:        time.Now(),
	}
}

func TestMintAndVerifyHappyPath(t *testing.T) {
	m, err := NewMinter(5 * time.Second)
	if err != nil {
		t.Fatal(err)
	}
	v := NewVerifier(m.Public, NewMemoryNonces())
	g := testGrant()
	c, err := m.Mint(g, MintRequest{Tool: "db", Operation: "read", Resource: "db://customers/123/profile"})
	if err != nil {
		t.Fatal(err)
	}
	wire, err := c.Encode()
	if err != nil {
		t.Fatal(err)
	}
	got, err := v.Verify(wire, VerifyRequest{Tool: "db", Operation: "read", Resource: "db://customers/123/profile", TaskID: "task-1"})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if got.Nonce != c.Nonce {
		t.Fatal("nonce mismatch")
	}
}

func TestMintRejectsWidening(t *testing.T) {
	m, _ := NewMinter(time.Second)
	_, err := m.Mint(testGrant(), MintRequest{Tool: "db", Operation: "read", Resource: "db://customers/124/x"})
	if err == nil {
		t.Fatal("expected widening error")
	}
}

func TestAttenuationNarrowingSucceedsWideningFails(t *testing.T) {
	existing := []Caveat{{Type: CaveatResource, Value: "db://customers/123/*"}}
	if _, err := Attenuate(existing, []Caveat{{Type: CaveatResource, Value: "db://customers/123/profile"}}); err != nil {
		t.Fatalf("narrowing: %v", err)
	}
	if _, err := Attenuate(existing, []Caveat{{Type: CaveatResource, Value: "db://customers/*"}}); err == nil {
		t.Fatal("widening caveat must fail")
	}
	oldExp := time.Now().Add(2 * time.Second).UTC().Format(time.RFC3339)
	existing = append(existing, Caveat{Type: CaveatExpires, Value: oldExp})
	later := time.Now().Add(1 * time.Hour).UTC().Format(time.RFC3339)
	if _, err := Attenuate(existing, []Caveat{{Type: CaveatExpires, Value: later}}); err == nil {
		t.Fatal("extending ttl must fail")
	}
}

func TestVerifyBadSignature(t *testing.T) {
	m, _ := NewMinter(time.Second)
	v := NewVerifier(m.Public, NewMemoryNonces())
	c, _ := m.Mint(testGrant(), MintRequest{Tool: "db", Operation: "read", Resource: "db://customers/123/x"})
	c.Signature = "AAAA"
	wire, _ := c.Encode()
	if _, err := v.Verify(wire, VerifyRequest{Tool: "db", Operation: "read", Resource: "db://customers/123/x"}); err == nil {
		t.Fatal("bad signature must fail")
	}
}

func TestVerifyExpired(t *testing.T) {
	m, _ := NewMinter(time.Second)
	base := time.Now()
	m.Now = func() time.Time { return base }
	c, _ := m.Mint(testGrant(), MintRequest{Tool: "db", Operation: "read", Resource: "db://customers/123/x"})
	v := NewVerifier(m.Public, NewMemoryNonces())
	v.Now = func() time.Time { return base.Add(2 * time.Second) }
	wire, _ := c.Encode()
	if _, err := v.Verify(wire, VerifyRequest{Tool: "db", Operation: "read", Resource: "db://customers/123/x"}); err == nil {
		t.Fatal("expired must fail")
	}
}

func TestVerifyReplay(t *testing.T) {
	m, _ := NewMinter(5 * time.Second)
	v := NewVerifier(m.Public, NewMemoryNonces())
	c, _ := m.Mint(testGrant(), MintRequest{Tool: "db", Operation: "read", Resource: "db://customers/123/x"})
	wire, _ := c.Encode()
	call := VerifyRequest{Tool: "db", Operation: "read", Resource: "db://customers/123/x", TaskID: "task-1"}
	if _, err := v.Verify(wire, call); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Verify(wire, call); err == nil {
		t.Fatal("replay must fail")
	}
}

func TestCaveatStrippingFailsVerification(t *testing.T) {
	m, _ := NewMinter(5 * time.Second)
	v := NewVerifier(m.Public, NewMemoryNonces())
	c, _ := m.Mint(testGrant(), MintRequest{Tool: "db", Operation: "read", Resource: "db://customers/123/x"})
	tampered := c.TamperResource("db://customers/124/x")
	wire, _ := tampered.Encode()
	if _, err := v.Verify(wire, VerifyRequest{Tool: "db", Operation: "read", Resource: "db://customers/124/x", TaskID: "task-1"}); err == nil {
		t.Fatal("stripped/widened caveat must fail signature")
	}
}

func TestRevokedGrantCannotMint(t *testing.T) {
	m, _ := NewMinter(time.Second)
	g := testGrant()
	g.Revoked = true
	if _, err := m.Mint(g, MintRequest{Tool: "db", Operation: "read", Resource: "db://customers/123/x"}); err == nil {
		t.Fatal("revoked grant must not mint")
	}
}
