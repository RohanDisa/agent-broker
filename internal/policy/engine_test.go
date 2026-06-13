package policy

import (
	"testing"
	"time"

	"capability-broker/internal/capability"
	"capability-broker/internal/injection"
)

func grant(tool, op, pat string) capability.Grant {
	return capability.Grant{
		ID: "g1", TaskID: "t1",
		Tool: tool, Operation: op, ResourcePattern: pat,
		IssuedAt: time.Now(),
	}
}

func TestLeastPrivilegeDeny(t *testing.T) {
	e := NewEngine()
	d := e.Evaluate(Input{
		Tool: "email", Operation: "send", Resource: "email://a@ourco.com",
		Grants: []capability.Grant{grant("db", "read", "db://customers/123/*")},
	})
	if d.Action != Deny || d.Control != ControlLeastPrivilege {
		t.Fatalf("got %+v", d)
	}
}

func TestResourceScope(t *testing.T) {
	e := NewEngine()
	g := grant("db", "read", "db://customers/123/*")
	allow := e.Evaluate(Input{Tool: "db", Operation: "read", Resource: "db://customers/123/p", Grants: []capability.Grant{g}})
	if allow.Action != Allow {
		t.Fatalf("in-scope should allow: %+v", allow)
	}
	deny := e.Evaluate(Input{Tool: "db", Operation: "read", Resource: "db://customers/124/p", Grants: []capability.Grant{g}})
	if deny.Action != Deny || deny.Control != ControlResourceScope {
		t.Fatalf("out-of-scope should deny by resource_scope: %+v", deny)
	}
}

func TestRateCountSession(t *testing.T) {
	e := NewEngine()
	g := grant("db", "read", "db://customers/123/*")
	g.Constraints.MaxCalls = 3
	d := e.Evaluate(Input{Tool: "db", Operation: "read", Resource: "db://customers/123/a", Grants: []capability.Grant{g}, CallCount: 3})
	if d.Action != Deny || d.Control != ControlRateCount {
		t.Fatalf("got %+v", d)
	}
	ok := e.Evaluate(Input{Tool: "db", Operation: "read", Resource: "db://customers/123/a", Grants: []capability.Grant{g}, CallCount: 2})
	if ok.Action != Allow {
		t.Fatalf("under cap should allow: %+v", ok)
	}
}

func TestHighRiskRequiresElevation(t *testing.T) {
	e := NewEngine()
	g := grant("payments", "charge", "payments://acct/1")
	d := e.Evaluate(Input{Tool: "payments", Operation: "charge", Resource: "payments://acct/1", Grants: []capability.Grant{g}})
	if d.Action != RequireElevation {
		t.Fatalf("got %+v", d)
	}
}

func TestEgressAllowlist(t *testing.T) {
	e := NewEngine()
	g := grant("email", "send", "email://*")
	g.Constraints.DestinationAllowlist = []string{"*@ourco.com"}
	deny := e.Evaluate(Input{
		Tool: "email", Operation: "send", Resource: "email://attacker@evil.com",
		Arguments:  map[string]string{"to": "attacker@evil.com", "body": "x"},
		Grants:     []capability.Grant{g},
		Provenance: injection.Provenance{Source: injection.User},
	})
	if deny.Action != Deny || deny.Control != ControlEgress {
		t.Fatalf("external dest should be egress deny: %+v", deny)
	}
	ok := e.Evaluate(Input{
		Tool: "email", Operation: "send", Resource: "email://alice@ourco.com",
		Arguments:  map[string]string{"to": "alice@ourco.com", "body": "hi"},
		Grants:     []capability.Grant{g},
		Provenance: injection.Provenance{Source: injection.User},
	})
	if ok.Action != Allow {
		t.Fatalf("internal dest should allow: %+v", ok)
	}
}

func TestProvenanceUntrustedSensitive(t *testing.T) {
	e := NewEngine()
	g := grant("email", "send", "email://*")
	g.Constraints.DestinationAllowlist = []string{"*@ourco.com"}
	d := e.Evaluate(Input{
		Tool: "email", Operation: "send", Resource: "email://alice@ourco.com",
		Arguments:  map[string]string{"to": "alice@ourco.com", "body": "ssn"},
		Grants:     []capability.Grant{g},
		Provenance: injection.Provenance{Source: injection.Web, Origin: "http://evil.example"},
		Sensitive:  true,
	})
	if d.Action != Deny || d.Control != ControlProvenance {
		t.Fatalf("web+sensitive egress should deny: %+v", d)
	}
}

func TestAblationDisablesResourceScope(t *testing.T) {
	e := NewEngine()
	e.Controls = AllOn().WithDisabled(string(ControlResourceScope), string(ControlElevation))
	g := grant("db", "delete", "db://customers/123/*")
	d := e.Evaluate(Input{Tool: "db", Operation: "delete", Resource: "db://customers/124/x", Grants: []capability.Grant{g}})
	if d.Action != Allow && d.Action != RequireElevation {
		// elevation disabled, resource scope disabled → allow
		t.Fatalf("ablated resource scope should not deny: %+v", d)
	}
	if d.Action != Allow {
		t.Fatalf("want allow after ablation, got %+v", d)
	}
}
