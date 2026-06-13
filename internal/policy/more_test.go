package policy

import (
	"testing"
	"time"

	"capability-broker/internal/capability"
	"capability-broker/internal/injection"
)

func TestDeleteRequiresElevation(t *testing.T) {
	e := NewEngine()
	g := grant("db", "delete", "db://customers/123/*")
	d := e.Evaluate(Input{Tool: "db", Operation: "delete", Resource: "db://customers/123/profile", Grants: []capability.Grant{g}})
	if d.Action != RequireElevation {
		t.Fatalf("%+v", d)
	}
}

func TestDataflowSensitiveExternal(t *testing.T) {
	e := NewEngine()
	e.Controls.Egress = false
	e.Controls.Provenance = false
	e.Controls.Elevation = false
	g := grant("email", "send", "email://*")
	d := e.Evaluate(Input{
		Tool: "email", Operation: "send", Resource: "email://evil@x.com",
		Arguments: map[string]string{"to": "evil@x.com", "body": "ssn"},
		Grants:    []capability.Grant{g},
		Sensitive: true,
	})
	if d.Action != Deny || d.Control != ControlDataflow {
		t.Fatalf("want dataflow deny, got %+v", d)
	}
}

func TestExpiredGrantIgnored(t *testing.T) {
	e := NewEngine()
	g := grant("db", "read", "db://customers/123/*")
	g.ExpiresAt = time.Now().Add(-time.Hour)
	d := e.Evaluate(Input{Tool: "db", Operation: "read", Resource: "db://customers/123/p", Grants: []capability.Grant{g}, Now: time.Now()})
	if d.Action != Deny {
		t.Fatalf("%+v", d)
	}
}

func TestWebWriteToDBDenied(t *testing.T) {
	e := NewEngine()
	g := grant("db", "write", "db://customers/123/*")
	d := e.Evaluate(Input{
		Tool: "db", Operation: "write", Resource: "db://customers/123/notes",
		Grants:     []capability.Grant{g},
		Provenance: injection.Provenance{Source: injection.Web},
	})
	if d.Action != Deny || d.Control != ControlProvenance {
		t.Fatalf("%+v", d)
	}
}

func TestRateWindow(t *testing.T) {
	e := NewEngine()
	g := grant("db", "read", "db://customers/123/*")
	g.Constraints.RateLimit = 1
	g.Constraints.RateWindow = time.Minute
	d := e.Evaluate(Input{Tool: "db", Operation: "read", Resource: "db://customers/123/a", Grants: []capability.Grant{g}, WindowCount: 1})
	if d.Action != Deny || d.Control != ControlRateCount {
		t.Fatalf("%+v", d)
	}
}

func TestMaxRecords(t *testing.T) {
	e := NewEngine()
	g := grant("db", "read", "db://customers/123/*")
	g.Constraints.MaxRecords = 2
	d := e.Evaluate(Input{Tool: "db", Operation: "read", Resource: "db://customers/123/a", Grants: []capability.Grant{g}, RecordCount: 2})
	if d.Action != Deny || d.Control != ControlRateCount {
		t.Fatalf("%+v", d)
	}
}
