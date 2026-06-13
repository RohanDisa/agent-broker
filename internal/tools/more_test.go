package tools

import (
	"testing"

	"capability-broker/internal/capability"
	"capability-broker/internal/injection"
)

func cred(tool, op, res string) *capability.Credential {
	return &capability.Credential{Tool: tool, Operation: op, Resource: res}
}

func TestDBReadWriteDelete(t *testing.T) {
	r := NewRegistry()
	got := r.Exec(Request{
		Tool: "db", Operation: "read", Resource: "db://customers/123/profile",
		Credential: cred("db", "read", "db://customers/123/profile"),
	})
	if !got.OK || !got.Sensitive {
		t.Fatalf("%+v", got)
	}
	w := r.Exec(Request{
		Tool: "db", Operation: "write", Resource: "db://customers/123/notes",
		Arguments:  map[string]string{"body": "hello"},
		Provenance: injection.Provenance{Source: injection.User},
		Credential: cred("db", "write", "db://customers/123/notes"),
	})
	if !w.OK {
		t.Fatal(w.Error)
	}
	d := r.Exec(Request{
		Tool: "db", Operation: "delete", Resource: "db://customers/123/notes",
		Credential: cred("db", "delete", "db://customers/123/notes"),
	})
	if !d.OK {
		t.Fatal(d.Error)
	}
}

func TestEmailAndPayments(t *testing.T) {
	r := NewRegistry()
	e := r.Exec(Request{
		Tool: "email", Operation: "send", Resource: "email://a@ourco.com",
		Arguments:  map[string]string{"to": "a@ourco.com", "body": "hi"},
		Credential: cred("email", "send", "email://a@ourco.com"),
	})
	if !e.OK {
		t.Fatal(e.Error)
	}
	p := r.Exec(Request{
		Tool: "payments", Operation: "charge", Resource: "payments://acct/1",
		Arguments:  map[string]string{"amount": "5"},
		Credential: cred("payments", "charge", "payments://acct/1"),
	})
	if !p.OK {
		t.Fatal(p.Error)
	}
	if _, ok := r.Get("nope"); ok {
		t.Fatal("unknown")
	}
	bad := r.Exec(Request{Tool: "nope", Operation: "x", Credential: cred("nope", "x", "z")})
	if bad.Error == "" {
		t.Fatal("unknown tool")
	}
}

func TestHTTPBenignAndMismatchCred(t *testing.T) {
	r := NewRegistry()
	ok := r.Exec(Request{
		Tool: "http", Operation: "fetch", Resource: "http://docs.example/ok",
		Credential: cred("http", "fetch", "http://docs.example/ok"),
	})
	if !ok.OK {
		t.Fatal(ok.Error)
	}
	mismatch := r.Exec(Request{
		Tool: "http", Operation: "fetch", Resource: "http://x",
		Credential: cred("email", "send", "email://a"),
	})
	if mismatch.OK {
		t.Fatal("mismatch cred")
	}
	shared := r.Exec(Request{
		Tool: "files", Operation: "write_shared", Resource: "files://scratch/pub",
		Arguments:  map[string]string{"body": "ok"},
		Credential: cred("files", "write_shared", "files://scratch/pub"),
	})
	if !shared.OK {
		t.Fatal(shared.Error)
	}
}
