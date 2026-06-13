package broker

import (
	"path/filepath"
	"testing"

	"capability-broker/internal/audit"
	"capability-broker/internal/capability"
	"capability-broker/internal/policy"
)

func TestKeyPathAndPersist(t *testing.T) {
	dir := t.TempDir()
	key := filepath.Join(dir, "signing.key")
	s, err := New(Config{TTL: capability.DefaultTTL, KeyPath: key})
	if err != nil {
		t.Fatal(err)
	}
	var n int
	s.SetPersist(func(audit.Entry) { n++ })
	ct, _ := s.CreateTask(CreateTaskReq{
		Name: "k",
		Grants: []capability.Grant{{Tool: "db", Operation: "read", ResourcePattern: "db://customers/123/*"}},
	})
	_, _ = s.Call(CallReq{TaskID: ct.TaskID, Tool: "db", Operation: "read", Resource: "db://customers/123/profile"})
	if n < 2 {
		t.Fatalf("persist calls %d", n)
	}
	s2, err := New(Config{TTL: capability.DefaultTTL, KeyPath: key})
	if err != nil {
		t.Fatal(err)
	}
	if len(s2.Minter.Public) == 0 {
		t.Fatal("reloaded key")
	}
}

func TestBadPresentedCredential(t *testing.T) {
	s := newTestService(t)
	ct, _ := s.CreateTask(CreateTaskReq{
		Name: "b",
		Grants: []capability.Grant{{Tool: "db", Operation: "read", ResourcePattern: "db://customers/123/*"}},
	})
	r, _ := s.Call(CallReq{
		TaskID: ct.TaskID, Tool: "db", Operation: "read",
		Resource: "db://customers/123/profile", Credential: "%%%not-a-token",
	})
	if r.Decision.Action != policy.Deny {
		t.Fatalf("%+v", r.Decision)
	}
}

func TestRevokedPresentedCredential(t *testing.T) {
	s := newTestService(t)
	ct, _ := s.CreateTask(CreateTaskReq{
		Name: "r",
		Grants: []capability.Grant{{Tool: "db", Operation: "read", ResourcePattern: "db://customers/123/*"}},
	})
	c, err := s.MintOnly(ct.TaskID, "db", "read", "db://customers/123/profile")
	if err != nil {
		t.Fatal(err)
	}
	wire, _ := c.Encode()
	_ = s.RevokeGrant(ct.Grants[0].ID)
	r, _ := s.Call(CallReq{
		TaskID: ct.TaskID, Tool: "db", Operation: "read",
		Resource: "db://customers/123/profile", Credential: wire,
	})
	if r.Decision.Control != policy.ControlRevocation {
		t.Fatalf("%+v", r.Decision)
	}
}
