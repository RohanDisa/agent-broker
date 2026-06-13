package broker

import (
	"testing"
	"time"

	"capability-broker/internal/capability"
	"capability-broker/internal/injection"
	"capability-broker/internal/policy"
)

func newTestService(t *testing.T) *Service {
	t.Helper()
	s, err := New(Config{TTL: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestAllowedTaskEndToEndAudit(t *testing.T) {
	s := newTestService(t)
	ct, err := s.CreateTask(CreateTaskReq{
		Name: "read customer",
		Grants: []capability.Grant{{
			Tool: "db", Operation: "read", ResourcePattern: "db://customers/123/*",
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := s.Call(CallReq{
		TaskID: ct.TaskID, Tool: "db", Operation: "read",
		Resource:   "db://customers/123/profile",
		Provenance: injection.Provenance{Source: injection.User},
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Decision.Action != policy.Allow || resp.Result == nil || !resp.Result.OK {
		t.Fatalf("want allow+exec, got %+v %+v", resp.Decision, resp.Result)
	}
	if err := s.VerifyAudit(); err != nil {
		t.Fatal(err)
	}
	if s.Audit.Len() < 3 {
		t.Fatalf("expected grant+decision+mint+exec, got %d", s.Audit.Len())
	}
}

func TestElevationPauseApproveProceedAndNoReuse(t *testing.T) {
	s := newTestService(t)
	ct, _ := s.CreateTask(CreateTaskReq{
		Name: "pay",
		Grants: []capability.Grant{{
			Tool: "payments", Operation: "charge", ResourcePattern: "payments://acct/1",
		}},
	})
	req := CallReq{TaskID: ct.TaskID, Tool: "payments", Operation: "charge", Resource: "payments://acct/1", Arguments: map[string]string{"amount": "10"}}
	r1, _ := s.Call(req)
	if r1.Decision.Action != policy.RequireElevation || r1.ElevationID == "" {
		t.Fatalf("want elevation, got %+v", r1)
	}
	if _, err := s.Approve(r1.ElevationID); err != nil {
		t.Fatal(err)
	}
	req.ElevationID = r1.ElevationID
	r2, _ := s.Call(req)
	if r2.Decision.Action != policy.Allow {
		t.Fatalf("approved should proceed: %+v", r2.Decision)
	}
	r3, _ := s.Call(req)
	if r3.Decision.Action != policy.Deny || r3.Decision.Control != policy.ControlElevation {
		t.Fatalf("reused approval must deny: %+v", r3.Decision)
	}
}

func TestRevocationTakesEffectOnNextCall(t *testing.T) {
	s := newTestService(t)
	ct, _ := s.CreateTask(CreateTaskReq{
		Name: "rev",
		Grants: []capability.Grant{{
			Tool: "db", Operation: "read", ResourcePattern: "db://customers/123/*",
		}},
	})
	r1, _ := s.Call(CallReq{TaskID: ct.TaskID, Tool: "db", Operation: "read", Resource: "db://customers/123/profile"})
	if r1.Decision.Action != policy.Allow {
		t.Fatalf("%+v", r1.Decision)
	}
	if err := s.RevokeGrant(ct.Grants[0].ID); err != nil {
		t.Fatal(err)
	}
	r2, _ := s.Call(CallReq{TaskID: ct.TaskID, Tool: "db", Operation: "read", Resource: "db://customers/123/profile"})
	if r2.Decision.Action != policy.Deny || r2.Decision.Control != policy.ControlRevocation {
		t.Fatalf("next call after revoke must deny: %+v", r2.Decision)
	}
}

func TestReplayRejected(t *testing.T) {
	s := newTestService(t)
	ct, _ := s.CreateTask(CreateTaskReq{
		Name: "replay",
		Grants: []capability.Grant{{
			Tool: "db", Operation: "read", ResourcePattern: "db://customers/123/*",
		}},
	})
	r1, _ := s.Call(CallReq{TaskID: ct.TaskID, Tool: "db", Operation: "read", Resource: "db://customers/123/profile"})
	r2, _ := s.Call(CallReq{
		TaskID: ct.TaskID, Tool: "db", Operation: "read", Resource: "db://customers/123/profile",
		Credential: r1.Credential,
	})
	if r2.Decision.Action != policy.Deny || r2.Decision.Control != policy.ControlSingleUse {
		t.Fatalf("replay: %+v", r2.Decision)
	}
}
