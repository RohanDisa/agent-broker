package store

import (
	"path/filepath"
	"testing"
	"time"

	"capability-broker/internal/audit"
	"capability-broker/internal/capability"
)

func TestMemoryCRUD(t *testing.T) {
	m := NewMemory()
	if err := m.CreateTask(Task{ID: "t1", Name: "n", CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if _, ok := m.GetTask("t1"); !ok {
		t.Fatal("missing task")
	}
	g := capability.Grant{ID: "g1", TaskID: "t1", Tool: "db", Operation: "read", ResourcePattern: "db://x"}
	if err := m.PutGrant(g); err != nil {
		t.Fatal(err)
	}
	if gs := m.GrantsFor("t1"); len(gs) != 1 {
		t.Fatal(gs)
	}
	if _, ok := m.GetGrant("g1"); !ok {
		t.Fatal("grant")
	}
	if err := m.MarkRevoked("g1"); err != nil {
		t.Fatal(err)
	}
	got, _ := m.GetGrant("g1")
	if !got.Revoked {
		t.Fatal("not revoked")
	}
	if err := m.MarkRevoked("nope"); err == nil {
		t.Fatal("expected missing grant")
	}
	_ = m.RecordCall(CallRecord{TaskID: "t1", GrantID: "g1", Records: 2, At: time.Now()})
	h := m.History("t1")
	if CountForGrant(h, "g1") != 1 || RecordsForGrant(h, "g1") != 2 {
		t.Fatal(h)
	}
	if WindowCount(h, "g1", time.Hour, time.Now()) != 1 {
		t.Fatal("window")
	}
}

func TestSQLiteAuditRoundTrip(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(filepath.Join(dir, "b.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.CreateTask(Task{ID: "t", Name: "n"}); err != nil {
		t.Fatal(err)
	}
	log := audit.NewLog()
	e := log.Append(audit.Event{Kind: "decision", Reason: "ok", TaskID: "t"})
	if err := s.PersistAudit(e); err != nil {
		t.Fatal(err)
	}
	got, err := s.LoadAudit()
	if err != nil || len(got) != 1 {
		t.Fatalf("%v %+v", err, got)
	}
	if err := audit.Verify(got); err != nil {
		t.Fatal(err)
	}
}
