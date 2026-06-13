package audit

import "testing"

func TestAppendAndVerify(t *testing.T) {
	l := NewLog()
	l.Append(Event{Kind: "decision", Decision: "allow", Reason: "ok", TaskID: "t1"})
	l.Append(Event{Kind: "mint", GrantID: "g1", TaskID: "t1"})
	l.Append(Event{Kind: "exec", Tool: "db", Operation: "read", Resource: "db://x"})
	if err := l.Verify(); err != nil {
		t.Fatal(err)
	}
	if l.Len() != 3 {
		t.Fatalf("len %d", l.Len())
	}
}

func TestTamperDetectedAndNamesBrokenLink(t *testing.T) {
	l := NewLog()
	l.Append(Event{Kind: "decision", Reason: "first"})
	l.Append(Event{Kind: "decision", Reason: "second"})
	l.Append(Event{Kind: "decision", Reason: "third"})
	if err := l.Tamper(2, "I was never here"); err != nil {
		t.Fatal(err)
	}
	err := l.Verify()
	if err == nil {
		t.Fatal("tamper must break the chain")
	}
	bl, ok := err.(BrokenLink)
	if !ok {
		t.Fatalf("want BrokenLink, got %T %v", err, err)
	}
	if bl.Seq != 2 {
		t.Fatalf("broken link should be seq 2, got %d", bl.Seq)
	}
}

func TestGenesisPrevHash(t *testing.T) {
	l := NewLog()
	e := l.Append(Event{Kind: "decision"})
	if e.PrevHash != GenesisHash {
		t.Fatalf("first prev=%s", e.PrevHash)
	}
}
