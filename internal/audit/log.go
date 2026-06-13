package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

const GenesisHash = "genesis"

// Entry is one hash-chained audit record. PrevHash is SHA-256 of the
// previous entry's canonical bytes; Hash is SHA-256 of this entry including
// PrevHash. Editing any field after the fact breaks the chain.
type Entry struct {
	Seq       int             `json:"seq"`
	Timestamp time.Time       `json:"ts"`
	Kind      string          `json:"kind"`
	TaskID    string          `json:"task_id,omitempty"`
	Decision  string          `json:"decision,omitempty"`
	Control   string          `json:"control,omitempty"`
	Reason    string          `json:"reason,omitempty"`
	Tool      string          `json:"tool,omitempty"`
	Operation string          `json:"operation,omitempty"`
	Resource  string          `json:"resource,omitempty"`
	GrantID   string          `json:"grant_id,omitempty"`
	Detail    json.RawMessage `json:"detail,omitempty"`
	PrevHash  string          `json:"prev_hash"`
	Hash      string          `json:"hash"`
}

type Event struct {
	Kind      string
	TaskID    string
	Decision  string
	Control   string
	Reason    string
	Tool      string
	Operation string
	Resource  string
	GrantID   string
	Detail    any
}

// Log is an append-only hash chain. The in-memory implementation is used by
// tests; the broker process persists the same records in SQLite.
type Log struct {
	mu      sync.Mutex
	entries []Entry
}

func NewLog() *Log { return &Log{} }

func (l *Log) Append(ev Event) Entry {
	l.mu.Lock()
	defer l.mu.Unlock()
	prev := GenesisHash
	if n := len(l.entries); n > 0 {
		prev = l.entries[n-1].Hash
	}
	var detail json.RawMessage
	if ev.Detail != nil {
		b, _ := json.Marshal(ev.Detail)
		detail = b
	}
	e := Entry{
		Seq:       len(l.entries) + 1,
		Timestamp: time.Now().UTC(),
		Kind:      ev.Kind,
		TaskID:    ev.TaskID,
		Decision:  ev.Decision,
		Control:   ev.Control,
		Reason:    ev.Reason,
		Tool:      ev.Tool,
		Operation: ev.Operation,
		Resource:  ev.Resource,
		GrantID:   ev.GrantID,
		Detail:    detail,
		PrevHash:  prev,
	}
	e.Hash = HashEntry(e)
	l.entries = append(l.entries, e)
	return e
}

func (l *Log) Entries() []Entry {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]Entry, len(l.entries))
	copy(out, l.entries)
	return out
}

func (l *Log) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.entries)
}

// Tamper is a test helper: mutate one field after hashing (simulates an
// after-the-fact edit).
func (l *Log) Tamper(seq int, reason string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	for i := range l.entries {
		if l.entries[i].Seq == seq {
			l.entries[i].Reason = reason
			return nil
		}
	}
	return fmt.Errorf("no entry %d", seq)
}

type canonical struct {
	Seq       int             `json:"seq"`
	Timestamp time.Time       `json:"ts"`
	Kind      string          `json:"kind"`
	TaskID    string          `json:"task_id,omitempty"`
	Decision  string          `json:"decision,omitempty"`
	Control   string          `json:"control,omitempty"`
	Reason    string          `json:"reason,omitempty"`
	Tool      string          `json:"tool,omitempty"`
	Operation string          `json:"operation,omitempty"`
	Resource  string          `json:"resource,omitempty"`
	GrantID   string          `json:"grant_id,omitempty"`
	Detail    json.RawMessage `json:"detail,omitempty"`
	PrevHash  string          `json:"prev_hash"`
}

func HashEntry(e Entry) string {
	c := canonical{
		Seq: e.Seq, Timestamp: e.Timestamp, Kind: e.Kind, TaskID: e.TaskID,
		Decision: e.Decision, Control: e.Control, Reason: e.Reason,
		Tool: e.Tool, Operation: e.Operation, Resource: e.Resource,
		GrantID: e.GrantID, Detail: e.Detail, PrevHash: e.PrevHash,
	}
	b, _ := json.Marshal(c)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
