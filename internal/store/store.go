package store

import (
	"sync"
	"time"

	"capability-broker/internal/capability"
)

type Task struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
}

type CallRecord struct {
	TaskID    string
	GrantID   string
	Tool      string
	Operation string
	Resource  string
	Records   int
	At        time.Time
}

// Store is the persistence surface. Tests use Memory; the broker process
// can wrap the same API with SQLite for the audit log.
type Store interface {
	CreateTask(t Task) error
	GetTask(id string) (Task, bool)
	PutGrant(g capability.Grant) error
	GrantsFor(taskID string) []capability.Grant
	GetGrant(id string) (capability.Grant, bool)
	MarkRevoked(grantID string) error
	RecordCall(c CallRecord) error
	History(taskID string) []CallRecord
}

type Memory struct {
	mu     sync.Mutex
	tasks  map[string]Task
	grants map[string]capability.Grant
	calls  []CallRecord
}

func NewMemory() *Memory {
	return &Memory{
		tasks:  make(map[string]Task),
		grants: make(map[string]capability.Grant),
	}
}

func (m *Memory) CreateTask(t Task) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tasks[t.ID] = t
	return nil
}

func (m *Memory) GetTask(id string) (Task, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.tasks[id]
	return t, ok
}

func (m *Memory) PutGrant(g capability.Grant) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.grants[g.ID] = g
	return nil
}

func (m *Memory) GrantsFor(taskID string) []capability.Grant {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []capability.Grant
	for _, g := range m.grants {
		if g.TaskID == taskID {
			out = append(out, g)
		}
	}
	return out
}

func (m *Memory) GetGrant(id string) (capability.Grant, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	g, ok := m.grants[id]
	return g, ok
}

func (m *Memory) MarkRevoked(grantID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	g, ok := m.grants[grantID]
	if !ok {
		return capability.ErrNoGrant
	}
	g.Revoked = true
	m.grants[grantID] = g
	return nil
}

func (m *Memory) RecordCall(c CallRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls = append(m.calls, c)
	return nil
}

func (m *Memory) History(taskID string) []CallRecord {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []CallRecord
	for _, c := range m.calls {
		if c.TaskID == taskID {
			out = append(out, c)
		}
	}
	return out
}

func CountForGrant(hist []CallRecord, grantID string) int {
	n := 0
	for _, c := range hist {
		if c.GrantID == grantID {
			n++
		}
	}
	return n
}

func RecordsForGrant(hist []CallRecord, grantID string) int {
	n := 0
	for _, c := range hist {
		if c.GrantID == grantID {
			n += c.Records
		}
	}
	return n
}

func WindowCount(hist []CallRecord, grantID string, window time.Duration, now time.Time) int {
	n := 0
	cut := now.Add(-window)
	for _, c := range hist {
		if c.GrantID == grantID && (window <= 0 || !c.At.Before(cut)) {
			n++
		}
	}
	return n
}
