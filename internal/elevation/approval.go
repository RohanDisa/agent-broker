package elevation

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync"
	"time"
)

var (
	ErrNotFound     = errors.New("elevation request not found")
	ErrNotApproved  = errors.New("elevation not approved")
	ErrAlreadyUsed  = errors.New("elevation approval already consumed")
	ErrDenied       = errors.New("elevation denied")
	ErrTaskMismatch = errors.New("elevation task mismatch")
)

type Status string

const (
	Pending  Status = "pending"
	Approved Status = "approved"
	Denied   Status = "denied"
	Consumed Status = "consumed"
)

// Request is a just-in-time approval for exactly one call. Reuse is rejected.
type Request struct {
	ID         string    `json:"id"`
	TaskID     string    `json:"task_id"`
	Tool       string    `json:"tool"`
	Operation  string    `json:"operation"`
	Resource   string    `json:"resource"`
	CallKey    string    `json:"call_key"`
	Reason     string    `json:"reason"`
	Status     Status    `json:"status"`
	CreatedAt  time.Time `json:"created_at"`
	ResolvedAt time.Time `json:"resolved_at,omitempty"`
}

// Service is the human-approval queue. Tests inject an auto-approver.
type Service struct {
	mu   sync.Mutex
	reqs map[string]*Request
}

func New() *Service {
	return &Service{reqs: make(map[string]*Request)}
}

func callKey(tool, op, resource string) string {
	return tool + "|" + op + "|" + resource
}

func (s *Service) Enqueue(taskID, tool, op, resource, reason string) *Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	id := newID()
	r := &Request{
		ID:        id,
		TaskID:    taskID,
		Tool:      tool,
		Operation: op,
		Resource:  resource,
		CallKey:   callKey(tool, op, resource),
		Reason:    reason,
		Status:    Pending,
		CreatedAt: time.Now().UTC(),
	}
	s.reqs[id] = r
	return r
}

func (s *Service) Approve(id string) (*Request, error) {
	return s.resolve(id, Approved)
}

func (s *Service) Deny(id string) (*Request, error) {
	return s.resolve(id, Denied)
}

func (s *Service) resolve(id string, st Status) (*Request, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.reqs[id]
	if !ok {
		return nil, ErrNotFound
	}
	if r.Status != Pending {
		return nil, ErrAlreadyUsed
	}
	r.Status = st
	r.ResolvedAt = time.Now().UTC()
	dup := *r
	return &dup, nil
}

// Consume marks a matching approved request used. A second charge cannot
// reuse the same approval.
func (s *Service) Consume(id, taskID, tool, op, resource string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.reqs[id]
	if !ok {
		return ErrNotFound
	}
	if r.TaskID != taskID {
		return ErrTaskMismatch
	}
	if r.Status == Denied {
		return ErrDenied
	}
	if r.Status == Consumed {
		return ErrAlreadyUsed
	}
	if r.Status != Approved {
		return ErrNotApproved
	}
	if r.CallKey != callKey(tool, op, resource) {
		return ErrNotApproved
	}
	r.Status = Consumed
	return nil
}

func (s *Service) Get(id string) (*Request, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.reqs[id]
	if !ok {
		return nil, ErrNotFound
	}
	dup := *r
	return &dup, nil
}

func (s *Service) Pending() []Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Request
	for _, r := range s.reqs {
		if r.Status == Pending {
			out = append(out, *r)
		}
	}
	return out
}

func newID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
