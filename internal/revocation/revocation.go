package revocation

import (
	"sync"
	"time"
)

// Ledger records grant revocations. Combined with short credential TTLs,
// a revoke bounds the damage window to the next call.
type Ledger struct {
	mu   sync.Mutex
	when map[string]time.Time
}

func New() *Ledger {
	return &Ledger{when: make(map[string]time.Time)}
}

func (l *Ledger) Revoke(grantID string) time.Time {
	l.mu.Lock()
	defer l.mu.Unlock()
	t := time.Now().UTC()
	l.when[grantID] = t
	return t
}

func (l *Ledger) Revoked(grantID string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	_, ok := l.when[grantID]
	return ok
}

func (l *Ledger) When(grantID string) (time.Time, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	t, ok := l.when[grantID]
	return t, ok
}
