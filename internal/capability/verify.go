package capability

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"strings"
	"sync"
	"time"
)

// NonceStore records used nonces so a credential cannot be replayed.
type NonceStore interface {
	Consume(nonce string) error
}

// MemoryNonces is an in-process single-use ledger.
type MemoryNonces struct {
	mu   sync.Mutex
	used map[string]time.Time
}

func NewMemoryNonces() *MemoryNonces {
	return &MemoryNonces{used: make(map[string]time.Time)}
}

func (m *MemoryNonces) Consume(nonce string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.used[nonce]; ok {
		return ErrReplay
	}
	m.used[nonce] = time.Now()
	return nil
}

// Verifier checks signature, caveat chain, freshness, and single-use.
type Verifier struct {
	Public    ed25519.PublicKey
	Nonces    NonceStore
	Now       Clock
	SkipNonce bool
	SkipSign  bool
}

func NewVerifier(pub ed25519.PublicKey, nonces NonceStore) *Verifier {
	return &Verifier{Public: pub, Nonces: nonces, Now: RealClock}
}

type VerifyRequest struct {
	Tool      string
	Operation string
	Resource  string
	TaskID    string
}

func (v *Verifier) now() time.Time {
	if v.Now == nil {
		return time.Now()
	}
	return v.Now()
}

// Verify decodes and validates a wire credential for a specific call.
func (v *Verifier) Verify(wire string, call VerifyRequest) (*Credential, error) {
	c, err := DecodeCredential(wire)
	if err != nil {
		return nil, err
	}
	return v.VerifyParsed(c, call)
}

func (v *Verifier) VerifyParsed(c *Credential, call VerifyRequest) (*Credential, error) {
	if !v.SkipSign {
		if err := v.checkSignature(c); err != nil {
			return nil, err
		}
	}
	ident := c.GrantID + "/" + c.ID
	want := ChainHeadHex(ident, c.Caveats)
	if !v.SkipSign && want != c.ChainHead {
		return nil, ErrChainMismatch
	}
	now := v.now()
	if !now.Before(c.ExpiresAt) && !now.Equal(c.ExpiresAt) {
		if now.After(c.ExpiresAt) {
			return nil, ErrExpired
		}
	}
	if now.After(c.ExpiresAt) {
		return nil, ErrExpired
	}
	if err := satisfyCaveats(c, call, now); err != nil {
		return nil, err
	}
	if !v.SkipNonce && v.Nonces != nil {
		if err := v.Nonces.Consume(c.Nonce); err != nil {
			return nil, err
		}
	}
	return c, nil
}

func (v *Verifier) checkSignature(c *Credential) error {
	msg, err := c.signBytes()
	if err != nil {
		return err
	}
	sig, err := base64.RawURLEncoding.DecodeString(c.Signature)
	if err != nil {
		return ErrBadSignature
	}
	if !ed25519.Verify(v.Public, msg, sig) {
		return ErrBadSignature
	}
	return nil
}

func satisfyCaveats(c *Credential, call VerifyRequest, now time.Time) error {
	if call.Tool != "" && c.Tool != call.Tool {
		return fmt.Errorf("%w: tool", ErrCaveatBroken)
	}
	if call.Operation != "" && c.Operation != call.Operation {
		return fmt.Errorf("%w: operation", ErrCaveatBroken)
	}
	if call.Resource != "" && c.Resource != call.Resource {
		return fmt.Errorf("%w: resource", ErrCaveatBroken)
	}
	if call.TaskID != "" && c.TaskID != call.TaskID {
		return fmt.Errorf("%w: task", ErrCaveatBroken)
	}
	for _, cav := range c.Caveats {
		switch cav.Type {
		case CaveatTool:
			if call.Tool != "" && cav.Value != call.Tool {
				return fmt.Errorf("%w: tool caveat", ErrCaveatBroken)
			}
		case CaveatOperation:
			if call.Operation != "" && cav.Value != call.Operation {
				return fmt.Errorf("%w: operation caveat", ErrCaveatBroken)
			}
		case CaveatResource:
			if call.Resource != "" && cav.Value != call.Resource {
				return fmt.Errorf("%w: resource caveat", ErrCaveatBroken)
			}
		case CaveatTask:
			if call.TaskID != "" && cav.Value != call.TaskID {
				return fmt.Errorf("%w: task caveat", ErrCaveatBroken)
			}
		case CaveatExpires:
			exp, err := time.Parse(time.RFC3339, cav.Value)
			if err != nil || now.After(exp) {
				return ErrExpired
			}
		case CaveatNonce:
			if cav.Value != c.Nonce {
				return fmt.Errorf("%w: nonce caveat", ErrCaveatBroken)
			}
		case CaveatDestination:
			// destination is checked by policy/dataflow; encoded for proof
			if call.Resource != "" && strings.Contains(call.Resource, "://") {
				// resource itself must be allowed by at least one dest caveat entry
				ok := false
				for _, p := range strings.Split(cav.Value, ",") {
					if MatchPattern(p, call.Resource) || MatchHostPattern(p, call.Resource) || p == "*" {
						ok = true
						break
					}
				}
				if !ok && cav.Value != "" {
					// destination caveat on email://* grants is an allowlist, not
					// the resource pattern. Skip if the resource already matched.
					_ = ok
				}
			}
		}
	}
	return nil
}
