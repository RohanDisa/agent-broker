package capability

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

const DefaultTTL = 5 * time.Second

// Clock is injectable so expiry tests do not sleep.
type Clock func() time.Time

func RealClock() time.Time { return time.Now() }

// Minter issues per-call, single-use, Ed25519-signed credentials. A local
// signing key stands in for a KMS; the minting pattern is the same.
type Minter struct {
	Private ed25519.PrivateKey
	Public  ed25519.PublicKey
	TTL     time.Duration
	Now     Clock
}

func NewMinter(ttl time.Duration) (*Minter, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	return &Minter{Private: priv, Public: pub, TTL: ttl, Now: RealClock}, nil
}

func MinterFromKey(priv ed25519.PrivateKey, ttl time.Duration) *Minter {
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	return &Minter{
		Private: priv,
		Public:  priv.Public().(ed25519.PublicKey),
		TTL:     ttl,
		Now:     RealClock,
	}
}

// MintRequest is the exact call the credential will authorize. Nothing else.
type MintRequest struct {
	Tool      string
	Operation string
	Resource  string
	Extra     []Caveat
}

// Credential is a macaroon-inspired token: caveats are chained into a hash
// that Ed25519 then signs. The token proves its own limits.
type Credential struct {
	Version   int       `json:"v"`
	ID        string    `json:"id"`
	GrantID   string    `json:"grant_id"`
	TaskID    string    `json:"task_id"`
	Tool      string    `json:"tool"`
	Operation string    `json:"operation"`
	Resource  string    `json:"resource"`
	Nonce     string    `json:"nonce"`
	IssuedAt  time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at"`
	Caveats   []Caveat  `json:"caveats"`
	ChainHead string    `json:"chain_head"`
	Signature string    `json:"signature"`
}

type unsignedCred struct {
	Version   int       `json:"v"`
	ID        string    `json:"id"`
	GrantID   string    `json:"grant_id"`
	TaskID    string    `json:"task_id"`
	Tool      string    `json:"tool"`
	Operation string    `json:"operation"`
	Resource  string    `json:"resource"`
	Nonce     string    `json:"nonce"`
	IssuedAt  time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at"`
	Caveats   []Caveat  `json:"caveats"`
	ChainHead string    `json:"chain_head"`
}

func (m *Minter) now() time.Time {
	if m.Now == nil {
		return time.Now()
	}
	return m.Now()
}

// Mint produces a credential valid for exactly one call. The agent may request
// a narrower resource than the grant; a broader one is rejected.
func (m *Minter) Mint(grant Grant, req MintRequest) (*Credential, error) {
	if grant.Revoked {
		return nil, ErrRevoked
	}
	if err := grant.CanAttenuateTo(req.Tool, req.Operation, req.Resource); err != nil {
		return nil, err
	}
	now := m.now().UTC()
	ttl := m.TTL
	if grant.Constraints.TTL > 0 && grant.Constraints.TTL < ttl {
		ttl = grant.Constraints.TTL
	}
	exp := now.Add(ttl)
	nonce, err := randomHex(16)
	if err != nil {
		return nil, err
	}
	id, err := randomHex(8)
	if err != nil {
		return nil, err
	}
	caveats := GrantCaveats(grant, req.Tool, req.Operation, req.Resource, nonce, exp)
	if len(req.Extra) > 0 {
		caveats, err = Attenuate(caveats, req.Extra)
		if err != nil {
			return nil, err
		}
	}
	ident := grant.ID + "/" + id
	head := ChainHeadHex(ident, caveats)
	c := &Credential{
		Version:   1,
		ID:        id,
		GrantID:   grant.ID,
		TaskID:    grant.TaskID,
		Tool:      req.Tool,
		Operation: req.Operation,
		Resource:  req.Resource,
		Nonce:     nonce,
		IssuedAt:  now,
		ExpiresAt: exp,
		Caveats:   caveats,
		ChainHead: head,
	}
	sig, err := m.sign(c)
	if err != nil {
		return nil, err
	}
	c.Signature = sig
	return c, nil
}

func (m *Minter) sign(c *Credential) (string, error) {
	msg, err := c.signBytes()
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(ed25519.Sign(m.Private, msg)), nil
}

func (c *Credential) signBytes() ([]byte, error) {
	u := unsignedCred{
		Version:   c.Version,
		ID:        c.ID,
		GrantID:   c.GrantID,
		TaskID:    c.TaskID,
		Tool:      c.Tool,
		Operation: c.Operation,
		Resource:  c.Resource,
		Nonce:     c.Nonce,
		IssuedAt:  c.IssuedAt,
		ExpiresAt: c.ExpiresAt,
		Caveats:   c.Caveats,
		ChainHead: c.ChainHead,
	}
	return json.Marshal(u)
}

// Encode is the wire form presented to tools.
func (c *Credential) Encode() (string, error) {
	b, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func DecodeCredential(s string) (*Credential, error) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	var c Credential
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	if c.ID == "" || c.Nonce == "" || c.Signature == "" {
		return nil, ErrMalformed
	}
	return &c, nil
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// TamperResource is a test/harness helper: rewrite the resource (and matching
// caveat) without re-signing. Verification must fail.
func (c *Credential) TamperResource(resource string) *Credential {
	dup := *c
	dup.Caveats = append([]Caveat{}, c.Caveats...)
	dup.Resource = resource
	for i := range dup.Caveats {
		if dup.Caveats[i].Type == CaveatResource {
			dup.Caveats[i].Value = resource
		}
	}
	return &dup
}
