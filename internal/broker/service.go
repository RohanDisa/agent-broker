package broker

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"capability-broker/internal/audit"
	"capability-broker/internal/capability"
	"capability-broker/internal/elevation"
	"capability-broker/internal/injection"
	"capability-broker/internal/policy"
	"capability-broker/internal/revocation"
	"capability-broker/internal/store"
	"capability-broker/internal/tools"
)

var (
	ErrUnknownTask = errors.New("unknown task")
	ErrNeedElev    = errors.New("call requires elevation")
)

type Config struct {
	TTL      time.Duration
	Controls policy.Controls
	KeyPath  string
	Now      capability.Clock
}

type Service struct {
	Store    store.Store
	Minter   *capability.Minter
	Verifier *capability.Verifier
	Policy   *policy.Engine
	Tools    *tools.Registry
	Elev     *elevation.Service
	Revoke   *revocation.Ledger
	Audit    *audit.Log
	Guard    injection.Guard
	Controls policy.Controls
	Now      capability.Clock

	mu      sync.Mutex
	lat     []time.Duration
	pol     []time.Duration
	persist func(audit.Entry)
}

func New(cfg Config) (*Service, error) {
	if cfg.TTL <= 0 {
		cfg.TTL = capability.DefaultTTL
	}
	if cfg.Controls == (policy.Controls{}) {
		cfg.Controls = policy.AllOn()
	}
	if cfg.Now == nil {
		cfg.Now = capability.RealClock
	}
	var minter *capability.Minter
	if cfg.KeyPath != "" {
		if priv, err := loadOrCreateKey(cfg.KeyPath); err == nil {
			minter = capability.MinterFromKey(priv, cfg.TTL)
		}
	}
	if minter == nil {
		var err error
		minter, err = capability.NewMinter(cfg.TTL)
		if err != nil {
			return nil, err
		}
	}
	minter.Now = cfg.Now
	nonces := capability.NewMemoryNonces()
	v := capability.NewVerifier(minter.Public, nonces)
	v.Now = cfg.Now
	eng := policy.NewEngine()
	eng.Controls = cfg.Controls
	return &Service{
		Store:    store.NewMemory(),
		Minter:   minter,
		Verifier: v,
		Policy:   eng,
		Tools:    tools.NewRegistry(),
		Elev:     elevation.New(),
		Revoke:   revocation.New(),
		Audit:    audit.NewLog(),
		Guard:    injection.RulesGuard{},
		Controls: cfg.Controls,
		Now:      cfg.Now,
	}, nil
}

func (s *Service) applyControls() {
	s.Policy.Controls = s.Controls
	s.Verifier.SkipNonce = !s.Controls.SingleUse
	s.Verifier.SkipSign = !s.Controls.Signature
}

type CreateTaskReq struct {
	Name   string             `json:"name"`
	Grants []capability.Grant `json:"grants"`
}

type CreateTaskResp struct {
	TaskID string             `json:"task_id"`
	Grants []capability.Grant `json:"grants"`
}

func (s *Service) CreateTask(req CreateTaskReq) (CreateTaskResp, error) {
	id := "task-" + shortID()
	t := store.Task{ID: id, Name: req.Name, CreatedAt: s.now()}
	if err := s.Store.CreateTask(t); err != nil {
		return CreateTaskResp{}, err
	}
	var out []capability.Grant
	for i, g := range req.Grants {
		if g.ID == "" {
			g.ID = fmt.Sprintf("%s-g%d", id, i+1)
		}
		g.TaskID = id
		if g.IssuedAt.IsZero() {
			g.IssuedAt = s.now()
		}
		if err := s.Store.PutGrant(g); err != nil {
			return CreateTaskResp{}, err
		}
		out = append(out, g)
		s.log(audit.Event{Kind: "grant", TaskID: id, GrantID: g.ID, Tool: g.Tool, Operation: g.Operation, Resource: g.ResourcePattern, Reason: "issued"})
	}
	s.log(audit.Event{Kind: "task", TaskID: id, Reason: req.Name})
	return CreateTaskResp{TaskID: id, Grants: out}, nil
}

type CallReq struct {
	TaskID      string               `json:"task_id"`
	Tool        string               `json:"tool"`
	Operation   string               `json:"operation"`
	Resource    string               `json:"resource"`
	Arguments   map[string]string    `json:"arguments"`
	Provenance  injection.Provenance `json:"provenance"`
	Credential  string               `json:"credential,omitempty"`
	ElevationID string               `json:"elevation_id,omitempty"`
	Sensitive   bool                 `json:"sensitive"`
}

type CallResp struct {
	Decision    policy.Decision `json:"decision"`
	Credential  string          `json:"credential,omitempty"`
	Result      *tools.Result   `json:"result,omitempty"`
	ElevationID string          `json:"elevation_id,omitempty"`
	Latency     time.Duration   `json:"latency"`
}

func (s *Service) Call(req CallReq) (CallResp, error) {
	start := time.Now()
	s.applyControls()
	defer func() {
		s.mu.Lock()
		s.lat = append(s.lat, time.Since(start))
		s.mu.Unlock()
	}()

	if req.Credential != "" {
		return s.callWithCredential(req, start)
	}

	if _, ok := s.Store.GetTask(req.TaskID); !ok {
		d := policy.Denied(policy.ControlLeastPrivilege, "unknown task")
		s.log(audit.Event{Kind: "decision", TaskID: req.TaskID, Decision: string(d.Action), Control: string(d.Control), Reason: d.Reason, Tool: req.Tool, Operation: req.Operation, Resource: req.Resource})
		return CallResp{Decision: d, Latency: time.Since(start)}, nil
	}

	grants := s.Store.GrantsFor(req.TaskID)
	for i := range grants {
		if s.Controls.Revocation {
			if s.Revoke.Revoked(grants[i].ID) {
				grants[i].Revoked = true
			}
		} else {
			// Ablation: the ledger may have a revoke, but this control is off.
			grants[i].Revoked = false
		}
	}

	prov := req.Provenance
	if prov.Source == "" {
		prov.Source = injection.User
	}
	sensitive := req.Sensitive || injection.LooksSensitive(argBody(req.Arguments))
	dest := injection.DestinationOf(req.Tool, req.Resource, req.Arguments)

	hist := s.Store.History(req.TaskID)
	var matchID string
	for _, g := range grants {
		if g.MatchesToolOp(req.Tool, req.Operation) && (!s.Controls.ResourceScope || capability.MatchPattern(g.ResourcePattern, req.Resource)) && !g.Revoked {
			matchID = g.ID
			break
		}
	}
	in := policy.Input{
		Tool:        req.Tool,
		Operation:   req.Operation,
		Resource:    req.Resource,
		Arguments:   req.Arguments,
		Grants:      grants,
		Provenance:  prov,
		Sensitive:   sensitive,
		Destination: dest,
		CallCount:   store.CountForGrant(hist, matchID),
		RecordCount: store.RecordsForGrant(hist, matchID),
		Now:         s.now(),
	}
	if matchID != "" {
		if g, ok := s.Store.GetGrant(matchID); ok && g.Constraints.RateWindow > 0 {
			in.WindowCount = store.WindowCount(hist, matchID, g.Constraints.RateWindow, s.now())
		}
	}

	polStart := time.Now()
	d := s.Policy.Evaluate(in)
	s.recordPolicy(time.Since(polStart))

	if s.Controls.Guard && d.Action != policy.Deny {
		if g := s.Guard.Inspect(req.Tool, req.Operation, req.Arguments, prov); g.Flagged {
			if policy.IsEgressOp(req.Tool, req.Operation) || req.Tool == "payments" {
				d = policy.Denied(policy.ControlGuard, g.Reason)
			}
		}
	}

	s.log(audit.Event{
		Kind: "decision", TaskID: req.TaskID, Decision: string(d.Action), Control: string(d.Control),
		Reason: d.Reason, Tool: req.Tool, Operation: req.Operation, Resource: req.Resource, GrantID: d.GrantID,
	})

	if d.Action == policy.Deny {
		return CallResp{Decision: d, Latency: time.Since(start)}, nil
	}

	if d.Action == policy.RequireElevation {
		if req.ElevationID == "" {
			r := s.Elev.Enqueue(req.TaskID, req.Tool, req.Operation, req.Resource, d.Reason)
			s.log(audit.Event{Kind: "elevate", TaskID: req.TaskID, Decision: "pending", Reason: d.Reason, Tool: req.Tool, Operation: req.Operation, Resource: req.Resource, GrantID: d.GrantID, Detail: map[string]string{"elevation_id": r.ID}})
			return CallResp{Decision: d, ElevationID: r.ID, Latency: time.Since(start)}, nil
		}
		if err := s.Elev.Consume(req.ElevationID, req.TaskID, req.Tool, req.Operation, req.Resource); err != nil {
			denied := policy.Denied(policy.ControlElevation, "elevation: "+err.Error())
			s.log(audit.Event{Kind: "decision", TaskID: req.TaskID, Decision: "deny", Control: string(denied.Control), Reason: denied.Reason, Tool: req.Tool, Operation: req.Operation, Resource: req.Resource})
			return CallResp{Decision: denied, ElevationID: req.ElevationID, Latency: time.Since(start)}, nil
		}
		s.log(audit.Event{Kind: "elevate", TaskID: req.TaskID, Decision: "approved", Reason: "consumed one-time approval", Tool: req.Tool, Operation: req.Operation, Resource: req.Resource, GrantID: d.GrantID})
	}

	g, ok := s.Store.GetGrant(d.GrantID)
	if !ok && d.GrantID != "ablated" {
		denied := policy.Denied(policy.ControlLeastPrivilege, "grant disappeared")
		return CallResp{Decision: denied, Latency: time.Since(start)}, nil
	}
	if d.GrantID == "ablated" {
		g = capability.Grant{ID: "ablated", TaskID: req.TaskID, Tool: req.Tool, Operation: req.Operation, ResourcePattern: req.Resource}
	}
	g = s.grantForMint(g, req)
	if s.Controls.Revocation && (g.Revoked || s.Revoke.Revoked(g.ID)) {
		denied := policy.Denied(policy.ControlRevocation, "grant revoked; next call denied")
		s.log(audit.Event{Kind: "decision", TaskID: req.TaskID, Decision: "deny", Control: string(denied.Control), Reason: denied.Reason, GrantID: g.ID})
		return CallResp{Decision: denied, Latency: time.Since(start)}, nil
	}

	cred, err := s.Minter.Mint(g, capability.MintRequest{Tool: req.Tool, Operation: req.Operation, Resource: req.Resource})
	if err != nil {
		denied := mintDeny(err)
		s.log(audit.Event{Kind: "decision", TaskID: req.TaskID, Decision: "deny", Control: string(denied.Control), Reason: denied.Reason})
		return CallResp{Decision: denied, Latency: time.Since(start)}, nil
	}
	wire, err := cred.Encode()
	if err != nil {
		return CallResp{}, err
	}
	s.log(audit.Event{Kind: "mint", TaskID: req.TaskID, GrantID: g.ID, Tool: req.Tool, Operation: req.Operation, Resource: req.Resource, Reason: "single-use credential minted", Detail: map[string]string{"cred_id": cred.ID, "nonce": cred.Nonce, "expires": cred.ExpiresAt.Format(time.RFC3339)}})

	verified, err := s.Verifier.Verify(wire, capability.VerifyRequest{Tool: req.Tool, Operation: req.Operation, Resource: req.Resource, TaskID: g.TaskID})
	if err != nil {
		denied := policy.Denied(policy.ControlSignature, "tool-side verify: "+err.Error())
		s.log(audit.Event{Kind: "decision", TaskID: req.TaskID, Decision: "deny", Control: string(denied.Control), Reason: denied.Reason})
		return CallResp{Decision: denied, Credential: wire, Latency: time.Since(start)}, nil
	}

	res := s.Tools.Exec(tools.Request{
		Tool: req.Tool, Operation: req.Operation, Resource: req.Resource,
		Arguments: req.Arguments, Provenance: prov, Credential: verified,
	})
	s.log(audit.Event{Kind: "exec", TaskID: req.TaskID, GrantID: g.ID, Tool: req.Tool, Operation: req.Operation, Resource: req.Resource, Reason: res.Output, Detail: map[string]any{"ok": res.OK, "error": res.Error}})
	_ = s.Store.RecordCall(store.CallRecord{
		TaskID: req.TaskID, GrantID: g.ID, Tool: req.Tool, Operation: req.Operation,
		Resource: req.Resource, Records: res.Records, At: s.now(),
	})
	allow := policy.Allowed(g.ID, d.Reason)
	return CallResp{Decision: allow, Credential: wire, Result: &res, Latency: time.Since(start)}, nil
}

func (s *Service) callWithCredential(req CallReq, start time.Time) (CallResp, error) {
	c, err := capability.DecodeCredential(req.Credential)
	if err != nil {
		d := policy.Denied(policy.ControlSignature, err.Error())
		s.log(audit.Event{Kind: "decision", TaskID: req.TaskID, Decision: "deny", Control: string(d.Control), Reason: d.Reason})
		return CallResp{Decision: d, Latency: time.Since(start)}, nil
	}
	if s.Controls.Revocation && s.Revoke.Revoked(c.GrantID) {
		d := policy.Denied(policy.ControlRevocation, "grant revoked; minted credential rejected on next call")
		s.log(audit.Event{Kind: "decision", TaskID: req.TaskID, Decision: "deny", Control: string(d.Control), Reason: d.Reason, GrantID: c.GrantID})
		return CallResp{Decision: d, Credential: req.Credential, Latency: time.Since(start)}, nil
	}
	verified, err := s.Verifier.Verify(req.Credential, capability.VerifyRequest{
		Tool: req.Tool, Operation: req.Operation, Resource: req.Resource, TaskID: req.TaskID,
	})
	if err != nil {
		ctrl := policy.ControlSignature
		if errors.Is(err, capability.ErrReplay) {
			ctrl = policy.ControlSingleUse
		}
		d := policy.Denied(ctrl, err.Error())
		s.log(audit.Event{Kind: "decision", TaskID: req.TaskID, Decision: "deny", Control: string(d.Control), Reason: d.Reason})
		return CallResp{Decision: d, Credential: req.Credential, Latency: time.Since(start)}, nil
	}
	prov := req.Provenance
	res := s.Tools.Exec(tools.Request{
		Tool: req.Tool, Operation: req.Operation, Resource: req.Resource,
		Arguments: req.Arguments, Provenance: prov, Credential: verified,
	})
	s.log(audit.Event{Kind: "exec", TaskID: req.TaskID, GrantID: verified.GrantID, Tool: req.Tool, Operation: req.Operation, Resource: req.Resource, Reason: "presented credential"})
	return CallResp{Decision: policy.Allowed(verified.GrantID, "credential accepted"), Credential: req.Credential, Result: &res, Latency: time.Since(start)}, nil
}

// MintOnly issues a credential without executing. Used by the red-team
// caveat-stripping scenario; not exposed as a general agent API.
func (s *Service) MintOnly(taskID, tool, op, resource string) (*capability.Credential, error) {
	s.applyControls()
	grants := s.Store.GrantsFor(taskID)
	for _, g := range grants {
		if s.Revoke.Revoked(g.ID) {
			continue
		}
		if err := g.CanAttenuateTo(tool, op, resource); err == nil {
			return s.Minter.Mint(g, capability.MintRequest{Tool: tool, Operation: op, Resource: resource})
		}
	}
	return nil, capability.ErrNoGrant
}

func (s *Service) RevokeGrant(grantID string) error {
	if err := s.Store.MarkRevoked(grantID); err != nil {
		return err
	}
	s.Revoke.Revoke(grantID)
	s.log(audit.Event{Kind: "revoke", GrantID: grantID, Reason: "grant revoked; takes effect on next call"})
	return nil
}

func (s *Service) Approve(id string) (*elevation.Request, error) {
	r, err := s.Elev.Approve(id)
	if err != nil {
		return nil, err
	}
	s.log(audit.Event{Kind: "elevate", TaskID: r.TaskID, Decision: "approved", Reason: "human approved", Tool: r.Tool, Operation: r.Operation, Resource: r.Resource, Detail: map[string]string{"elevation_id": id}})
	return r, nil
}

func (s *Service) DenyElevation(id string) (*elevation.Request, error) {
	r, err := s.Elev.Deny(id)
	if err != nil {
		return nil, err
	}
	s.log(audit.Event{Kind: "elevate", TaskID: r.TaskID, Decision: "denied", Reason: "human denied", Tool: r.Tool, Operation: r.Operation, Resource: r.Resource})
	return r, nil
}

func (s *Service) AuditEntries() []audit.Entry { return s.Audit.Entries() }

func (s *Service) VerifyAudit() error { return s.Audit.Verify() }

func (s *Service) LatencySnapshot() (p50, p99 time.Duration, n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return percentile(s.lat)
}

func (s *Service) PolicyLatencySnapshot() (p50, p99 time.Duration, n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return percentile(s.pol)
}

func (s *Service) recordPolicy(d time.Duration) {
	s.mu.Lock()
	s.pol = append(s.pol, d)
	s.mu.Unlock()
}

func percentile(lat []time.Duration) (p50, p99 time.Duration, n int) {
	n = len(lat)
	if n == 0 {
		return 0, 0, 0
	}
	cp := append([]time.Duration{}, lat...)
	for i := 1; i < len(cp); i++ {
		j := i
		for j > 0 && cp[j] < cp[j-1] {
			cp[j], cp[j-1] = cp[j-1], cp[j]
			j--
		}
	}
	p50 = cp[(n*50)/100]
	idx := (n * 99) / 100
	if idx >= n {
		idx = n - 1
	}
	p99 = cp[idx]
	return p50, p99, n
}

func (s *Service) log(ev audit.Event) {
	e := s.Audit.Append(ev)
	if s.persist != nil {
		s.persist(e)
	}
}

func (s *Service) SetPersist(fn func(audit.Entry)) { s.persist = fn }

func (s *Service) now() time.Time {
	if s.Now == nil {
		return time.Now()
	}
	return s.Now()
}

// grantForMint copies a grant and relaxes checks that the current control
// flags have turned off, so ablation actually removes the layer.
func (s *Service) grantForMint(g capability.Grant, req CallReq) capability.Grant {
	if !s.Controls.Revocation {
		g.Revoked = false
	}
	if !s.Controls.ResourceScope {
		g.ResourcePattern = req.Resource
	}
	if !s.Controls.LeastPrivilege {
		g.Tool = req.Tool
		g.Operation = req.Operation
		if g.ResourcePattern == "" {
			g.ResourcePattern = req.Resource
		}
	}
	return g
}

func mintDeny(err error) policy.Decision {
	switch {
	case errors.Is(err, capability.ErrRevoked):
		return policy.Denied(policy.ControlRevocation, err.Error())
	case errors.Is(err, capability.ErrWidening):
		return policy.Denied(policy.ControlResourceScope, err.Error())
	default:
		return policy.Denied(policy.ControlSignature, err.Error())
	}
}

func argBody(args map[string]string) string {
	if args == nil {
		return ""
	}
	return args["body"] + " " + args["value"]
}

func shortID() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func loadOrCreateKey(path string) (ed25519.PrivateKey, error) {
	if b, err := os.ReadFile(path); err == nil {
		block, _ := pem.Decode(b)
		if block != nil && len(block.Bytes) == ed25519.PrivateKeySize {
			return ed25519.PrivateKey(block.Bytes), nil
		}
		if len(b) == ed25519.PrivateKeySize {
			return ed25519.PrivateKey(b), nil
		}
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	block := &pem.Block{Type: "ED25519 PRIVATE KEY", Bytes: priv}
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		return priv, nil
	}
	return priv, nil
}

func SplitResource(resource string) (toolHint string) {
	if i := strings.Index(resource, "://"); i > 0 {
		return resource[:i]
	}
	return ""
}
