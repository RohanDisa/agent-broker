package tools

import (
	"fmt"
	"strings"
	"sync"

	"capability-broker/internal/capability"
	"capability-broker/internal/injection"
)

// Request is what the broker presents to a tool after minting a credential.
// Tools independently verify the credential; they never receive standing auth.
type Request struct {
	Tool       string
	Operation  string
	Resource   string
	Arguments  map[string]string
	Provenance injection.Provenance
	Credential *capability.Credential
}

type Result struct {
	OK         bool                 `json:"ok"`
	Output     string               `json:"output"`
	Provenance injection.Provenance `json:"provenance"`
	Sensitive  bool                 `json:"sensitive"`
	Records    int                  `json:"records,omitempty"`
	Error      string               `json:"error,omitempty"`
}

type Tool interface {
	Name() string
	Exec(req Request) Result
}

// Registry holds mock tools with realistic auth semantics: no valid
// credential, no execution. Live secrets are never used.
type Registry struct {
	mu    sync.Mutex
	tools map[string]Tool
}

func NewRegistry() *Registry {
	r := &Registry{tools: make(map[string]Tool)}
	r.Register(NewEmail())
	r.Register(NewDB())
	r.Register(NewFiles())
	r.Register(NewHTTP())
	r.Register(NewPayments())
	return r
}

func (r *Registry) Register(t Tool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.tools[t.Name()] = t
}

func (r *Registry) Get(name string) (Tool, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	t, ok := r.tools[name]
	return t, ok
}

func (r *Registry) Exec(req Request) Result {
	if req.Credential == nil {
		return Result{Error: "tool refused: no credential"}
	}
	if req.Credential.Tool != req.Tool || req.Credential.Operation != req.Operation {
		return Result{Error: "tool refused: credential does not cover this call"}
	}
	t, ok := r.Get(req.Tool)
	if !ok {
		return Result{Error: fmt.Sprintf("unknown tool %s", req.Tool)}
	}
	return t.Exec(req)
}

func arg(m map[string]string, k string) string {
	if m == nil {
		return ""
	}
	return m[k]
}

func inheritOut(req Request, source injection.Source, origin, body string, sensitive bool) Result {
	p := req.Provenance.Inherit(source, origin)
	if req.Provenance.Source == "" {
		p = injection.Provenance{Source: source, Origin: origin}
	}
	return Result{OK: true, Output: body, Provenance: p, Sensitive: sensitive}
}

func joinArgs(m map[string]string) string {
	var b strings.Builder
	for k, v := range m {
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(v)
		b.WriteByte(' ')
	}
	return b.String()
}
