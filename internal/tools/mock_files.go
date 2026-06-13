package tools

import (
	"sync"

	"capability-broker/internal/injection"
)

type fileRec struct {
	Body       string
	Provenance injection.Provenance
	Sensitive  bool
}

type Files struct {
	mu    sync.Mutex
	store map[string]fileRec
}

func NewFiles() *Files {
	return &Files{store: make(map[string]fileRec)}
}

func (f *Files) Name() string { return "files" }

func (f *Files) Exec(req Request) Result {
	switch req.Operation {
	case "write", "write_shared":
		body := arg(req.Arguments, "body")
		rec := fileRec{
			Body:       body,
			Provenance: req.Provenance.Inherit(injection.Tool, req.Resource),
			Sensitive:  injection.LooksSensitive(body) || req.Provenance.Effective() == injection.Web,
		}
		// Preserve inbound taint as the stored effective source so a later
		// read cannot launder web/doc labels off.
		rec.Provenance.Source = req.Provenance.Effective()
		if rec.Provenance.Source == "" {
			rec.Provenance.Source = injection.Tool
		}
		if rec.Provenance.Origin == "" {
			rec.Provenance.Origin = req.Resource
		}
		f.mu.Lock()
		f.store[req.Resource] = rec
		f.mu.Unlock()
		return Result{OK: true, Output: "wrote " + req.Resource, Provenance: rec.Provenance, Sensitive: rec.Sensitive}
	case "read":
		f.mu.Lock()
		rec, ok := f.store[req.Resource]
		f.mu.Unlock()
		if !ok {
			return Result{Error: "files: not found"}
		}
		return Result{OK: true, Output: rec.Body, Provenance: rec.Provenance, Sensitive: rec.Sensitive}
	default:
		return Result{Error: "files: unknown operation"}
	}
}
