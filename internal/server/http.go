package server

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"capability-broker/internal/broker"
	"capability-broker/internal/capability"
	"capability-broker/internal/injection"
)

type Server struct {
	Broker *broker.Service
}

func New(b *broker.Service) *Server { return &Server{Broker: b} }

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", s.health)
	mux.HandleFunc("GET /v1/health", s.health)
	mux.HandleFunc("POST /v1/tasks", s.createTask)
	mux.HandleFunc("POST /v1/call", s.call)
	mux.HandleFunc("POST /v1/tools/call", s.call)
	mux.HandleFunc("POST /v1/elevate/approve", s.approve)
	mux.HandleFunc("POST /v1/elevate/deny", s.deny)
	mux.HandleFunc("GET /v1/elevate/pending", s.pending)
	mux.HandleFunc("POST /v1/revoke", s.revoke)
	mux.HandleFunc("GET /v1/audit", s.audit)
	mux.HandleFunc("POST /v1/audit/verify", s.verifyAudit)
	mux.HandleFunc("GET /v1/metrics", s.metrics)
	return withLog(mux)
}

func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) createTask(w http.ResponseWriter, r *http.Request) {
	var req broker.CreateTaskReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	resp, err := s.Broker.CreateTask(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) call(w http.ResponseWriter, r *http.Request) {
	var req broker.CallReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if req.Provenance.Source == "" {
		req.Provenance.Source = injection.User
	}
	resp, err := s.Broker.Call(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) approve(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	resp, err := s.Broker.Approve(body.ID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) deny(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ID string `json:"id"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	resp, err := s.Broker.DenyElevation(body.ID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) pending(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.Broker.Elev.Pending())
}

func (s *Server) revoke(w http.ResponseWriter, r *http.Request) {
	var body struct {
		GrantID string `json:"grant_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.Broker.RevokeGrant(body.GrantID); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"revoked": body.GrantID})
}

func (s *Server) audit(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.Broker.AuditEntries())
}

func (s *Server) verifyAudit(w http.ResponseWriter, _ *http.Request) {
	if err := s.Broker.VerifyAudit(); err != nil {
		writeJSON(w, http.StatusConflict, map[string]string{"ok": "false", "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "entries": s.Broker.Audit.Len()})
}

func (s *Server) metrics(w http.ResponseWriter, _ *http.Request) {
	p50, p99, n := s.Broker.LatencySnapshot()
	pp50, pp99, pn := s.Broker.PolicyLatencySnapshot()
	writeJSON(w, http.StatusOK, map[string]any{
		"calls":          n,
		"call_p50":       p50.String(),
		"call_p99":       p99.String(),
		"policy_eval_n":  pn,
		"policy_p50":     pp50.String(),
		"policy_p99":     pp99.String(),
		"policy_p50_ns":  pp50.Nanoseconds(),
		"policy_p99_ns":  pp99.Nanoseconds(),
		"credential_ttl": capability.DefaultTTL.String(),
	})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func withLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		_, _ = io.Copy(io.Discard, r.Body)
		if !strings.HasPrefix(r.URL.Path, "/health") {
			_ = start
		}
	})
}
