package policy

import (
	"strings"
	"time"

	"capability-broker/internal/capability"
	"capability-broker/internal/injection"
)

// Input is everything the deny-by-default engine needs for one call.
type Input struct {
	Tool        string
	Operation   string
	Resource    string
	Arguments   map[string]string
	Grants      []capability.Grant
	Provenance  injection.Provenance
	Sensitive   bool
	Destination string
	CallCount   int // prior matching calls in this task (for max_calls)
	RecordCount int // prior records read in this task
	WindowCount int // calls inside the rate window
	Now         time.Time
}

// Engine is a typed policy DSL. Equivalent Rego lives in policy/rego so
// policy is data you can audit, not a pile of if-statements buried in the
// HTTP handler. Deny is the default; every allow is justified by a grant.
type Engine struct {
	Controls Controls
}

func NewEngine() *Engine {
	return &Engine{Controls: AllOn()}
}

func (e *Engine) Evaluate(in Input) Decision {
	if in.Now.IsZero() {
		in.Now = time.Now()
	}
	dest := in.Destination
	if dest == "" {
		dest = destinationFrom(in.Tool, in.Resource, in.Arguments)
	}

	var match *capability.Grant
	var toolOpHit *capability.Grant
	var revokedHit *capability.Grant
	for i := range in.Grants {
		g := &in.Grants[i]
		if !g.ExpiresAt.IsZero() && in.Now.After(g.ExpiresAt) {
			continue
		}
		if !g.MatchesToolOp(in.Tool, in.Operation) {
			continue
		}
		if e.Controls.ResourceScope && !capability.MatchPattern(g.ResourcePattern, in.Resource) {
			if toolOpHit == nil && !g.Revoked {
				toolOpHit = g
			}
			continue
		}
		if g.Revoked {
			revokedHit = g
			continue
		}
		if toolOpHit == nil {
			toolOpHit = g
		}
		match = g
		break
	}

	if match == nil && revokedHit != nil && e.Controls.Revocation {
		return Denied(ControlRevocation, "grant revoked; next call denied")
	}
	if e.Controls.LeastPrivilege && match == nil && toolOpHit == nil {
		return Denied(ControlLeastPrivilege, "no grant matches tool+operation; deny by default")
	}
	if e.Controls.ResourceScope && match == nil && toolOpHit != nil {
		return Denied(ControlResourceScope, "grant matches tool+op but resource "+in.Resource+" is outside "+toolOpHit.ResourcePattern)
	}
	if match == nil {
		if !e.Controls.LeastPrivilege {
			// Ablation: invent a synthetic grant so later rules can still run.
			synth := capability.Grant{ID: "ablated", TaskID: "", Tool: in.Tool, Operation: in.Operation, ResourcePattern: in.Resource}
			match = &synth
		} else {
			return Denied(ControlLeastPrivilege, "no active grant for this call")
		}
	}

	if e.Controls.RateCount {
		if match.Constraints.MaxCalls > 0 && in.CallCount >= match.Constraints.MaxCalls {
			return Denied(ControlRateCount, "session max_calls caveat exceeded")
		}
		if match.Constraints.MaxRecords > 0 && in.RecordCount >= match.Constraints.MaxRecords {
			return Denied(ControlRateCount, "session max_records data cap exceeded")
		}
		if match.Constraints.RateLimit > 0 && in.WindowCount >= match.Constraints.RateLimit {
			return Denied(ControlRateCount, "rate_limit caveat exceeded")
		}
	}

	if e.Controls.Egress && IsEgressOp(in.Tool, in.Operation) {
		allow := match.Constraints.DestinationAllowlist
		if len(allow) > 0 && dest != "" && !match.DestinationAllowed(dest) {
			return Denied(ControlEgress, "destination "+dest+" is not on the grant allowlist")
		}
	}

	if e.Controls.Dataflow && in.Sensitive && IsEgressOp(in.Tool, in.Operation) {
		allow := match.Constraints.DestinationAllowlist
		if dest != "" && (len(allow) == 0 || !match.DestinationAllowed(dest)) {
			return Denied(ControlDataflow, "sensitive payload cannot leave to "+dest)
		}
	}

	if e.Controls.Provenance {
		if inj := provenanceViolation(in, dest); inj != "" {
			return Denied(ControlProvenance, inj)
		}
	}

	if e.Controls.Elevation && (match.Constraints.RequiresElevation || HighRiskOp(in.Tool, in.Operation, in.Resource)) {
		return Elevate(match.ID, "high-risk operation requires just-in-time approval")
	}

	return Allowed(match.ID, "grant "+match.ID+" authorizes "+in.Tool+"."+in.Operation+" on "+in.Resource)
}

func provenanceViolation(in Input, dest string) string {
	src := in.Provenance.Effective()
	untrusted := src == injection.Web || src == injection.Doc
	if !untrusted {
		return ""
	}
	// Sensitive *resource* (db, payments), not merely a sensitive *payload*.
	// Scratch files are the laundering intermediate and must keep the taint
	// without being blocked — the write into db/email is the consequence.
	sensitiveTarget := strings.HasPrefix(in.Resource, "db://") || strings.HasPrefix(in.Resource, "payments://")
	if sensitiveTarget && (in.Operation == "write" || in.Operation == "delete" || in.Operation == "charge") {
		return "untrusted " + string(src) + " provenance targeting sensitive resource " + in.Resource
	}
	if IsEgressOp(in.Tool, in.Operation) && in.Sensitive {
		return "untrusted " + string(src) + " provenance carrying sensitive data to " + dest
	}
	if IsEgressOp(in.Tool, in.Operation) && dest != "" && !strings.HasSuffix(strings.ToLower(stripScheme(dest)), "@ourco.com") {
		return "untrusted " + string(src) + " provenance sending to unapproved destination " + dest
	}
	return ""
}

func destinationFrom(tool, resource string, args map[string]string) string {
	if args != nil {
		if to, ok := args["to"]; ok && to != "" {
			return to
		}
		if u, ok := args["url"]; ok && u != "" {
			return u
		}
	}
	if tool == "email" || strings.HasPrefix(resource, "email://") {
		return stripScheme(resource)
	}
	return resource
}

func stripScheme(s string) string {
	if i := strings.Index(s, "://"); i >= 0 {
		return s[i+3:]
	}
	return s
}
