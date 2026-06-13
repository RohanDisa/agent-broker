package injection

import "strings"

// GuardResult is a rules-based (or optional model) classifier on tool args.
// The rules path is the one CI runs. A local Ollama model is optional and
// never required.
type GuardResult struct {
	Flagged bool   `json:"flagged"`
	Reason  string `json:"reason,omitempty"`
}

type Guard interface {
	Inspect(tool, operation string, args map[string]string, prov Provenance) GuardResult
}

// RulesGuard looks for injection-driven intent without a model.
type RulesGuard struct{}

func (RulesGuard) Inspect(tool, operation string, args map[string]string, prov Provenance) GuardResult {
	if tool == "email" && operation == "send" {
		to := args["to"]
		body := args["body"]
		ext := to != "" && !strings.HasSuffix(strings.ToLower(to), "@ourco.com")
		untrusted := prov.Effective() == Web || prov.Effective() == Doc
		if ext && untrusted {
			return GuardResult{Flagged: true, Reason: "guard: send_email to external dest with untrusted provenance"}
		}
		if ext && LooksSensitive(body) {
			return GuardResult{Flagged: true, Reason: "guard: send_email of sensitive payload to external dest"}
		}
		if strings.Contains(strings.ToLower(body), "ignore previous") ||
			strings.Contains(strings.ToLower(body), "exfiltrat") {
			return GuardResult{Flagged: true, Reason: "guard: injection phrasing in email body"}
		}
	}
	if tool == "payments" && operation == "charge" && (prov.Effective() == Web || prov.Effective() == Doc) {
		return GuardResult{Flagged: true, Reason: "guard: payment charge derived from untrusted content"}
	}
	return GuardResult{}
}

// ModelGuard is a placeholder for an optional Ollama classifier. If the
// endpoint is empty it falls back to RulesGuard. Never a hard dependency.
type ModelGuard struct {
	Endpoint string
	Fallback RulesGuard
}

func (g ModelGuard) Inspect(tool, operation string, args map[string]string, prov Provenance) GuardResult {
	// Optional model path is intentionally unused in CI. Wire Ollama here
	// if BROKER_GUARD_URL is set; until then the rules fallback is the product.
	return g.Fallback.Inspect(tool, operation, args, prov)
}
