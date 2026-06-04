package capability

import (
	"fmt"
	"time"
)

// Grant is a narrow, typed authority: one tool, one operation, one resource
// pattern, plus caveats that can only shrink that authority.
type Grant struct {
	ID              string      `json:"id"`
	TaskID          string      `json:"task_id"`
	Tool            string      `json:"tool"`
	Operation       string      `json:"operation"`
	ResourcePattern string      `json:"resource_pattern"`
	Constraints     Constraints `json:"constraints"`
	IssuedAt        time.Time   `json:"issued_at"`
	ExpiresAt       time.Time   `json:"expires_at"`
	Revoked         bool        `json:"revoked"`
}

// Constraints attenuate a grant. They are the standing caveats on the grant
// itself; per-call credentials may add more, never fewer.
type Constraints struct {
	MaxCalls             int           `json:"max_calls,omitempty"`
	TTL                  time.Duration `json:"ttl,omitempty"`
	RateLimit            int           `json:"rate_limit,omitempty"`
	RateWindow           time.Duration `json:"rate_window,omitempty"`
	DestinationAllowlist []string      `json:"destination_allowlist,omitempty"`
	RequiresElevation    bool          `json:"requires_elevation,omitempty"`
	MaxRecords           int           `json:"max_records,omitempty"`
}

// MatchesToolOp reports whether this grant covers the tool and operation.
// Resource matching is a separate check so policy can attribute denials to
// least-privilege vs resource-scope.
func (g Grant) MatchesToolOp(tool, operation string) bool {
	return g.Tool == tool && g.Operation == operation
}

// Covers reports whether this grant authorizes (tool, operation, resource).
func (g Grant) Covers(tool, operation, resource string) bool {
	if !g.MatchesToolOp(tool, operation) {
		return false
	}
	return MatchPattern(g.ResourcePattern, resource)
}

// CanAttenuateTo is the core capability-security property: the requested
// resource must be equal to or narrower than the grant. Broadening fails.
func (g Grant) CanAttenuateTo(tool, operation, resource string) error {
	if !g.MatchesToolOp(tool, operation) {
		return fmt.Errorf("%w: grant %s is %s.%s, requested %s.%s",
			ErrWidening, g.ID, g.Tool, g.Operation, tool, operation)
	}
	if !IsNarrowerOrEqual(resource, g.ResourcePattern) {
		return fmt.Errorf("%w: resource %q is not a narrowing of %q",
			ErrWidening, resource, g.ResourcePattern)
	}
	return nil
}

func (g Grant) DestinationAllowed(dest string) bool {
	if len(g.Constraints.DestinationAllowlist) == 0 {
		return true
	}
	for _, pat := range g.Constraints.DestinationAllowlist {
		if MatchPattern(pat, dest) || MatchHostPattern(pat, dest) {
			return true
		}
	}
	return false
}
