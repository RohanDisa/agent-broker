package injection

import (
	"regexp"
	"strings"

	"capability-broker/internal/capability"
)

var (
	reSSN    = regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`)
	reSecret = regexp.MustCompile(`(?i)\b(sk-live|password|api[_-]?key|ssn)\b`)
	rePII    = regexp.MustCompile(`(?i)\b(customer_record|home_address|date_of_birth|credit_card)\b`)
)

// LooksSensitive is a conservative payload classifier used when a tool did
// not already tag the data. False positives here become egress denials, so
// we key on explicit markers plus obvious PII shapes.
func LooksSensitive(s string) bool {
	if s == "" {
		return false
	}
	return reSSN.MatchString(s) || reSecret.MatchString(s) || rePII.MatchString(s)
}

// EgressCheck is the exfiltration control: sensitive payload to a
// non-allowlisted destination is blocked.
func EgressCheck(destination string, payload string, sensitive bool, allowlist []string) (blocked bool, reason string) {
	if !sensitive && !LooksSensitive(payload) {
		return false, ""
	}
	if destinationAllowlisted(destination, allowlist) {
		return false, ""
	}
	return true, "sensitive data to non-allowlisted destination " + destination
}

func destinationAllowlisted(dest string, allowlist []string) bool {
	if dest == "" {
		return false
	}
	if len(allowlist) == 0 {
		return false
	}
	for _, p := range allowlist {
		if capability.MatchPattern(p, dest) || capability.MatchHostPattern(p, dest) {
			return true
		}
	}
	return false
}

func DestinationOf(tool, resource string, args map[string]string) string {
	if args != nil {
		if to := args["to"]; to != "" {
			return to
		}
		if u := args["url"]; u != "" {
			return u
		}
	}
	if strings.HasPrefix(resource, "email://") {
		return strings.TrimPrefix(resource, "email://")
	}
	return resource
}
