package policy

import "strings"

// Action is the three-way policy result. Every decision carries a reason
// that is written to the audit log.
type Action string

const (
	Allow            Action = "allow"
	Deny             Action = "deny"
	RequireElevation Action = "require_elevation"
)

// Control names the layer that produced the decision. The red-team table
// maps each attack to one of these.
type Control string

const (
	ControlLeastPrivilege Control = "least_privilege"
	ControlResourceScope  Control = "resource_scope"
	ControlRateCount      Control = "rate_count"
	ControlElevation      Control = "elevation"
	ControlProvenance     Control = "provenance"
	ControlEgress         Control = "egress"
	ControlDataflow       Control = "dataflow"
	ControlRevocation     Control = "revocation"
	ControlSingleUse      Control = "single_use"
	ControlSignature      Control = "signature"
	ControlGuard          Control = "guard"
	ControlNone           Control = ""
)

// Decision is the policy engine output.
type Decision struct {
	Action  Action  `json:"action"`
	Reason  string  `json:"reason"`
	Control Control `json:"control"`
	GrantID string  `json:"grant_id,omitempty"`
}

func (d Decision) Allowed() bool { return d.Action == Allow }

func (d Decision) Denied() bool { return d.Action == Deny }

func Denied(control Control, reason string) Decision {
	return Decision{Action: Deny, Control: control, Reason: reason}
}

func Allowed(grantID, reason string) Decision {
	return Decision{Action: Allow, Control: ControlNone, GrantID: grantID, Reason: reason}
}

func Elevate(grantID, reason string) Decision {
	return Decision{Action: RequireElevation, Control: ControlElevation, GrantID: grantID, Reason: reason}
}

func HighRiskOp(tool, operation, resource string) bool {
	if tool == "payments" && operation == "charge" {
		return true
	}
	if tool == "db" && operation == "delete" {
		return true
	}
	if tool == "email" && operation == "send" && isExternalEmail(resource) {
		return true
	}
	return false
}

func isExternalEmail(resource string) bool {
	r := resource
	if i := strings.Index(r, "://"); i >= 0 {
		r = r[i+3:]
	}
	return r != "" && !strings.HasSuffix(strings.ToLower(r), "@ourco.com")
}

func IsEgressOp(tool, operation string) bool {
	if tool == "email" && operation == "send" {
		return true
	}
	if tool == "http" && (operation == "post" || operation == "write") {
		return true
	}
	if tool == "files" && operation == "write_shared" {
		return true
	}
	return false
}
