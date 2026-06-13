package policy

// Controls toggles individual defenses so the red-team suite can prove each
// layer: attack succeeds with the control off, fails with it on.
type Controls struct {
	LeastPrivilege bool
	ResourceScope  bool
	RateCount      bool
	Elevation      bool
	Provenance     bool
	Egress         bool
	Dataflow       bool
	Revocation     bool
	SingleUse      bool
	Signature      bool
	Guard          bool
}

func AllOn() Controls {
	return Controls{
		LeastPrivilege: true,
		ResourceScope:  true,
		RateCount:      true,
		Elevation:      true,
		Provenance:     true,
		Egress:         true,
		Dataflow:       true,
		Revocation:     true,
		SingleUse:      true,
		Signature:      true,
		Guard:          true,
	}
}

func (c Controls) WithDisabled(names ...string) Controls {
	for _, n := range names {
		switch Control(n) {
		case ControlLeastPrivilege:
			c.LeastPrivilege = false
		case ControlResourceScope:
			c.ResourceScope = false
		case ControlRateCount:
			c.RateCount = false
		case ControlElevation:
			c.Elevation = false
		case ControlProvenance:
			c.Provenance = false
		case ControlEgress:
			c.Egress = false
		case ControlDataflow:
			c.Dataflow = false
		case ControlRevocation:
			c.Revocation = false
		case ControlSingleUse:
			c.SingleUse = false
		case ControlSignature:
			c.Signature = false
		case ControlGuard:
			c.Guard = false
		}
	}
	return c
}
