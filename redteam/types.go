package redteam

import "capability-broker/internal/injection"

type Scenario struct {
	Name        string   `yaml:"name"`
	Kind        string   `yaml:"kind"` // attack | benign
	Description string   `yaml:"description"`
	Setup       Setup    `yaml:"setup"`
	Steps       []Step   `yaml:"steps"`
	Expect      Expect   `yaml:"expect"`
	Ablation    Ablation `yaml:"ablation"`
}

type Setup struct {
	Grants []GrantSpec `yaml:"grants"`
}

type GrantSpec struct {
	Tool            string         `yaml:"tool"`
	Operation       string         `yaml:"operation"`
	ResourcePattern string         `yaml:"resource_pattern"`
	Constraints     ConstraintSpec `yaml:"constraints"`
}

type ConstraintSpec struct {
	MaxCalls             int      `yaml:"max_calls"`
	MaxRecords           int      `yaml:"max_records"`
	DestinationAllowlist []string `yaml:"destination_allowlist"`
	RequiresElevation    bool     `yaml:"requires_elevation"`
}

type Step struct {
	Action      string            `yaml:"action"` // call | approve | revoke | mint_tamper | present
	Tool        string            `yaml:"tool"`
	Operation   string            `yaml:"operation"`
	Resource    string            `yaml:"resource"`
	Arguments   map[string]string `yaml:"arguments"`
	Provenance  ProvSpec          `yaml:"provenance"`
	Sensitive   bool              `yaml:"sensitive"`
	ElevationID string            `yaml:"elevation_id"`
	UseCred     bool              `yaml:"use_last_credential"`
	InheritFrom *int              `yaml:"inherit_from"`
	GrantIndex  int               `yaml:"grant_index"`
	Expect      Expect            `yaml:"expect"`
}

type ProvSpec struct {
	Source string `yaml:"source"`
	Origin string `yaml:"origin"`
}

func (p ProvSpec) To() injection.Provenance {
	src := injection.User
	if p.Source != "" {
		src = injection.ParseSource(p.Source)
	}
	return injection.Provenance{Source: src, Origin: p.Origin}
}

type Expect struct {
	Action  string `yaml:"action"` // allow | deny | require_elevation
	Control string `yaml:"control"`
}

type Ablation struct {
	Disable      []string `yaml:"disable"`
	ExpectAction string   `yaml:"expect_action"`
}

type Result struct {
	Name           string `json:"name"`
	Kind           string `json:"kind"`
	Passed         bool   `json:"passed"`
	Control        string `json:"control"`
	GotAction      string `json:"got_action"`
	GotControl     string `json:"got_control"`
	AblationPassed bool   `json:"ablation_passed,omitempty"`
	AblationGot    string `json:"ablation_got,omitempty"`
	Detail         string `json:"detail,omitempty"`
}

type Report struct {
	Results        []Result `json:"results"`
	AttackTotal    int      `json:"attack_total"`
	AttackBlocked  int      `json:"attack_blocked"`
	BlockRate      float64  `json:"block_rate"`
	BenignTotal    int      `json:"benign_total"`
	BenignAllowed  int      `json:"benign_allowed"`
	FalsePositives int      `json:"false_positives"`
	FalsePosRate   float64  `json:"false_positive_rate"`
	AblationOK     int      `json:"ablation_ok"`
	AblationTotal  int      `json:"ablation_total"`
	P50            string   `json:"p50,omitempty"`
	P99            string   `json:"p99,omitempty"`
}
