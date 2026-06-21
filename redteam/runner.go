package redteam

import (
	"embed"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"capability-broker/internal/broker"
	"capability-broker/internal/capability"
	"capability-broker/internal/injection"
	"capability-broker/internal/policy"

	"gopkg.in/yaml.v3"
)

//go:embed scenarios/*.yaml
var scenarioFS embed.FS

func LoadEmbedded() ([]Scenario, error) {
	return loadFS(scenarioFS, "scenarios")
}

func loadFS(fsys fs.FS, dir string) ([]Scenario, error) {
	ents, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return nil, err
	}
	var out []Scenario
	for _, e := range ents {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		b, err := fs.ReadFile(fsys, dir+"/"+e.Name())
		if err != nil {
			return nil, err
		}
		var sc Scenario
		if err := yaml.Unmarshal(b, &sc); err != nil {
			return nil, fmt.Errorf("%s: %w", e.Name(), err)
		}
		out = append(out, sc)
	}
	return out, nil
}

func LoadDir(dir string) ([]Scenario, error) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []Scenario
	for _, e := range ents {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, err
		}
		var sc Scenario
		if err := yaml.Unmarshal(b, &sc); err != nil {
			return nil, fmt.Errorf("%s: %w", e.Name(), err)
		}
		out = append(out, sc)
	}
	return out, nil
}

func RunAll(scenarios []Scenario) (Report, error) {
	var rep Report
	for _, sc := range scenarios {
		res, err := RunOne(sc, policy.AllOn())
		if err != nil {
			return rep, err
		}
		if sc.Kind == "attack" && len(sc.Ablation.Disable) > 0 {
			ab, err := RunOne(sc, policy.AllOn().WithDisabled(sc.Ablation.Disable...))
			if err != nil {
				return rep, err
			}
			want := sc.Ablation.ExpectAction
			if want == "" {
				want = "allow"
			}
			res.AblationGot = ab.GotAction
			res.AblationPassed = ab.GotAction == want
			rep.AblationTotal++
			if res.AblationPassed {
				rep.AblationOK++
			}
			if !res.AblationPassed {
				res.Detail += fmt.Sprintf("; ablation: want %s got %s (%s)", want, ab.GotAction, ab.GotControl)
			}
		}
		rep.Results = append(rep.Results, res)
		switch sc.Kind {
		case "attack":
			rep.AttackTotal++
			if res.Passed {
				rep.AttackBlocked++
			}
		case "benign":
			rep.BenignTotal++
			if res.Passed {
				rep.BenignAllowed++
			} else {
				rep.FalsePositives++
			}
		}
	}
	if rep.AttackTotal > 0 {
		rep.BlockRate = float64(rep.AttackBlocked) / float64(rep.AttackTotal)
	}
	if rep.BenignTotal > 0 {
		rep.FalsePosRate = float64(rep.FalsePositives) / float64(rep.BenignTotal)
	}
	return rep, nil
}

func RunOne(sc Scenario, ctrl policy.Controls) (Result, error) {
	s, err := broker.New(broker.Config{TTL: 5 * time.Second, Controls: ctrl})
	if err != nil {
		return Result{}, err
	}
	var grants []capability.Grant
	for _, g := range sc.Setup.Grants {
		grants = append(grants, capability.Grant{
			Tool: g.Tool, Operation: g.Operation, ResourcePattern: g.ResourcePattern,
			Constraints: capability.Constraints{
				MaxCalls:             g.Constraints.MaxCalls,
				MaxRecords:           g.Constraints.MaxRecords,
				DestinationAllowlist: g.Constraints.DestinationAllowlist,
				RequiresElevation:    g.Constraints.RequiresElevation,
			},
		})
	}
	ct, err := s.CreateTask(broker.CreateTaskReq{Name: sc.Name, Grants: grants})
	if err != nil {
		return Result{}, err
	}

	var last broker.CallResp
	var lastCred string
	var outputs []broker.CallResp
	elevID := ""

	finalExpect := sc.Expect
	res := Result{Name: sc.Name, Kind: sc.Kind, Control: sc.Expect.Control}

	for i, st := range sc.Steps {
		switch st.Action {
		case "revoke":
			idx := st.GrantIndex
			if idx < 0 || idx >= len(ct.Grants) {
				idx = 0
			}
			if err := s.RevokeGrant(ct.Grants[idx].ID); err != nil {
				return res, err
			}
			continue
		case "approve":
			id := st.ElevationID
			if id == "" {
				id = elevID
			}
			if id == "" {
				continue
			}
			if _, err := s.Approve(id); err != nil {
				return res, err
			}
			continue
		case "mint_tamper":
			c, err := s.MintOnly(ct.TaskID, st.Tool, st.Operation, st.Resource)
			if err != nil {
				return res, err
			}
			widened := st.Arguments["widen_to"]
			if widened == "" {
				widened = "db://customers/124/profile"
			}
			tampered := c.TamperResource(widened)
			wire, err := tampered.Encode()
			if err != nil {
				return res, err
			}
			lastCred = wire
			last, err = s.Call(broker.CallReq{
				TaskID: ct.TaskID, Tool: st.Tool, Operation: st.Operation,
				Resource: widened, Credential: wire,
			})
			if err != nil {
				return res, err
			}
			outputs = append(outputs, last)
			if st.Expect.Action != "" {
				finalExpect = st.Expect
			}
			continue
		}

		args := map[string]string{}
		for k, v := range st.Arguments {
			args[k] = v
		}
		prov := st.Provenance.To()
		sensitive := st.Sensitive
		if st.InheritFrom != nil {
			idx := *st.InheritFrom
			if idx >= 0 && idx < len(outputs) && outputs[idx].Result != nil {
				prev := outputs[idx].Result
				if args["body"] == "" {
					args["body"] = injection.Unwrap(prev.Output)
				}
				prov = prev.Provenance
				if prev.Sensitive {
					sensitive = true
				}
			}
		}
		req := broker.CallReq{
			TaskID:     ct.TaskID,
			Tool:       st.Tool,
			Operation:  st.Operation,
			Resource:   st.Resource,
			Arguments:  args,
			Provenance: prov,
			Sensitive:  sensitive,
		}
		if st.UseCred {
			req.Credential = lastCred
		}
		if st.ElevationID == "last" || (st.Action == "call_elevated") {
			req.ElevationID = elevID
		}
		if st.ElevationID != "" && st.ElevationID != "last" {
			req.ElevationID = st.ElevationID
		}
		last, err = s.Call(req)
		if err != nil {
			return res, err
		}
		if last.Credential != "" {
			lastCred = last.Credential
		}
		if last.ElevationID != "" {
			elevID = last.ElevationID
		}
		outputs = append(outputs, last)
		if st.Expect.Action != "" {
			finalExpect = st.Expect
			if !matchExpect(last, st.Expect) {
				res.Passed = false
				res.GotAction = string(last.Decision.Action)
				res.GotControl = string(last.Decision.Control)
				res.Detail = fmt.Sprintf("step %d: want %s/%s got %s/%s (%s)", i, st.Expect.Action, st.Expect.Control, last.Decision.Action, last.Decision.Control, last.Decision.Reason)
				return res, nil
			}
		}
	}

	res.GotAction = string(last.Decision.Action)
	res.GotControl = string(last.Decision.Control)
	res.Passed = matchExpect(last, finalExpect)
	if !res.Passed {
		res.Detail = fmt.Sprintf("want %s/%s got %s/%s (%s)", finalExpect.Action, finalExpect.Control, last.Decision.Action, last.Decision.Control, last.Decision.Reason)
	}
	p50, p99, _ := s.LatencySnapshot()
	_ = p50
	_ = p99
	return res, nil
}

func matchExpect(got broker.CallResp, exp Expect) bool {
	if exp.Action != "" && string(got.Decision.Action) != exp.Action {
		return false
	}
	if exp.Control != "" && string(got.Decision.Control) != exp.Control {
		return false
	}
	return true
}

func (r Report) Headline() string {
	return fmt.Sprintf("block_rate=%.0f%% (%d/%d attacks)  false_positive_rate=%.0f%% (%d/%d benign)  ablation=%d/%d",
		r.BlockRate*100, r.AttackBlocked, r.AttackTotal,
		r.FalsePosRate*100, r.FalsePositives, r.BenignTotal,
		r.AblationOK, r.AblationTotal)
}

func (r Report) Table() string {
	var b strings.Builder
	b.WriteString("| Attack | Outcome | Defending layer |\n")
	b.WriteString("|---|---|---|\n")
	for _, res := range r.Results {
		if res.Kind != "attack" {
			continue
		}
		out := "BLOCKED"
		if !res.Passed {
			out = "MISSED"
		}
		b.WriteString("| " + res.Name + " | " + out + " | " + res.Control + " |\n")
	}
	return b.String()
}

func FailCI(r Report) error {
	if r.AttackTotal == 0 {
		return fmt.Errorf("no attack scenarios")
	}
	if r.BlockRate < 1.0 {
		return fmt.Errorf("block rate %.0f%% below 100%%: a security control regressed", r.BlockRate*100)
	}
	if r.FalsePositives > 0 {
		return fmt.Errorf("false positives: %d benign scenario(s) denied", r.FalsePositives)
	}
	if r.AblationTotal > 0 && r.AblationOK < r.AblationTotal {
		return fmt.Errorf("ablation proof failed: %d/%d (attack should succeed with the defending control off)", r.AblationOK, r.AblationTotal)
	}
	return nil
}
