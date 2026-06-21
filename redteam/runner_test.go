package redteam

import (
	"testing"
)

func TestRedTeamSuiteGatesBuild(t *testing.T) {
	scenarios, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	if len(scenarios) < 18 {
		t.Fatalf("expected 18 scenarios, got %d", len(scenarios))
	}
	rep, err := RunAll(scenarios)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(rep.Headline())
	t.Log("\n" + rep.Table())
	if err := FailCI(rep); err != nil {
		for _, r := range rep.Results {
			if !r.Passed || (r.Kind == "attack" && !r.AblationPassed && len(r.Detail) > 0) {
				t.Logf("%s passed=%v ablation=%v %s %s", r.Name, r.Passed, r.AblationPassed, r.Detail, r.AblationGot)
			}
		}
		t.Fatal(err)
	}
}
