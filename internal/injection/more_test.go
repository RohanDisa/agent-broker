package injection

import "testing"

func TestJoinAndParse(t *testing.T) {
	a := Tagged{Body: "one", Provenance: Provenance{Source: User}, Sensitive: false}
	b := Tagged{Body: "two", Provenance: Provenance{Source: Web, Origin: "http://x"}, Sensitive: true}
	j := Join(a, b)
	if j.Provenance.Effective() != Web || !j.Sensitive || j.Body == "" {
		t.Fatalf("%+v", j)
	}
	if ParseSource("USER") != User || ParseSource("web") != Web || ParseSource("doc") != Doc || ParseSource("tool") != Tool {
		t.Fatal("parse")
	}
	if ParseSource("???") != Web {
		t.Fatal("unknown defaults to untrusted")
	}
}

func TestDestinationOfAndModelGuard(t *testing.T) {
	if DestinationOf("email", "email://a@x.com", map[string]string{"to": "b@y.com"}) != "b@y.com" {
		t.Fatal("args win")
	}
	if DestinationOf("email", "email://a@x.com", nil) != "a@x.com" {
		t.Fatal("resource")
	}
	g := ModelGuard{}
	r := g.Inspect("payments", "charge", nil, Provenance{Source: Web})
	if !r.Flagged {
		t.Fatal("model guard fallback")
	}
	if !LooksSensitive("api_key sk-live") || LooksSensitive("hello") {
		t.Fatal("sensitive classifier")
	}
}

func TestEgressNoDest(t *testing.T) {
	blocked, _ := EgressCheck("", "customer_record", true, []string{"*@ourco.com"})
	if !blocked {
		t.Fatal("empty dest")
	}
}
