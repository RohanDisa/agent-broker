package policy

import (
	"testing"
	"time"

	"capability-broker/internal/capability"
)

func BenchmarkEvaluateAllow(b *testing.B) {
	e := NewEngine()
	g := grant("db", "read", "db://customers/123/*")
	in := Input{
		Tool: "db", Operation: "read", Resource: "db://customers/123/profile",
		Grants: []capability.Grant{g}, Now: time.Now(),
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		d := e.Evaluate(in)
		if d.Action != Allow {
			b.Fatal(d)
		}
	}
}

func BenchmarkEvaluateDeny(b *testing.B) {
	e := NewEngine()
	g := grant("db", "read", "db://customers/123/*")
	in := Input{
		Tool: "email", Operation: "send", Resource: "email://attacker@evil.com",
		Grants: []capability.Grant{g}, Now: time.Now(),
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		d := e.Evaluate(in)
		if d.Action != Deny {
			b.Fatal(d)
		}
	}
}
