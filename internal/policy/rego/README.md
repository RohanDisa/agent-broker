# Policy as code

These Rego files are the auditable statement of what the broker enforces.
The Go engine in `engine.go` evaluates the same rules so CI has no OPA
versioning surprises and no extra runtime.

Why not bury this in the HTTP handler: policy is data. You can version it,
diff it, and show an interviewer the exact predicate that blocked an attack.

Why not require OPA at runtime: a teaching-grade broker should run offline
in CI with one `go test`. The Go engine is the documented fallback DSL.

Package `broker.policy` is the logical package name; OPA is not a hard
dependency.
