package broker.policy

# Caveats are enforced across the session, not just the current call.

deny[reason] if {
  some g in input.grants
  g.id == input.matched_grant
  g.constraints.max_calls > 0
  input.call_count >= g.constraints.max_calls
  reason := "session max_calls caveat exceeded"
}

deny[reason] if {
  some g in input.grants
  g.id == input.matched_grant
  g.constraints.max_records > 0
  input.record_count >= g.constraints.max_records
  reason := "session max_records data cap exceeded"
}
