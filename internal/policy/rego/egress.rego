package broker.policy

# Any send/write to a destination not on the grant allowlist is denied.

egress if {
  input.tool == "email"
  input.operation == "send"
}

on_allowlist if {
  some g in input.grants
  g.id == input.matched_grant
  some p in g.constraints.destination_allowlist
  glob.match(p, [], destination)
}

deny[reason] if {
  egress
  count(input.matched_allowlist) > 0
  not on_allowlist
  reason := sprintf("destination %s is not on the grant allowlist", [destination])
}
