package broker.policy

# Deny by default. An allow must be justified by an active grant covering
# tool + operation. Resource matching is a separate rule.

default allow := false

grant_matches_tool_op if {
  some g in input.grants
  not g.revoked
  g.tool == input.tool
  g.operation == input.operation
}

deny[reason] if {
  not grant_matches_tool_op
  reason := "no grant matches tool+operation; deny by default"
}
