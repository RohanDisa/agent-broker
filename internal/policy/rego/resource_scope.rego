package broker.policy

# db://customers/123/* does not authorize db://customers/124.

resource_in_scope if {
  some g in input.grants
  not g.revoked
  g.tool == input.tool
  g.operation == input.operation
  glob.match(g.resource_pattern, [], input.resource)
}

deny[reason] if {
  grant_matches_tool_op
  not resource_in_scope
  reason := sprintf("resource %s outside granted pattern", [input.resource])
}
