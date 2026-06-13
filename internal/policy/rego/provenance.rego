package broker.policy

# A tool call whose arguments were derived from untrusted content (web/doc)
# and that targets a sensitive resource is denied. This is the anti-injection
# policy: we assume the model was fooled; we still stop the consequence.

untrusted if {
  input.provenance.effective == "web"
}

untrusted if {
  input.provenance.effective == "doc"
}

sensitive_target if {
  startswith(input.resource, "db://")
}

sensitive_target if {
  input.sensitive
}

deny[reason] if {
  untrusted
  sensitive_target
  input.operation == "write"
  reason := "untrusted provenance targeting sensitive resource"
}

deny[reason] if {
  untrusted
  input.sensitive
  input.tool == "email"
  input.operation == "send"
  reason := "untrusted provenance carrying sensitive data"
}
