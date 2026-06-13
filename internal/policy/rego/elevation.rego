package broker.policy

high_risk if {
  input.tool == "payments"
  input.operation == "charge"
}

high_risk if {
  input.tool == "db"
  input.operation == "delete"
}

high_risk if {
  input.tool == "email"
  input.operation == "send"
  not endswith(lower(destination), "@ourco.com")
}

require_elevation if {
  high_risk
}

destination := input.arguments.to
destination := trim_prefix(input.resource, "email://") if {
  not input.arguments.to
}
