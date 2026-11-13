config {
  call_module_type = "all"
}

plugin "terraform" {
  enabled = true
  preset  = "recommended"
}

# main.tf uses two-argument lookup() throughout (about 1,700 calls), which floods
# reviewdog past the GitHub annotation limit and fails the step.
rule "terraform_deprecated_lookup" {
  enabled = false
}
