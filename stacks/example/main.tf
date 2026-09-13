# stacks/example — layout reference for a drift-managed stack.
#
# Copy this directory per stack (stacks/<name>/), add your resources, and
# point the backend at your state. The detect workflow runs
# `terraform init` + a refresh-only plan in stacks/<name>/, so the backend
# must be reachable from Actions through DRIFT_READONLY_ROLE.
#
# Keep detect, PR-check, and apply on the same terraform version
# (the workflows pin 1.9) — provider-version churn looks like drift.

terraform {
  # Example: S3 backend. Fill in your bucket/key/region.
  # backend "s3" {
  #   bucket = "my-tfstate-bucket"
  #   key    = "example.tfstate"
  #   region = "us-east-1"
  # }

  required_version = ">= 1.9"
}

# Placeholder so the layout validates before you add real resources.
resource "terraform_data" "example" {
  input = "replace me with real resources"
}
