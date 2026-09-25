# No provider, no cloud account: terraform_data is built into Terraform >= 1.4 and OpenTofu.
variable "releases" {
  type    = list(string)
  default = ["api", "worker"]
}

resource "terraform_data" "release" {
  for_each = toset(var.releases)
  input    = { name = each.key, version = "1.0.0" }
}
