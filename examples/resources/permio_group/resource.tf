resource "permio_group" "engineering" {
  name        = "engineering"
  description = "Everyone in engineering"
}

# Grant to the group with its principal ("group:engineering").
output "engineering_principal" {
  value = permio_group.engineering.principal
}
