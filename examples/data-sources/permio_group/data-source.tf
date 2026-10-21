data "permio_group" "engineering" {
  name = "engineering"
}

output "engineering_members" {
  value = data.permio_group.engineering.members
}
