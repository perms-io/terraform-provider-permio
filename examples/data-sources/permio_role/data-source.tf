# Look up a role created outside Terraform and grant it by ID.
data "permio_role" "admin" {
  name = "Workspace admin"
}

resource "permio_grant" "alice" {
  principal = "user_alice"
  resource  = "/workspaces/acme"
  roles     = [data.permio_role.admin.id]
}
