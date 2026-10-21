resource "permio_permission" "read" {
  name = "document.read"
}

resource "permio_permission" "share" {
  name = "document.share"
}

resource "permio_role" "viewer" {
  name        = "Viewer"
  permissions = [permio_permission.read.name]
}

resource "permio_group" "support" {
  name = "support"
}

# Every member of the support group can read everything in workspace acme.
resource "permio_grant" "support_acme" {
  principal = permio_group.support.principal
  resource  = "/workspaces/acme"
  roles     = [permio_role.viewer.id]
}

# A user granted directly. A "_" segment matches any single segment,
# so this covers /workspaces/<any>/shared.
resource "permio_grant" "alice_shared" {
  principal   = "user_alice"
  resource    = "/workspaces/_/shared"
  roles       = [permio_role.viewer.id]
  permissions = [permio_permission.share.name]
}
