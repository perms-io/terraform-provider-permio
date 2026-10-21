resource "permio_permission" "read" {
  name = "document.read"
}

resource "permio_permission" "write" {
  name = "document.write"
}

resource "permio_role" "editor" {
  name        = "Document editor"
  description = "Reads and edits documents"
  permissions = [
    permio_permission.read.name,
    permio_permission.write.name,
  ]
}
