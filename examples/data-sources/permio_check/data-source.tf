# Policy test: fail the plan if a contractor can delete production documents.
data "permio_check" "contractor_cannot_delete" {
  principal   = "user_contractor"
  resource    = "/workspaces/acme/environments/production"
  permissions = ["document.delete"]
}

check "contractor_cannot_delete" {
  assert {
    condition     = !data.permio_check.contractor_cannot_delete.allowed
    error_message = "Contractors must not be able to delete production documents."
  }
}
