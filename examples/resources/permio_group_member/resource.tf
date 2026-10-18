resource "permio_group" "oncall" {
  name = "oncall"
}

# Non-authoritative: adds one member and leaves any others alone.
# Do not combine with permio_group_members on the same group.
resource "permio_group_member" "alice" {
  group     = permio_group.oncall.name
  principal = "user_alice"
}
