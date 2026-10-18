resource "permio_group" "engineering" {
  name = "engineering"
}

# Authoritative: these are the group's only members. Anyone else is removed.
resource "permio_group_members" "engineering" {
  group = permio_group.engineering.name
  members = [
    "user_alice",
    "user_bob",
  ]
}
