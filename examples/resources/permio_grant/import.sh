# Imported by "<project>|<principal>|<resource URI>". The project is required.
# The project ends at the first "|" (project names cannot contain "|") and the resource URI starts after the
# last "|" (resource URIs cannot contain "|"), so the principal is everything in between and may itself
# contain "|", as Auth0 user IDs do.
terraform import permio_grant.support_acme "default|group:support|/workspaces/acme"
terraform import permio_grant.alice_acme "default|auth0|abc123|/workspaces/acme"
