# A role is imported by "<project>/<role ID>" or "<project>/<role name>". The project is required,
# because role names can contain "/" (everything after the first "/" is the role ID or name).
terraform import permio_role.editor default/2f6c1d1e-6a4b-4c8f-9d55-0c1f3f6b7a10
terraform import permio_role.editor "default/Document editor"
