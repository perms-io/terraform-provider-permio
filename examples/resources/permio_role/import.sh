# A role can be imported by "<project>/<role ID>" or "<project>/<role name>", or without the project prefix
# for the provider's project. Role names that contain "/" must use the "<project>/<name>" form.
terraform import permio_role.editor default/2f6c1d1e-6a4b-4c8f-9d55-0c1f3f6b7a10
terraform import permio_role.editor "default/Document editor"
