# Terraform Provider for Permio

Manage [Permio](https://perms.io) authorisation as code: permissions, roles, groups and their
members, and grants of roles and permissions to principals on resource URIs. The `permio_check`
data source evaluates permission checks, so you can write policy tests in Terraform.

- Documentation: [`docs/`](docs/index.md) (published on the Terraform Registry)
- Examples: [`examples/`](examples/), including a complete [SaaS workspace](examples/saas-workspace/main.tf)

## Quick start

1. Create a **full-access** API key for your project in the Permio dashboard and export it:

   ```sh
   export PERMIO_API_KEY=perms_...
   ```

2. Write a configuration:

   ```terraform
   terraform {
     required_providers {
       permio = {
         source = "perms-io/permio"
       }
     }
   }

   provider "permio" {}

   resource "permio_permission" "read" {
     name = "document.read"
   }

   resource "permio_permission" "write" {
     name = "document.write"
   }

   resource "permio_role" "editor" {
     name        = "Editor"
     permissions = [permio_permission.read.name, permio_permission.write.name]
   }

   resource "permio_group" "engineering" {
     name = "engineering"
   }

   resource "permio_group_members" "engineering" {
     group   = permio_group.engineering.name
     members = ["user_alice", "user_bob"]
   }

   # Everyone in engineering can edit everything under /workspaces/acme.
   resource "permio_grant" "engineering" {
     principal = permio_group.engineering.principal
     resource  = "/workspaces/acme"
     roles     = [permio_role.editor.id]
   }
   ```

3. Run `terraform init` and `terraform apply`.

## Provider configuration

| Argument  | Environment variable | Default                  |
|-----------|----------------------|--------------------------|
| `api_key` | `PERMIO_API_KEY`     | (required)               |
| `project` | `PERMIO_PROJECT`     | `default`                |

An API key belongs to one organisation and one project. Managing objects needs a full-access key;
a check-only key is enough for the data sources.

## Resources and data sources

| Resource                | Description                                                                 |
|-------------------------|-----------------------------------------------------------------------------|
| `permio_permission`     | A permission. Renamed in place.                                              |
| `permio_role`           | A named set of permissions. Grants refer to it by `id`.                      |
| `permio_group`          | A group of principals; grant to its `principal` (`group:<name>`).            |
| `permio_group_members`  | A group's complete member list (authoritative).                             |
| `permio_group_member`   | One group member (non-authoritative). Don't mix with `permio_group_members`. |
| `permio_grant`          | Roles and permissions of one principal on one resource URI (authoritative). |

Data sources: `permio_permission`, `permio_role` (by name or ID), `permio_group` (with members) and
`permio_check`.

**Use exactly one `permio_grant` per principal and resource URI.** It manages everything granted
directly on that pair and revokes anything else.

## Development

Requires Go (see `go.mod`) and a `terraform` binary on `PATH` (or in `TF_ACC_TERRAFORM_PATH`).

```sh
make build     # build
make test      # unit tests against an in-process fake Permio API (go test -race ./...)
make docs      # regenerate docs/ with tfplugindocs
make testacc   # acceptance tests against a real API (needs PERMIO_API_KEY; creates and deletes objects)
```

To try a local build, add a `dev_overrides` block for `privatejar/permio` to your
[CLI configuration](https://developer.hashicorp.com/terraform/cli/config/config-file#development-overrides-for-provider-developers)
pointing at the directory containing the built `terraform-provider-permio` binary.

## License

[Apache-2.0](LICENSE)
