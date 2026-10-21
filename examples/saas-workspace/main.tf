# A SaaS workspace model: permissions, roles built from them, teams as groups, and grants that are
# inherited down the resource tree.
#
#   /workspaces/<workspace>                              workspace-wide grants
#   /workspaces/<workspace>/projects/<project>           project-level grants
#   /workspaces/<workspace>/projects/<project>/docs/<id> documents inherit both
#
# Run with PERMIO_API_KEY set to a full-access key for the project.

terraform {
  required_providers {
    permio = {
      source = "PrivateJAR/permio"
    }
  }
}

provider "permio" {}

variable "workspace" {
  description = "Workspace slug used in resource URIs."
  type        = string
  default     = "acme"
}

variable "admins" {
  description = "User IDs of the workspace admins."
  type        = set(string)
  default     = ["user_alice"]
}

variable "engineers" {
  description = "User IDs of the engineering team."
  type        = set(string)
  default     = ["user_bob", "user_carol"]
}

variable "support" {
  description = "User IDs of the support team."
  type        = set(string)
  default     = ["user_dave"]
}

locals {
  workspace_uri = "/workspaces/${var.workspace}"
}

# --- Permissions ---------------------------------------------------------------------------------

resource "permio_permission" "document_read" {
  name        = "document.read"
  description = "Read documents"
}

resource "permio_permission" "document_write" {
  name        = "document.write"
  description = "Create and edit documents"
}

resource "permio_permission" "document_delete" {
  name        = "document.delete"
  description = "Delete documents"
}

resource "permio_permission" "document_share" {
  name        = "document.share"
  description = "Share documents outside the workspace"
}

resource "permio_permission" "project_manage" {
  name        = "project.manage"
  description = "Create, rename and archive projects"
}

resource "permio_permission" "member_manage" {
  name        = "member.manage"
  description = "Invite and remove workspace members"
}

resource "permio_permission" "billing_view" {
  name        = "billing.view"
  description = "View invoices and usage"
}

resource "permio_permission" "billing_manage" {
  name        = "billing.manage"
  description = "Change the plan and payment details"
}

# --- Roles ---------------------------------------------------------------------------------------

resource "permio_role" "viewer" {
  name        = "${var.workspace} viewer"
  description = "Read-only access"
  permissions = [permio_permission.document_read.name]
}

resource "permio_role" "editor" {
  name        = "${var.workspace} editor"
  description = "Reads and writes documents"
  permissions = [
    permio_permission.document_read.name,
    permio_permission.document_write.name,
    permio_permission.document_share.name,
  ]
}

resource "permio_role" "maintainer" {
  name        = "${var.workspace} maintainer"
  description = "Editor, plus deleting documents and managing projects"
  permissions = [
    permio_permission.document_read.name,
    permio_permission.document_write.name,
    permio_permission.document_share.name,
    permio_permission.document_delete.name,
    permio_permission.project_manage.name,
  ]
}

resource "permio_role" "admin" {
  name        = "${var.workspace} admin"
  description = "Everything in the workspace"
  permissions = [
    permio_permission.document_read.name,
    permio_permission.document_write.name,
    permio_permission.document_delete.name,
    permio_permission.document_share.name,
    permio_permission.project_manage.name,
    permio_permission.member_manage.name,
    permio_permission.billing_view.name,
    permio_permission.billing_manage.name,
  ]
}

resource "permio_role" "billing" {
  name        = "${var.workspace} billing"
  description = "Views billing"
  permissions = [permio_permission.billing_view.name]
}

# --- Teams ---------------------------------------------------------------------------------------

resource "permio_group" "admins" {
  name        = "${var.workspace}-admins"
  description = "Workspace administrators"
}

resource "permio_group" "engineering" {
  name        = "${var.workspace}-engineering"
  description = "Engineering team"
}

resource "permio_group" "support" {
  name        = "${var.workspace}-support"
  description = "Customer support"
}

resource "permio_group_members" "admins" {
  group   = permio_group.admins.name
  members = var.admins
}

resource "permio_group_members" "engineering" {
  group   = permio_group.engineering.name
  members = var.engineers
}

resource "permio_group_members" "support" {
  group   = permio_group.support.name
  members = var.support
}

# --- Grants --------------------------------------------------------------------------------------
# One permio_grant per (principal, resource) pair. Grants on the workspace are inherited by every
# project and document below it.

resource "permio_grant" "admins" {
  principal = permio_group.admins.principal
  resource  = local.workspace_uri
  roles     = [permio_role.admin.id]
}

resource "permio_grant" "engineering" {
  principal = permio_group.engineering.principal
  resource  = local.workspace_uri
  roles     = [permio_role.editor.id]
}

# Engineering maintains the "platform" project only.
resource "permio_grant" "engineering_platform" {
  principal = permio_group.engineering.principal
  resource  = "${local.workspace_uri}/projects/platform"
  roles     = [permio_role.maintainer.id]
}

resource "permio_grant" "support" {
  principal = permio_group.support.principal
  resource  = local.workspace_uri
  roles     = [permio_role.viewer.id, permio_role.billing.id]
}

# A "_" segment matches any single segment: support can share the help-centre docs of every project.
resource "permio_grant" "support_help_centre" {
  principal   = permio_group.support.principal
  resource    = "${local.workspace_uri}/projects/_/help-centre"
  permissions = [permio_permission.document_share.name]
}

# An external auditor, granted directly rather than through a group.
resource "permio_grant" "auditor" {
  principal = "user_auditor"
  resource  = "${local.workspace_uri}/projects/finance"
  roles     = [permio_role.viewer.id]
}

# --- Policy tests --------------------------------------------------------------------------------
# Data sources are read during planning, so these evaluate grants that already exist: run them on
# the plan after the first apply (or in a terraform test run block).

data "permio_check" "engineer_can_delete_platform_docs" {
  principal   = tolist(var.engineers)[0]
  resource    = "${local.workspace_uri}/projects/platform/docs/1"
  permissions = ["document.delete"]
  depends_on  = [permio_grant.engineering_platform, permio_group_members.engineering]
}

data "permio_check" "support_cannot_manage_billing" {
  principal   = tolist(var.support)[0]
  resource    = local.workspace_uri
  permissions = ["billing.manage"]
  depends_on  = [permio_grant.support, permio_group_members.support]
}

check "workspace_policy" {
  assert {
    condition     = data.permio_check.engineer_can_delete_platform_docs.allowed
    error_message = "Engineers should be able to delete documents in the platform project."
  }
  assert {
    condition     = !data.permio_check.support_cannot_manage_billing.allowed
    error_message = "Support must not be able to manage billing."
  }
}

output "group_principals" {
  value = {
    admins      = permio_group.admins.principal
    engineering = permio_group.engineering.principal
    support     = permio_group.support.principal
  }
}
