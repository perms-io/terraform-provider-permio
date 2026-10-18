package provider

import (
	"regexp"
	"testing"

	pb "github.com/PrivateJAR/permio-go/proto/permissions/v1"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"

	"github.com/PrivateJAR/terraform-provider-permio/internal/fakeserver"
)

const dataSourceBase = `
resource "permio_permission" "read" {
  name        = "doc.read"
  description = "Read documents"
}
resource "permio_permission" "write" { name = "doc.write" }
resource "permio_permission" "bill" { name = "billing.view" }
resource "permio_role" "editor" {
  name        = "Editor"
  description = "Edits documents"
  permissions = [permio_permission.read.name, permio_permission.write.name]
}
resource "permio_group" "eng" {
  name        = "engineering"
  description = "Engineers"
}
resource "permio_group_members" "eng" {
  group   = permio_group.eng.name
  members = ["alice", "bob"]
}
resource "permio_grant" "eng" {
  principal = permio_group.eng.principal
  resource  = "/workspaces/acme"
  roles     = [permio_role.editor.id]
}
resource "permio_grant" "billing" {
  principal   = "carol"
  resource    = "/workspaces/_/billing"
  permissions = [permio_permission.bill.name]
}
`

func TestDataSources(t *testing.T) {
	e := newTestEnv(t)
	e.run(
		resource.TestStep{Config: e.config(dataSourceBase)},
		resource.TestStep{
			Config: e.config(dataSourceBase) + `
data "permio_permission" "read" {
  name     = "doc.read"
}
data "permio_role" "by_name" {
  name     = "Editor"
}
data "permio_role" "by_id" {
  id       = permio_role.editor.id
}
data "permio_group" "eng" {
  name     = "engineering"
}
# alice inherits Editor on everything under /workspaces/acme through the group.
data "permio_check" "alice_can_edit" {
  principal   = "alice"
  resource    = "/workspaces/acme/docs/1"
  permissions = ["doc.read", "doc.write"]
}
data "permio_check" "alice_cannot_bill" {
  principal   = "alice"
  resource    = "/workspaces/acme/docs/1"
  permissions = ["doc.read", "billing.view"]
}
# carol's wildcard grant covers every workspace's billing.
data "permio_check" "carol_billing" {
  principal   = "carol"
  resource    = "/workspaces/globex/billing/invoices"
  permissions = ["billing.view"]
}
data "permio_check" "group_itself" {
  principal   = "group:engineering"
  resource    = "/workspaces/acme"
  permissions = ["doc.write"]
}
`,
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttr("data.permio_permission.read", "description", "Read documents"),
				resource.TestCheckResourceAttrPair("data.permio_permission.read", "id", "permio_permission.read", "id"),

				resource.TestCheckResourceAttrPair("data.permio_role.by_name", "id", "permio_role.editor", "id"),
				resource.TestCheckResourceAttr("data.permio_role.by_name", "description", "Edits documents"),
				resource.TestCheckResourceAttr("data.permio_role.by_name", "permissions.#", "2"),
				resource.TestCheckResourceAttr("data.permio_role.by_id", "name", "Editor"),

				resource.TestCheckResourceAttr("data.permio_group.eng", "principal", "group:engineering"),
				resource.TestCheckResourceAttr("data.permio_group.eng", "description", "Engineers"),
				resource.TestCheckResourceAttr("data.permio_group.eng", "members.#", "2"),
				resource.TestCheckTypeSetElemAttr("data.permio_group.eng", "members.*", "alice"),

				resource.TestCheckResourceAttr("data.permio_check.alice_can_edit", "allowed", "true"),
				resource.TestCheckResourceAttr("data.permio_check.alice_can_edit", "missing.#", "0"),
				resource.TestCheckResourceAttr("data.permio_check.alice_cannot_bill", "allowed", "false"),
				resource.TestCheckResourceAttr("data.permio_check.alice_cannot_bill", "missing.#", "1"),
				resource.TestCheckTypeSetElemAttr("data.permio_check.alice_cannot_bill", "missing.*", "billing.view"),
				resource.TestCheckResourceAttr("data.permio_check.carol_billing", "allowed", "true"),
				resource.TestCheckResourceAttr("data.permio_check.group_itself", "allowed", "true"),
			),
		},
	)
}

// Data sources work with a check-only API key.
func TestDataSources_checkOnlyKey(t *testing.T) {
	e := newTestEnv(t)
	_, err := e.client.API.CreatePermission(ctx(), &pb.CreatePermissionRequest{ProjectName: "default", Name: "doc.read", Description: "Read"})
	e.must(err)
	_, err = e.client.API.CreateRole(ctx(), &pb.CreateRoleRequest{ProjectName: "default", Name: "Reader", Permissions: []string{"doc.read"}})
	e.must(err)
	_, err = e.client.API.CreateGroup(ctx(), &pb.CreateGroupRequest{ProjectName: "default", Name: "eng"})
	e.must(err)
	e.run(resource.TestStep{
		Config: e.configWithKey(fakeserver.CheckOnlyKey, `
data "permio_permission" "read" { name = "doc.read" }
data "permio_role" "reader" { name = "Reader" }
data "permio_group" "eng" { name = "eng" }
data "permio_check" "x" {
  principal   = "alice"
  resource    = "/docs/1"
  permissions = ["doc.read"]
}`),
		Check: resource.ComposeAggregateTestCheckFunc(
			resource.TestCheckResourceAttr("data.permio_permission.read", "description", "Read"),
			resource.TestCheckResourceAttr("data.permio_role.reader", "permissions.#", "1"),
			resource.TestCheckResourceAttr("data.permio_group.eng", "members.#", "0"),
			resource.TestCheckResourceAttr("data.permio_check.x", "allowed", "false"),
			resource.TestCheckTypeSetElemAttr("data.permio_check.x", "missing.*", "doc.read"),
		),
	})
}

func TestDataSources_notFound(t *testing.T) {
	e := newTestEnv(t)
	e.run(resource.TestStep{
		Config:      e.config(`data "permio_role" "x" { name = "Nope" }`),
		ExpectError: regexp.MustCompile(`Role not found`),
	})
	e.run(resource.TestStep{
		Config:      e.config(`data "permio_group" "x" { name = "nope" }`),
		ExpectError: regexp.MustCompile(`group not found`),
	})
	e.run(resource.TestStep{
		Config: e.config(`data "permio_role" "x" {
  name = "a"
  id   = "b"
}`),
		ExpectError: regexp.MustCompile(`Invalid Attribute Combination`),
	})
}
