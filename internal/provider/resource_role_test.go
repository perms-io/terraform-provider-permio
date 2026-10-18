package provider

import (
	"fmt"
	"regexp"
	"testing"

	pb "github.com/PrivateJAR/permio-go/proto/permissions/v1"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

const rolePermissions = `
resource "permio_permission" "read" { name = "doc.read" }
resource "permio_permission" "write" { name = "doc.write" }
resource "permio_permission" "delete" { name = "doc.delete" }
`

func TestRole_lifecycle(t *testing.T) {
	e := newTestEnv(t)
	var id string
	e.run(
		resource.TestStep{
			Config: e.config(rolePermissions + `
resource "permio_role" "editor" {
  name        = "Editor"
  description = "Edits documents"
  permissions = [permio_permission.read.name, permio_permission.write.name]
}`),
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttrSet("permio_role.editor", "id"),
				resource.TestCheckResourceAttr("permio_role.editor", "permissions.#", "2"),
				resource.TestCheckTypeSetElemAttr("permio_role.editor", "permissions.*", "doc.read"),
				func(s *terraform.State) error {
					id = s.RootModule().Resources["permio_role.editor"].Primary.ID
					return nil
				},
				e.checkRole("Editor", "doc.read", "doc.write"),
			),
		},
		// Rename and change permissions in place.
		resource.TestStep{
			Config: e.config(rolePermissions + `
resource "permio_role" "editor" {
  name        = "Document editor"
  description = "Edits and deletes documents"
  permissions = [permio_permission.read.name, permio_permission.write.name, permio_permission.delete.name]
}`),
			ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
				plancheck.ExpectResourceAction("permio_role.editor", plancheck.ResourceActionUpdate),
			}},
			Check: resource.ComposeAggregateTestCheckFunc(
				e.checkRole("Document editor", "doc.read", "doc.write", "doc.delete"),
				func(s *terraform.State) error {
					if got := s.RootModule().Resources["permio_role.editor"].Primary.ID; got != id {
						return fmt.Errorf("role ID changed from %s to %s", id, got)
					}
					return nil
				},
			),
		},
		// Import by ID, by "<project>/<id>" and by name.
		resource.TestStep{
			ResourceName: "permio_role.editor", ImportState: true, ImportStateVerify: true,
			ImportStateIdFunc:       func(*terraform.State) (string, error) { return id, nil },
			ImportStateVerifyIgnore: []string{"timeouts"},
		},
		resource.TestStep{
			ResourceName: "permio_role.editor", ImportState: true, ImportStateVerify: true,
			ImportStateIdFunc:       func(*terraform.State) (string, error) { return "default/" + id, nil },
			ImportStateVerifyIgnore: []string{"timeouts"},
		},
		resource.TestStep{
			ResourceName: "permio_role.editor", ImportState: true, ImportStateVerify: true,
			ImportStateId:           "default/Document editor",
			ImportStateVerifyIgnore: []string{"timeouts"},
		},
		// Drift: permissions changed out of band are put back.
		resource.TestStep{
			PreConfig: func() {
				_, err := e.client.API.UpdateRole(ctx(), &pb.UpdateRoleRequest{ProjectName: "default", Id: id, Name: "Document editor", Description: "Edits and deletes documents", Permissions: []string{"doc.read"}})
				e.must(err)
			},
			Config: e.config(rolePermissions + `
resource "permio_role" "editor" {
  name        = "Document editor"
  description = "Edits and deletes documents"
  permissions = [permio_permission.read.name, permio_permission.write.name, permio_permission.delete.name]
}`),
			ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
				plancheck.ExpectResourceAction("permio_role.editor", plancheck.ResourceActionUpdate),
			}},
			Check: e.checkRole("Document editor", "doc.read", "doc.write", "doc.delete"),
		},
		// Drift: deleted out of band, so it is created again.
		resource.TestStep{
			PreConfig: func() {
				_, err := e.client.API.DeleteRole(ctx(), &pb.DeleteRoleRequest{ProjectName: "default", Id: id})
				e.must(err)
			},
			Config: e.config(rolePermissions + `
resource "permio_role" "editor" {
  name        = "Document editor"
  description = "Edits and deletes documents"
  permissions = [permio_permission.read.name, permio_permission.write.name, permio_permission.delete.name]
}`),
			ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
				plancheck.ExpectResourceAction("permio_role.editor", plancheck.ResourceActionCreate),
			}},
			Check: e.checkRole("Document editor", "doc.read", "doc.write", "doc.delete"),
		},
	)
	roles, err := e.client.ListAllRoles(ctx(), "default", "")
	e.must(err)
	if len(roles) != 0 {
		t.Fatalf("roles left after destroy: %v", roles)
	}
}

func TestRole_validation(t *testing.T) {
	e := newTestEnv(t)
	e.run(resource.TestStep{
		Config: e.config(`resource "permio_role" "x" {
  name        = "Empty"
  permissions = []
}`),
		PlanOnly:    true,
		ExpectError: regexp.MustCompile(`at least 1`),
	})
	e.run(resource.TestStep{
		Config: e.config(`resource "permio_role" "x" {
  name        = "Missing"
  permissions = ["does.not.exist"]
}`),
		ExpectError: regexp.MustCompile(`specified permissions not\s+found`),
	})
}

func TestRole_alreadyExists(t *testing.T) {
	e := newTestEnv(t)
	_, err := e.client.API.CreatePermission(ctx(), &pb.CreatePermissionRequest{ProjectName: "default", Name: "doc.read"})
	e.must(err)
	_, err = e.client.API.CreateRole(ctx(), &pb.CreateRoleRequest{ProjectName: "default", Name: "Reader", Permissions: []string{"doc.read"}})
	e.must(err)
	e.run(resource.TestStep{
		Config: e.config(`resource "permio_role" "x" {
  name        = "Reader"
  permissions = ["doc.read"]
}`),
		ExpectError: regexp.MustCompile(`Role already exists`),
	})
}
