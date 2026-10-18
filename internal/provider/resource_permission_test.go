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

func TestPermission_lifecycle(t *testing.T) {
	e := newTestEnv(t)
	var firstID string
	e.run(
		// Create.
		resource.TestStep{
			Config: e.config(`
resource "permio_permission" "read" {
  name        = "document.read"
  description = "Read documents"
}`),
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttr("permio_permission.read", "project", "default"),
				resource.TestCheckResourceAttr("permio_permission.read", "name", "document.read"),
				resource.TestCheckResourceAttrSet("permio_permission.read", "id"),
				func(s *terraform.State) error {
					firstID = s.RootModule().Resources["permio_permission.read"].Primary.ID
					return nil
				},
				e.checkPermission("document.read", "Read documents"),
			),
		},
		// Update the description in place.
		resource.TestStep{
			Config: e.config(`
resource "permio_permission" "read" {
  name        = "document.read"
  description = "Read any document"
}`),
			ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
				plancheck.ExpectResourceAction("permio_permission.read", plancheck.ResourceActionUpdate),
			}},
			Check: e.checkPermission("document.read", "Read any document"),
		},
		// Rename in place: no role uses it, so the API rename keeps the ID.
		resource.TestStep{
			Config: e.config(`
resource "permio_permission" "read" {
  name        = "doc.read"
  description = "Read any document"
}`),
			ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
				plancheck.ExpectResourceAction("permio_permission.read", plancheck.ResourceActionUpdate),
			}},
			Check: resource.ComposeAggregateTestCheckFunc(
				e.checkPermission("doc.read", "Read any document"),
				e.checkNoPermission("document.read"),
				func(s *terraform.State) error {
					if id := s.RootModule().Resources["permio_permission.read"].Primary.ID; id != firstID {
						return fmt.Errorf("rename changed the ID from %s to %s", firstID, id)
					}
					return nil
				},
			),
		},
		// Import by "<project>/<name>" and by "<name>".
		resource.TestStep{
			ResourceName:            "permio_permission.read",
			ImportState:             true,
			ImportStateId:           "default/doc.read",
			ImportStateVerify:       true,
			ImportStateVerifyIgnore: []string{"timeouts"},
		},
		resource.TestStep{
			ResourceName:            "permio_permission.read",
			ImportState:             true,
			ImportStateId:           "doc.read",
			ImportStateVerify:       true,
			ImportStateVerifyIgnore: []string{"timeouts"},
		},
		// Drift: deleted out of band, so it is planned for creation again.
		resource.TestStep{
			PreConfig: func() {
				_, err := e.client.API.DeletePermission(ctx(), &pb.DeletePermissionRequest{ProjectName: "default", Name: "doc.read"})
				e.must(err)
			},
			Config: e.config(`
resource "permio_permission" "read" {
  name        = "doc.read"
  description = "Read any document"
}`),
			ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
				plancheck.ExpectResourceAction("permio_permission.read", plancheck.ResourceActionCreate),
			}},
			Check: e.checkPermission("doc.read", "Read any document"),
		},
		// Drift: description changed out of band, so it is planned for update.
		resource.TestStep{
			PreConfig: func() {
				_, err := e.client.API.UpdatePermission(ctx(), &pb.UpdatePermissionRequest{ProjectName: "default", Name: "doc.read", Description: "changed"})
				e.must(err)
			},
			Config: e.config(`
resource "permio_permission" "read" {
  name        = "doc.read"
  description = "Read any document"
}`),
			ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
				plancheck.ExpectResourceAction("permio_permission.read", plancheck.ResourceActionUpdate),
			}},
			Check: e.checkPermission("doc.read", "Read any document"),
		},
	)
	// Destroyed at the end of the test case.
	if err := e.checkNoPermission("doc.read")(nil); err != nil {
		t.Fatal(err)
	}
}

func TestPermission_renameMovesRoles(t *testing.T) {
	e := newTestEnv(t)
	e.run(
		resource.TestStep{
			Config: e.config(`
resource "permio_permission" "read" { name = "doc.read" }
resource "permio_permission" "write" { name = "doc.write" }
resource "permio_role" "editor" {
  name        = "Editor"
  permissions = [permio_permission.read.name, permio_permission.write.name]
}`),
			Check: e.checkRole("Editor", "doc.read", "doc.write"),
		},
		resource.TestStep{
			// A role outside Terraform also uses the permission.
			PreConfig: func() {
				_, err := e.client.API.CreateRole(ctx(), &pb.CreateRoleRequest{ProjectName: "default", Name: "Reader", Permissions: []string{"doc.read"}})
				e.must(err)
			},
			Config: e.config(`
resource "permio_permission" "read" { name = "document.read" }
resource "permio_permission" "write" { name = "doc.write" }
resource "permio_role" "editor" {
  name        = "Editor"
  permissions = [permio_permission.read.name, permio_permission.write.name]
}`),
			Check: resource.ComposeAggregateTestCheckFunc(
				e.checkRole("Editor", "document.read", "doc.write"),
				e.checkRole("Reader", "document.read"),
				e.checkNoPermission("doc.read"),
				e.checkPermission("document.read", ""),
			),
		},
		// Clean up the role made outside Terraform, so that the permission can be destroyed.
		resource.TestStep{
			PreConfig: func() {
				r, err := e.client.FindRoleByName(ctx(), "default", "Reader")
				e.must(err)
				_, err = e.client.API.DeleteRole(ctx(), &pb.DeleteRoleRequest{ProjectName: "default", Id: r.GetId()})
				e.must(err)
			},
			Config: e.config(`
resource "permio_permission" "read" { name = "document.read" }
resource "permio_permission" "write" { name = "doc.write" }
resource "permio_role" "editor" {
  name        = "Editor"
  permissions = [permio_permission.read.name, permio_permission.write.name]
}`),
		},
	)
}

func TestPermission_deleteRemovesFromRoles(t *testing.T) {
	e := newTestEnv(t)
	e.run(
		resource.TestStep{
			Config: e.config(`
resource "permio_permission" "read" { name = "doc.read" }
resource "permio_permission" "write" { name = "doc.write" }`),
		},
		resource.TestStep{
			PreConfig: func() {
				_, err := e.client.API.CreateRole(ctx(), &pb.CreateRoleRequest{ProjectName: "default", Name: "Outside", Permissions: []string{"doc.read", "doc.write"}})
				e.must(err)
			},
			Config: e.config(`resource "permio_permission" "write" { name = "doc.write" }`),
			Check: resource.ComposeAggregateTestCheckFunc(
				e.checkNoPermission("doc.read"),
				e.checkRole("Outside", "doc.write"), // still readable, without the deleted permission
			),
		},
		resource.TestStep{
			// doc.write is now the role's only permission, so it cannot be removed from it.
			Config:      e.config(``),
			ExpectError: regexp.MustCompile(`only permission of role`),
		},
		resource.TestStep{
			PreConfig: func() {
				r, err := e.client.FindRoleByName(ctx(), "default", "Outside")
				e.must(err)
				_, err = e.client.API.DeleteRole(ctx(), &pb.DeleteRoleRequest{ProjectName: "default", Id: r.GetId()})
				e.must(err)
			},
			Config: e.config(``),
			Check:  e.checkNoPermission("doc.write"),
		},
	)
}

func TestPermission_alreadyExists(t *testing.T) {
	e := newTestEnv(t)
	_, err := e.client.API.CreatePermission(ctx(), &pb.CreatePermissionRequest{ProjectName: "default", Name: "doc.read"})
	e.must(err)
	e.run(resource.TestStep{
		Config:      e.config(`resource "permio_permission" "read" { name = "doc.read" }`),
		ExpectError: regexp.MustCompile(`(?s)already exists.*terraform import <address> default/doc.read`),
	})
}

func TestPermission_validation(t *testing.T) {
	e := newTestEnv(t)
	for _, name := range []string{"has space", "", "a/b"} {
		e.run(resource.TestStep{
			Config:      e.config(fmt.Sprintf(`resource "permio_permission" "x" { name = %q }`, name)),
			PlanOnly:    true,
			ExpectError: regexp.MustCompile(`Invalid Attribute Value`),
		})
	}
	e.run(resource.TestStep{
		Config: e.config(`resource "permio_permission" "x" {
  project = "Not_Valid"
  name    = "ok"
}`),
		PlanOnly:    true,
		ExpectError: regexp.MustCompile(`lower-case letters, digits and hyphens`),
	})
}
