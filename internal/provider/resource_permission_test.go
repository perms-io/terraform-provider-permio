package provider

import (
	"fmt"
	"regexp"
	"strings"
	"testing"

	pb "github.com/PrivateJAR/permio-go/proto/permissions/v1"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"google.golang.org/grpc/codes"
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

// Destroying a permission removes it from the roles that contain it (the API does not), so they stay readable.
func TestPermission_destroyRemovesFromRoles(t *testing.T) {
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
		// doc.write is now the role's only permission, so it cannot be removed from it.
		resource.TestStep{
			Config:      e.config(``),
			ExpectError: regexp.MustCompile(`(?s)only\s+permission\s+of\s+role\s+"Outside".*needs\s+at\s+least\s+one`),
		},
		resource.TestStep{
			PreConfig: func() {
				e.must(e.checkPermission("doc.write", "")(nil))
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

// The roles that lose the permission are named in a warning.
func TestPermission_destroyWarnsAboutRoles(t *testing.T) {
	e := newTestEnv(t)
	for _, n := range []string{"doc.read", "doc.write"} {
		_, err := e.client.API.CreatePermission(ctx(), &pb.CreatePermissionRequest{ProjectName: "default", Name: n})
		e.must(err)
	}
	_, err := e.client.API.CreateRole(ctx(), &pb.CreateRoleRequest{ProjectName: "default", Name: "Editor", Permissions: []string{"doc.read", "doc.write"}})
	e.must(err)
	r := &permissionResource{pd: &providerData{client: e.client, project: "default"}}

	// Not planned as a destroy (a replacement): refused, and nothing changes.
	var diags diag.Diagnostics
	if r.deleteChecked(ctx(), "default", "doc.read", false, &diags) || !diags.HasError() || !strings.Contains(diags[0].Detail(), `"Editor"`) {
		t.Fatalf("replacement: diagnostics = %v, want an error naming the role", diags)
	}
	e.must(e.checkRole("Editor", "doc.read", "doc.write")(nil))
	e.must(e.checkPermission("doc.read", "")(nil))

	// A destroy: removed from the role, with a warning.
	diags = nil
	if !r.deleteChecked(ctx(), "default", "doc.read", true, &diags) || diags.HasError() || diags.WarningsCount() != 1 {
		t.Fatalf("destroy: diagnostics = %v, want one warning", diags)
	}
	if w := diags.Warnings()[0]; !strings.Contains(w.Detail(), `role "Editor"`) || !strings.Contains(w.Detail(), `"doc.read"`) {
		t.Errorf("warning = %q", w.Detail())
	}
	e.must(e.checkRole("Editor", "doc.write")(nil))
	e.must(e.checkNoPermission("doc.read")(nil))
}

// Removing a permission from a managed role and deleting the permission in the same apply works. (Terraform
// destroys the permission before it updates the role.)
func TestPermission_deleteAndRoleUpdateInOneApply(t *testing.T) {
	e := newTestEnv(t)
	after := e.config(`
resource "permio_permission" "write" { name = "doc.write" }
resource "permio_role" "editor" {
  name        = "Editor"
  permissions = [permio_permission.write.name]
}`)
	e.run(
		resource.TestStep{
			Config: e.config(`
resource "permio_permission" "read" { name = "doc.read" }
resource "permio_permission" "write" { name = "doc.write" }
resource "permio_role" "editor" {
  name        = "Editor"
  permissions = [permio_permission.read.name, permio_permission.write.name]
}`),
		},
		resource.TestStep{
			Config: after,
			Check: resource.ComposeAggregateTestCheckFunc(
				e.checkRole("Editor", "doc.write"),
				e.checkNoPermission("doc.read"),
			),
		},
		resource.TestStep{
			Config: after,
			ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
				plancheck.ExpectEmptyPlan(),
			}},
		},
	)
}

// Replacing a permission that managed roles use fails clearly instead of stripping it from the roles.
func TestPermission_replaceRefusedWhileRolesUseIt(t *testing.T) {
	e := newTestEnv(t)
	cfg := e.config(`
resource "permio_permission" "read" { name = "doc.read" }
resource "permio_permission" "write" { name = "doc.write" }
resource "permio_role" "editor" {
  name        = "Editor"
  permissions = [permio_permission.read.name, permio_permission.write.name]
}
resource "permio_role" "reader" {
  name        = "Reader"
  permissions = [permio_permission.read.name]
  depends_on  = [permio_role.editor]
}`)
	e.run(
		resource.TestStep{Config: cfg},
		resource.TestStep{
			Taint:       []string{"permio_permission.read"},
			Config:      cfg,
			ExpectError: regexp.MustCompile(`(?s)Permission is still used by roles.*being\s+replaced.*"Editor".*"Reader".*\(its\s+only\s+permission\)`),
		},
		// Nothing was taken away from the roles.
		resource.TestStep{
			PreConfig: func() {
				e.must(e.checkRole("Editor", "doc.read", "doc.write")(nil))
				e.must(e.checkRole("Reader", "doc.read")(nil))
				e.must(e.checkPermission("doc.read", "")(nil))
			},
			Config:             cfg,
			PlanOnly:           true,
			ExpectNonEmptyPlan: true, // still tainted
		},
	)
}

// renameCfg is a permission used by a role, under the given name.
func renameCfg(e *testEnv, name string) string { return e.config(renameBody(name)) }

func renameBody(name string) string {
	return fmt.Sprintf(`
resource "permio_permission" "read" { name = %q }
resource "permio_permission" "write" { name = "doc.write" }
resource "permio_role" "editor" {
  name        = "Editor"
  permissions = [permio_permission.read.name, permio_permission.write.name]
}`, name)
}

// A rename that creates the new permission, moves roles and deletes the old one can fail part way. The next apply
// recognises the permission it created and finishes the job.
func TestPermission_renameRecoversFromPartialFailure(t *testing.T) {
	for _, failing := range []string{"UpdateRole", "DeletePermission"} {
		t.Run(failing, func(t *testing.T) {
			e := newTestEnv(t)
			var firstID string
			e.run(
				resource.TestStep{
					Config: renameCfg(e, "doc.read"),
					Check: func(s *tfState) error {
						firstID = s.RootModule().Resources["permio_permission.read"].Primary.ID
						return nil
					},
				},
				resource.TestStep{
					PreConfig:   func() { e.fake.FailNext(failing, codes.Unavailable) },
					Config:      renameCfg(e, "document.read"),
					ExpectError: regexp.MustCompile(`(?s)Both\s+"doc.read"\s+and\s+"document.read"\s+exist.\s+Run\s+apply\s+again\s+to\s+finish\s+the\s+rename`),
				},
				resource.TestStep{
					Config: renameCfg(e, "document.read"),
					ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction("permio_permission.read", plancheck.ResourceActionUpdate),
					}},
					Check: resource.ComposeAggregateTestCheckFunc(
						e.checkRole("Editor", "document.read", "doc.write"),
						e.checkNoPermission("doc.read"),
						e.checkPermission("document.read", ""),
						resource.TestCheckResourceAttr("permio_permission.read", "name", "document.read"),
						func(s *tfState) error {
							if id := s.RootModule().Resources["permio_permission.read"].Primary.ID; id == firstID {
								return fmt.Errorf("ID %s did not change to the new permission's", id)
							}
							return nil
						},
					),
				},
				// Converged.
				resource.TestStep{
					Config: renameCfg(e, "document.read"),
					ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					}},
				},
			)
		})
	}
}

// If the old permission is gone by the next refresh (its delete went through after all), the resource follows the
// permission the rename created instead of disappearing from state.
func TestPermission_renameRecoversWhenOldPermissionIsGone(t *testing.T) {
	e := newTestEnv(t)
	e.run(
		resource.TestStep{Config: renameCfg(e, "doc.read")},
		resource.TestStep{
			PreConfig:   func() { e.fake.FailNext("DeletePermission", codes.Unavailable) },
			Config:      renameCfg(e, "document.read"),
			ExpectError: regexp.MustCompile(`Run\s+apply\s+again\s+to\s+finish\s+the\s+rename`),
		},
		resource.TestStep{
			PreConfig: func() {
				_, err := e.client.API.DeletePermission(ctx(), &pb.DeletePermissionRequest{ProjectName: "default", Name: "doc.read"})
				e.must(err)
			},
			Config: renameCfg(e, "document.read"),
			ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
				plancheck.ExpectEmptyPlan(),
			}},
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttr("permio_permission.read", "name", "document.read"),
				e.checkRole("Editor", "document.read", "doc.write"),
			),
		},
	)
}

// While a rename is unfinished, renaming to a third name is refused with instructions.
func TestPermission_renameToAnotherNameWhileUnfinished(t *testing.T) {
	e := newTestEnv(t)
	e.run(
		resource.TestStep{Config: renameCfg(e, "doc.read")},
		resource.TestStep{
			PreConfig:   func() { e.fake.FailNext("DeletePermission", codes.Unavailable) },
			Config:      renameCfg(e, "document.read"),
			ExpectError: regexp.MustCompile(`Run\s+apply\s+again\s+to\s+finish\s+the\s+rename`),
		},
		resource.TestStep{
			Config:      renameCfg(e, "documents.read"),
			ExpectError: regexp.MustCompile(`(?s)An earlier rename did not finish.*Set\s+name\s+to\s+"document.read"`),
		},
		resource.TestStep{
			Config: renameCfg(e, "document.read"),
			Check: resource.ComposeAggregateTestCheckFunc(
				e.checkRole("Editor", "document.read", "doc.write"),
				e.checkNoPermission("doc.read"),
				e.checkNoPermission("documents.read"),
			),
		},
	)
}

// Renaming to the name of a permission that something else manages must fail, not take it over: CreatePermission
// would silently return the existing permission.
func TestPermission_renameRefusesExistingPermission(t *testing.T) {
	cases := map[string]string{
		"used by a role": renameBody("doc.read"),
		"unused": `
resource "permio_permission" "read" { name = "doc.read" }`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			e := newTestEnv(t)
			renamed := strings.Replace(body, `"doc.read"`, `"document.read"`, 1)
			var foreignID string
			e.run(
				resource.TestStep{Config: e.config(body)},
				resource.TestStep{
					PreConfig: func() {
						p, err := e.client.API.CreatePermission(ctx(), &pb.CreatePermissionRequest{ProjectName: "default", Name: "document.read"})
						e.must(err)
						foreignID = p.GetId()
					},
					Config:      e.config(renamed),
					ExpectError: regexp.MustCompile(`(?s)Permission already exists.*"document.read"\s+already\s+exists\s+in\s+project\s+"default".*not\s+created\s+by\s+this\s+resource.*terraform\s+import\s+<address>\s+default/document.read`),
				},
				// Nothing changed: the old permission and its role are as they were, and the other permission is untouched.
				resource.TestStep{
					PreConfig: func() {
						e.must(e.checkPermission("doc.read", "")(nil))
						p, err := e.client.API.GetPermission(ctx(), &pb.GetPermissionRequest{ProjectName: "default", Name: "document.read"})
						e.must(err)
						if p.GetId() != foreignID {
							t.Fatalf("document.read was replaced")
						}
						if strings.Contains(body, "Editor") {
							e.must(e.checkRole("Editor", "doc.read", "doc.write")(nil))
						}
					},
					Config: e.config(body),
					ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					}},
				},
			)
		})
	}
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
		ExpectError: regexp.MustCompile(`not\s+a\s+valid\s+project\s+name`),
	})
}
