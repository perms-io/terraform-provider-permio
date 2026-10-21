package provider

import (
	"fmt"
	"regexp"
	"strings"
	"testing"

	pb "github.com/PrivateJAR/permio-go/proto/permissions/v1"
	"github.com/hashicorp/terraform-plugin-framework-timeouts/resource/timeouts"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	fwresource "github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
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
		// The project is required, because role names can contain "/".
		resource.TestStep{
			ResourceName: "permio_role.editor", ImportState: true,
			ImportStateIdFunc: func(*terraform.State) (string, error) { return id, nil },
			ExpectError:       regexp.MustCompile(`the\s+project\s+is\s+missing`),
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

// A permission that a role contains is deleted outside Terraform. The API keeps referring to it from the role,
// GetRole then fails and the role list leaves it out, and the API rejects every change to the role until the
// permission exists again. The plan must not try (and fail) to change the role forever, and errors must name the
// permission and say how to fix it.
func TestRole_deletedPermission(t *testing.T) {
	e := newTestEnv(t)
	roleCfg := func(desc string, perms ...string) string {
		return e.config(fmt.Sprintf(`
resource "permio_role" "editor" {
  name        = "Editor"
  description = %q
  permissions = ["%s"]
}`, desc, strings.Join(perms, `", "`)))
	}
	brokenErr := regexp.MustCompile(`(?s)refers\s+to\s+the\s+permission\(s\)\s+"doc.write",\s+which\s+no\s+longer\s+exist.*recreate\s+the\s+permission`)
	e.run(
		resource.TestStep{
			PreConfig: func() {
				for _, n := range []string{"doc.read", "doc.write"} {
					_, err := e.client.API.CreatePermission(ctx(), &pb.CreatePermissionRequest{ProjectName: "default", Name: n})
					e.must(err)
				}
			},
			Config: roleCfg("", "doc.read", "doc.write"),
		},
		// Deleted out of band. The plan stays empty: the deleted permission stays in the role's state.
		resource.TestStep{
			PreConfig: func() {
				_, err := e.client.API.DeletePermission(ctx(), &pb.DeletePermissionRequest{ProjectName: "default", Name: "doc.write"})
				e.must(err)
			},
			Config: roleCfg("", "doc.read", "doc.write"),
			ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
				plancheck.ExpectEmptyPlan(),
			}},
			Check: resource.TestCheckResourceAttr("permio_role.editor", "permissions.#", "2"),
		},
		// Any change to the role fails with an error that names the permission and says what to do.
		resource.TestStep{
			Config:      roleCfg("changed", "doc.read", "doc.write"),
			ExpectError: brokenErr,
		},
		resource.TestStep{
			Config:      roleCfg("", "doc.read"),
			ExpectError: brokenErr,
		},
		// Recreating the permission fixes the role.
		resource.TestStep{
			PreConfig: func() {
				_, err := e.client.API.CreatePermission(ctx(), &pb.CreatePermissionRequest{ProjectName: "default", Name: "doc.write"})
				e.must(err)
			},
			Config: roleCfg("changed", "doc.read", "doc.write"),
			Check:  e.checkRole("Editor", "doc.read", "doc.write"),
		},
		resource.TestStep{
			Config: roleCfg("changed", "doc.read"),
			Check:  e.checkRole("Editor", "doc.read"),
		},
	)
}

// Reading such a role reports a warning that names the deleted permission.
func TestRole_readWarnsAboutDeletedPermission(t *testing.T) {
	e := newTestEnv(t)
	for _, n := range []string{"doc.read", "doc.write"} {
		_, err := e.client.API.CreatePermission(ctx(), &pb.CreatePermissionRequest{ProjectName: "default", Name: n})
		e.must(err)
	}
	role, err := e.client.API.CreateRole(ctx(), &pb.CreateRoleRequest{ProjectName: "default", Name: "Editor", Permissions: []string{"doc.read", "doc.write"}})
	e.must(err)
	_, err = e.client.API.DeletePermission(ctx(), &pb.DeletePermissionRequest{ProjectName: "default", Name: "doc.write"})
	e.must(err)

	// The fake behaves like the real service.
	if _, err := e.client.API.GetRole(ctx(), &pb.GetRoleRequest{ProjectName: "default", Id: role.GetId()}); err == nil {
		t.Fatal("GetRole succeeded for a role that refers to a deleted permission")
	}
	e.must(e.checkRole("Editor", "doc.read")(nil))

	r := &roleResource{pd: &providerData{client: e.client, project: "default"}}
	var schemaResp fwresource.SchemaResponse
	r.Schema(ctx(), fwresource.SchemaRequest{}, &schemaResp)
	read := func(known ...string) (*fwresource.ReadResponse, roleModel) {
		state := tfsdk.State{Schema: schemaResp.Schema}
		e.must(diagErr(state.Set(ctx(), &roleModel{
			ID: types.StringValue(role.GetId()), Project: types.StringValue("default"), Name: types.StringValue("Editor"),
			Description: types.StringValue(""), Permissions: stringsToSet(known),
			Timeouts: timeouts.Value{Object: types.ObjectNull(map[string]attr.Type{
				"create": types.StringType, "read": types.StringType, "update": types.StringType, "delete": types.StringType,
			})},
		})))
		resp := &fwresource.ReadResponse{State: state}
		r.Read(ctx(), fwresource.ReadRequest{State: state}, resp)
		var got roleModel
		e.must(diagErr(resp.State.Get(ctx(), &got)))
		return resp, got
	}

	resp, got := read("doc.read", "doc.write")
	if resp.Diagnostics.HasError() || resp.Diagnostics.WarningsCount() != 1 {
		t.Fatalf("diagnostics = %v, want one warning", resp.Diagnostics)
	}
	w := resp.Diagnostics.Warnings()[0]
	if w.Summary() != brokenRoleSummary || !strings.Contains(w.Detail(), `"doc.write", which no longer exist`) || !strings.Contains(w.Detail(), "recreate the permission") {
		t.Errorf("warning = %q: %q", w.Summary(), w.Detail())
	}
	if perms := setToStrings(ctx(), got.Permissions, &resp.Diagnostics); strings.Join(perms, ",") != "doc.read,doc.write" {
		t.Errorf("permissions in state = %v, want the deleted one kept", perms)
	}

	// Without a prior state (after an import), the API cannot say which permission is missing.
	resp, _ = read()
	if resp.Diagnostics.WarningsCount() != 1 || !strings.Contains(resp.Diagnostics.Warnings()[0].Detail(), "at least one permission that no longer exists") {
		t.Errorf("diagnostics = %v, want a warning about an unnamed permission", resp.Diagnostics)
	}
}
