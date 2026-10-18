package provider

import (
	"fmt"
	"regexp"
	"slices"
	"testing"

	pb "github.com/PrivateJAR/permio-go/proto/permissions/v1"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
)

const grantBase = `
resource "permio_permission" "read" { name = "doc.read" }
resource "permio_permission" "write" { name = "doc.write" }
resource "permio_permission" "share" { name = "doc.share" }
resource "permio_role" "viewer" {
  name        = "Viewer"
  permissions = [permio_permission.read.name]
}
resource "permio_role" "editor" {
  name        = "Editor"
  permissions = [permio_permission.read.name, permio_permission.write.name]
}
`

func TestGrant_lifecycleAndDiffs(t *testing.T) {
	e := newTestEnv(t)
	grantCfg := func(roles, perms string) string {
		return e.config(grantBase + fmt.Sprintf(`
resource "permio_grant" "alice" {
  principal   = "alice"
  resource    = "/workspaces/acme"
  roles       = %s
  permissions = %s
}`, roles, perms))
	}
	none := func() []string { return nil }
	var grantsBefore, revokesBefore int
	counts := func() {
		grantsBefore, revokesBefore = e.fake.Calls("GrantUserPermissionsAndRolesOnResource"), e.fake.Calls("RevokeUserPermissionsAndRolesOnResource")
	}
	expectCalls := func(grants, revokes int) resource.TestCheckFunc {
		return func(*tfState) error {
			g := e.fake.Calls("GrantUserPermissionsAndRolesOnResource") - grantsBefore
			r := e.fake.Calls("RevokeUserPermissionsAndRolesOnResource") - revokesBefore
			if g != grants || r != revokes {
				return fmt.Errorf("got %d grant and %d revoke calls, want %d and %d", g, r, grants, revokes)
			}
			return nil
		}
	}

	e.run(
		resource.TestStep{
			PreConfig: counts,
			Config:    grantCfg(`[permio_role.viewer.id]`, `[permio_permission.share.name]`),
			Check: resource.ComposeAggregateTestCheckFunc(
				e.checkGrant("alice", "/workspaces/acme", []string{"doc.share"}, e.roleID("Viewer")),
				resource.TestCheckResourceAttr("permio_grant.alice", "id", "default|alice|/workspaces/acme"),
				expectCalls(1, 0),
			),
		},
		// Swap a role and drop the direct permission: one grant (the new role) and one revoke (the rest).
		resource.TestStep{
			PreConfig: counts,
			Config:    grantCfg(`[permio_role.editor.id]`, `[]`),
			ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
				plancheck.ExpectResourceAction("permio_grant.alice", plancheck.ResourceActionUpdate),
			}},
			Check: resource.ComposeAggregateTestCheckFunc(
				e.checkGrant("alice", "/workspaces/acme", nil, e.roleID("Editor")),
				expectCalls(1, 1),
			),
		},
		// Only additions: no revoke call.
		resource.TestStep{
			PreConfig: counts,
			Config:    grantCfg(`[permio_role.editor.id, permio_role.viewer.id]`, `[permio_permission.share.name]`),
			Check: resource.ComposeAggregateTestCheckFunc(
				e.checkGrant("alice", "/workspaces/acme", []string{"doc.share"}, func() []string {
					return append(e.roleID("Editor")(), e.roleID("Viewer")()...)
				}),
				expectCalls(1, 0),
			),
		},
		// Only removals: no grant call.
		resource.TestStep{
			PreConfig: counts,
			Config:    grantCfg(`[permio_role.editor.id]`, `[permio_permission.share.name]`),
			Check: resource.ComposeAggregateTestCheckFunc(
				e.checkGrant("alice", "/workspaces/acme", []string{"doc.share"}, e.roleID("Editor")),
				expectCalls(0, 1),
			),
		},
		resource.TestStep{
			ResourceName: "permio_grant.alice", ImportState: true, ImportStateVerify: true,
			ImportStateId: "default|alice|/workspaces/acme", ImportStateVerifyIgnore: []string{"timeouts"},
		},
		resource.TestStep{
			ResourceName: "permio_grant.alice", ImportState: true, ImportStateVerify: true,
			ImportStateId: "alice|/workspaces/acme", ImportStateVerifyIgnore: []string{"timeouts"},
		},
		// Drift: something granted outside Terraform on the same pair is revoked.
		resource.TestStep{
			PreConfig: func() {
				_, err := e.client.API.GrantUserPermissionsAndRolesOnResource(ctx(), &pb.GrantUserPermissionsAndRolesOnResourceRequest{
					ProjectName: "default", UserId: "alice", ResourceUri: "/workspaces/acme", Permissions: []string{"doc.write"},
				})
				e.must(err)
			},
			Config: grantCfg(`[permio_role.editor.id]`, `[permio_permission.share.name]`),
			ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
				plancheck.ExpectResourceAction("permio_grant.alice", plancheck.ResourceActionUpdate),
			}},
			Check: e.checkGrant("alice", "/workspaces/acme", []string{"doc.share"}, e.roleID("Editor")),
		},
		// Drift: everything revoked outside Terraform, so the grant is created again.
		resource.TestStep{
			PreConfig: func() {
				perms, roles, err := e.grant("alice", "/workspaces/acme")
				e.must(err)
				_, err = e.client.API.RevokeUserPermissionsAndRolesOnResource(ctx(), &pb.RevokeUserPermissionsAndRolesOnResourceRequest{
					ProjectName: "default", UserId: "alice", ResourceUri: "/workspaces/acme", Permissions: perms, Roles: roles,
				})
				e.must(err)
			},
			Config: grantCfg(`[permio_role.editor.id]`, `[permio_permission.share.name]`),
			ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
				plancheck.ExpectResourceAction("permio_grant.alice", plancheck.ResourceActionCreate),
			}},
			Check: e.checkGrant("alice", "/workspaces/acme", []string{"doc.share"}, e.roleID("Editor")),
		},
		// Changing the resource replaces the grant: the old pair is revoked.
		resource.TestStep{
			Config: e.config(grantBase + `
resource "permio_grant" "alice" {
  principal = "alice"
  resource  = "/workspaces/acme/projects/1"
  roles     = [permio_role.editor.id]
}`),
			ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
				plancheck.ExpectResourceAction("permio_grant.alice", plancheck.ResourceActionDestroyBeforeCreate),
			}},
			Check: resource.ComposeAggregateTestCheckFunc(
				e.checkGrant("alice", "/workspaces/acme", nil, none),
				e.checkGrant("alice", "/workspaces/acme/projects/1", nil, e.roleID("Editor")),
			),
		},
		// Destroying the grant revokes everything on the pair.
		resource.TestStep{
			Config: e.config(grantBase),
			Check:  e.checkGrant("alice", "/workspaces/acme/projects/1", nil, none),
		},
	)
}

func TestGrant_createTakesOverExistingPair(t *testing.T) {
	e := newTestEnv(t)
	e.run(
		resource.TestStep{Config: e.config(grantBase)},
		resource.TestStep{
			PreConfig: func() {
				_, err := e.client.API.GrantUserPermissionsAndRolesOnResource(ctx(), &pb.GrantUserPermissionsAndRolesOnResourceRequest{
					ProjectName: "default", UserId: "bob", ResourceUri: "/docs/1", Permissions: []string{"doc.write", "doc.share"},
				})
				e.must(err)
			},
			Config: e.config(grantBase + `
resource "permio_grant" "bob" {
  principal   = "bob"
  resource    = "/docs/1"
  permissions = [permio_permission.read.name, permio_permission.share.name]
}`),
			Check: e.checkGrant("bob", "/docs/1", []string{"doc.read", "doc.share"}, nil),
		},
	)
}

func TestGrant_groupPrincipal(t *testing.T) {
	e := newTestEnv(t)
	cfg := e.config(grantBase + `
resource "permio_group" "eng" { name = "engineering" }
resource "permio_grant" "eng" {
  principal = permio_group.eng.principal
  resource  = "/workspaces/acme"
  roles     = [permio_role.editor.id]
}`)
	e.run(
		resource.TestStep{
			Config: cfg,
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttr("permio_grant.eng", "principal", "group:engineering"),
				e.checkGrant("group:engineering", "/workspaces/acme", nil, e.roleID("Editor")),
			),
		},
		resource.TestStep{
			ResourceName: "permio_grant.eng", ImportState: true, ImportStateVerify: true,
			ImportStateId: "default|group:engineering|/workspaces/acme", ImportStateVerifyIgnore: []string{"timeouts"},
		},
		// Drift: the group (and with it its grants) deleted out of band; both are created again.
		resource.TestStep{
			PreConfig: func() {
				_, err := e.client.API.DeleteGroup(ctx(), &pb.DeleteGroupRequest{ProjectName: "default", Name: "engineering"})
				e.must(err)
			},
			Config: cfg,
			ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
				plancheck.ExpectResourceAction("permio_group.eng", plancheck.ResourceActionCreate),
				plancheck.ExpectResourceAction("permio_grant.eng", plancheck.ResourceActionCreate),
			}},
			Check: e.checkGrant("group:engineering", "/workspaces/acme", nil, e.roleID("Editor")),
		},
	)
}

func TestGrant_ignoresDeletedPermissions(t *testing.T) {
	e := newTestEnv(t)
	cfg := e.config(`
resource "permio_permission" "read" { name = "doc.read" }
resource "permio_grant" "alice" {
  principal   = "alice"
  resource    = "/docs/1"
  permissions = [permio_permission.read.name]
}`)
	e.run(
		resource.TestStep{Config: cfg},
		// The grant also names a permission that has since been deleted. The API cannot revoke it, so it must not
		// show up as a permanent diff.
		resource.TestStep{
			PreConfig: func() {
				e.fake.SetGrantOutOfBand("default", "alice", "/docs/1", []string{"doc.read", "gone.permission"}, nil)
			},
			Config: cfg,
			ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
				plancheck.ExpectEmptyPlan(),
			}},
		},
	)
	// Destroy revoked what it could.
	perms, _, err := e.grant("alice", "/docs/1")
	e.must(err)
	if slices.Contains(perms, "doc.read") {
		t.Fatalf("doc.read still granted: %v", perms)
	}
}

func TestGrant_validation(t *testing.T) {
	e := newTestEnv(t)
	cases := map[string]string{
		`principal = "alice"
  resource  = "docs/1"
  permissions = ["a"]`: `must start with`,
		`principal = "alice"
  resource  = "/docs/"
  permissions = ["a"]`: `empty segments`,
		`principal = "alice"
  resource  = "/docs/(1)"
  permissions = ["a"]`: `must not contain any of the characters`,
		`principal = "alice"
  resource  = "/docs/a b"
  permissions = ["a"]`: `whitespace`,
		`principal = "group:Not_Valid"
  resource  = "/docs/1"
  permissions = ["a"]`: `reserved for\s+groups`,
		`principal = "alice"
  resource  = "/docs/1"`: `Nothing to grant`,
		`principal = "alice"
  resource  = "/docs/1"
  roles     = ["Editor Role"]`: `role ID`,
	}
	for body, want := range cases {
		e.run(resource.TestStep{
			Config:      e.config("resource \"permio_grant\" \"x\" {\n  " + body + "\n}"),
			PlanOnly:    true,
			ExpectError: regexp.MustCompile(want),
		})
	}
}

func TestParseGrantID(t *testing.T) {
	pd := &providerData{project: "default"}
	cases := []struct {
		id                      string
		project, principal, uri string
		ok                      bool
	}{
		{"default|alice|/docs/1", "default", "alice", "/docs/1", true},
		{"alice|/docs/1", "default", "alice", "/docs/1", true},
		{"prod|group:eng|/w/_/billing", "prod", "group:eng", "/w/_/billing", true},
		{"prod|odd|name|/docs", "prod", "odd|name", "/docs", true},
		{"prod|user/with/slashes|/docs", "prod", "user/with/slashes", "/docs", true},
		{"alice", "", "", "", false},
		{"default|alice|docs", "", "", "", false},
		{"BAD|alice|/docs", "", "", "", false},
	}
	for _, c := range cases {
		project, principal, uri, ok := parseGrantID(c.id, pd)
		if ok != c.ok || project != c.project || principal != c.principal || uri != c.uri {
			t.Errorf("parseGrantID(%q) = %q, %q, %q, %v; want %q, %q, %q, %v", c.id, project, principal, uri, ok, c.project, c.principal, c.uri, c.ok)
		}
	}
}
