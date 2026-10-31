package provider

import (
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	pb "github.com/perms-io/permio-go/proto/permissions/v1"
)

func TestGroup_lifecycle(t *testing.T) {
	e := newTestEnv(t)
	e.run(
		resource.TestStep{
			Config: e.config(`
resource "permio_group" "eng" {
  name        = "engineering"
  description = "Engineers"
}`),
			ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
				// The principal is known at plan time.
				plancheck.ExpectKnownValue("permio_group.eng", tfjsonPath("principal"), knownString("group:engineering")),
			}},
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttr("permio_group.eng", "principal", "group:engineering"),
				resource.TestCheckResourceAttr("permio_group.eng", "project", "default"),
				resource.TestCheckResourceAttrSet("permio_group.eng", "id"),
			),
		},
		// The description is updated in place.
		resource.TestStep{
			Config: e.config(`
resource "permio_group" "eng" {
  name        = "engineering"
  description = "All engineers"
}`),
			ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
				plancheck.ExpectResourceAction("permio_group.eng", plancheck.ResourceActionUpdate),
			}},
			Check: resource.TestCheckResourceAttr("permio_group.eng", "description", "All engineers"),
		},
		resource.TestStep{
			ResourceName: "permio_group.eng", ImportState: true, ImportStateVerify: true,
			ImportStateId: "default/engineering", ImportStateVerifyIgnore: []string{"timeouts"},
		},
		resource.TestStep{
			ResourceName: "permio_group.eng", ImportState: true, ImportStateVerify: true,
			ImportStateId: "engineering", ImportStateVerifyIgnore: []string{"timeouts"},
		},
		// Drift: deleted out of band.
		resource.TestStep{
			PreConfig: func() {
				_, err := e.client.API.DeleteGroup(ctx(), &pb.DeleteGroupRequest{ProjectName: "default", Name: "engineering"})
				e.must(err)
			},
			Config: e.config(`
resource "permio_group" "eng" {
  name        = "engineering"
  description = "All engineers"
}`),
			ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
				plancheck.ExpectResourceAction("permio_group.eng", plancheck.ResourceActionCreate),
			}},
		},
		// Groups cannot be renamed: a new name replaces the group.
		resource.TestStep{
			Config: e.config(`
resource "permio_group" "eng" {
  name        = "eng"
  description = "All engineers"
}`),
			ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
				plancheck.ExpectResourceAction("permio_group.eng", plancheck.ResourceActionDestroyBeforeCreate),
			}},
			Check: func(*tfState) error {
				if _, err := e.client.API.GetGroup(ctx(), &pb.GetGroupRequest{ProjectName: "default", Name: "engineering"}); err == nil {
					t.Error("old group still exists")
				}
				return nil
			},
		},
	)
}

func TestGroup_validationAndConflicts(t *testing.T) {
	e := newTestEnv(t)
	e.run(resource.TestStep{
		Config:      e.config(`resource "permio_group" "x" { name = "Not_A_Slug" }`),
		PlanOnly:    true,
		ExpectError: regexp.MustCompile(`slug`),
	})
	_, err := e.client.API.CreateGroup(ctx(), &pb.CreateGroupRequest{ProjectName: "default", Name: "taken"})
	e.must(err)
	e.run(resource.TestStep{
		Config:      e.config(`resource "permio_group" "x" { name = "taken" }`),
		ExpectError: regexp.MustCompile(`(?s)Group already exists.*default/taken`),
	})
}

func TestGroupMembers_authoritative(t *testing.T) {
	e := newTestEnv(t)
	cfg := func(members string) string {
		return e.config(`
resource "permio_group" "eng" { name = "engineering" }
resource "permio_group_members" "eng" {
  group   = permio_group.eng.name
  members = ` + members + `
}`)
	}
	e.run(
		resource.TestStep{
			Config: cfg(`["alice", "bob"]`),
			Check: resource.ComposeAggregateTestCheckFunc(
				e.checkMembers("engineering", "alice", "bob"),
				resource.TestCheckResourceAttr("permio_group_members.eng", "id", "default/engineering"),
			),
		},
		resource.TestStep{
			Config: cfg(`["bob", "carol"]`),
			Check:  e.checkMembers("engineering", "bob", "carol"),
		},
		// A member added outside Terraform is removed on the next apply.
		resource.TestStep{
			PreConfig: func() {
				e.must(e.client.AddGroupMembers(ctx(), "default", "engineering", []string{"mallory"}))
			},
			Config: cfg(`["bob", "carol"]`),
			ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
				plancheck.ExpectResourceAction("permio_group_members.eng", plancheck.ResourceActionUpdate),
			}},
			Check: e.checkMembers("engineering", "bob", "carol"),
		},
		resource.TestStep{
			ResourceName: "permio_group_members.eng", ImportState: true, ImportStateVerify: true,
			ImportStateId: "default/engineering", ImportStateVerifyIgnore: []string{"timeouts"},
		},
		// More members than one API call accepts.
		resource.TestStep{
			Config: cfg(`[for i in range(250) : format("user-%03d", i)]`),
			Check:  resource.TestCheckResourceAttr("permio_group_members.eng", "members.#", "250"),
		},
		resource.TestStep{
			Config: cfg(`[]`),
			Check:  e.checkMembers("engineering"),
		},
		resource.TestStep{
			Config: cfg(`["alice"]`),
			Check:  e.checkMembers("engineering", "alice"),
		},
		// Destroying the members resource empties the group but keeps it.
		resource.TestStep{
			Config: e.config(`resource "permio_group" "eng" { name = "engineering" }`),
			Check:  e.checkMembers("engineering"),
		},
	)
}

func TestGroupMembers_rejectsNestedGroups(t *testing.T) {
	e := newTestEnv(t)
	e.run(resource.TestStep{
		Config: e.config(`
resource "permio_group_members" "x" {
  group   = "eng"
  members = ["group:other"]
}`),
		PlanOnly:    true,
		ExpectError: regexp.MustCompile(`groups cannot be members of groups`),
	})
}

func TestGroupMember_nonAuthoritative(t *testing.T) {
	e := newTestEnv(t)
	cfg := e.config(`
resource "permio_group" "eng" { name = "engineering" }
resource "permio_group_member" "alice" {
  group     = permio_group.eng.name
  principal = "alice"
}
resource "permio_group_member" "bob" {
  group     = permio_group.eng.name
  principal = "user/bob@example.com"
}`)
	e.run(
		resource.TestStep{
			Config: cfg,
			Check: resource.ComposeAggregateTestCheckFunc(
				e.checkMembers("engineering", "alice", "user/bob@example.com"),
				resource.TestCheckResourceAttr("permio_group_member.bob", "id", "default/engineering/user/bob@example.com"),
			),
		},
		// Members added outside Terraform are left alone.
		resource.TestStep{
			PreConfig: func() { e.must(e.client.AddGroupMembers(ctx(), "default", "engineering", []string{"carol"})) },
			Config:    cfg,
			ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
				plancheck.ExpectEmptyPlan(),
			}},
			Check: e.checkMembers("engineering", "alice", "carol", "user/bob@example.com"),
		},
		resource.TestStep{
			ResourceName: "permio_group_member.bob", ImportState: true, ImportStateVerify: true,
			ImportStateId: "default/engineering/user/bob@example.com", ImportStateVerifyIgnore: []string{"timeouts"},
		},
		// The project is required, because the principal can contain "/".
		resource.TestStep{
			ResourceName: "permio_group_member.bob", ImportState: true,
			ImportStateId: "engineering/bob",
			ExpectError:   regexp.MustCompile(`three\s+parts\s+separated\s+by\s+"/"`),
		},
		resource.TestStep{
			ResourceName: "permio_group_member.bob", ImportState: true,
			ImportStateId: "a-project-name-that-is-too-long-x/engineering/bob",
			ExpectError:   regexp.MustCompile(`not\s+a\s+valid\s+project\s+name:\s+it\s+must\s+be\s+1\s+to\s+32`),
		},
		// Drift: removed out of band, so it is added again.
		resource.TestStep{
			PreConfig: func() { e.must(e.client.RemoveGroupMembers(ctx(), "default", "engineering", []string{"alice"})) },
			Config:    cfg,
			ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
				plancheck.ExpectResourceAction("permio_group_member.alice", plancheck.ResourceActionCreate),
			}},
			Check: e.checkMembers("engineering", "alice", "carol", "user/bob@example.com"),
		},
		// Removing one member resource removes only that member.
		resource.TestStep{
			Config: e.config(`
resource "permio_group" "eng" { name = "engineering" }
resource "permio_group_member" "alice" {
  group     = permio_group.eng.name
  principal = "alice"
}`),
			Check: e.checkMembers("engineering", "alice", "carol"),
		},
	)
}
