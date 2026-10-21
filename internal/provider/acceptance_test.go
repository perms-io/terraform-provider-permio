package provider

import (
	"fmt"
	"os"
	"testing"

	pb "github.com/PrivateJAR/permio-go/proto/permissions/v1"
	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/PrivateJAR/terraform-provider-permio/internal/client"
)

// Acceptance tests run against a real Permio API. They need TF_ACC=1 and a full-access PERMIO_API_KEY, and use
// PERMIO_API_URL (default production) and PERMIO_PROJECT (default "default"). They create uniquely named objects
// and destroy them afterwards.

func accPreCheck(t *testing.T) {
	t.Helper()
	if os.Getenv("TF_ACC") == "" {
		t.Skip("set TF_ACC=1 to run acceptance tests against a real Permio API")
	}
	if os.Getenv(EnvAPIKey) == "" {
		t.Skip("set " + EnvAPIKey + " (a full-access key) to run acceptance tests")
	}
}

func accProject() string {
	if p := os.Getenv(EnvProject); p != "" {
		return p
	}
	return client.DefaultProject
}

func accClient(t *testing.T) *client.Client {
	t.Helper()
	endpoint := os.Getenv(EnvAPIURL)
	if endpoint == "" {
		endpoint = client.DefaultEndpoint
	}
	c, err := client.New(client.Config{APIKey: os.Getenv(EnvAPIKey), Endpoint: endpoint, UserAgent: "terraform-provider-permio/acctest"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

var accFactories = map[string]func() (tfprotov6.ProviderServer, error){
	"permio": providerserver.NewProtocol6WithError(New("acctest")()),
}

func TestAccPermio_workspace(t *testing.T) {
	accPreCheck(t)
	c := accClient(t)
	project := accProject()
	prefix := "tfacc-" + acctest.RandStringFromCharSet(8, "abcdefghijklmnopqrstuvwxyz0123456789")
	// An Auth0-style user ID: "|" is also the grant import ID separator.
	user := "auth0|" + prefix + "-alice"

	cfgNamed := func(readName, description string, editorPerms string) string {
		return fmt.Sprintf(`
provider "permio" {}

resource "permio_permission" "read" {
  name        = "%[1]s.%[5]s"
  description = %[2]q
}
resource "permio_permission" "write" { name = "%[1]s.doc.write" }

resource "permio_role" "editor" {
  name        = "%[1]s Editor"
  permissions = %[3]s
}

resource "permio_group" "eng" {
  name        = "%[1]s-eng"
  description = %[2]q
}

resource "permio_group_members" "eng" {
  group   = permio_group.eng.name
  members = [%[4]q]
}

resource "permio_grant" "eng" {
  principal = permio_group.eng.principal
  resource  = "/%[1]s/workspaces/acme"
  roles     = [permio_role.editor.id]
}

resource "permio_grant" "direct" {
  principal   = %[4]q
  resource    = "/%[1]s/workspaces/acme/docs/1"
  permissions = [permio_permission.write.name]
}
`, prefix, description, editorPerms, user, readName)
	}
	cfg := func(description string, editorPerms string) string {
		return cfgNamed("doc.read", description, editorPerms)
	}
	checkCfg := cfg("v2", `[permio_permission.read.name, permio_permission.write.name]`) + fmt.Sprintf(`
data "permio_role" "editor" { name = permio_role.editor.name }
data "permio_check" "inherited" {
  principal   = %[2]q
  resource    = "/%[1]s/workspaces/acme/docs/2"
  permissions = [permio_permission.read.name, permio_permission.write.name]
}
`, prefix, user)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { accPreCheck(t) },
		ProtoV6ProviderFactories: accFactories,
		CheckDestroy: func(*terraform.State) error {
			if _, err := c.API.GetGroup(t.Context(), &pb.GetGroupRequest{ProjectName: project, Name: prefix + "-eng"}); !client.IsNotFound(err) {
				return fmt.Errorf("group still exists (err=%v)", err)
			}
			if _, err := c.API.GetPermission(t.Context(), &pb.GetPermissionRequest{ProjectName: project, Name: prefix + ".doc.read"}); !client.IsNotFound(err) {
				return fmt.Errorf("permission still exists (err=%v)", err)
			}
			if _, err := c.API.GetPermission(t.Context(), &pb.GetPermissionRequest{ProjectName: project, Name: prefix + ".document.read"}); !client.IsNotFound(err) {
				return fmt.Errorf("renamed permission still exists (err=%v)", err)
			}
			if r, err := c.FindRoleByName(t.Context(), project, prefix+" Editor"); err != nil || r != nil {
				return fmt.Errorf("role still exists (err=%v)", err)
			}
			return nil
		},
		Steps: []resource.TestStep{
			{
				Config: cfg("v1", `[permio_permission.read.name]`),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("permio_group.eng", "principal", "group:"+prefix+"-eng"),
					resource.TestCheckResourceAttr("permio_role.editor", "permissions.#", "1"),
					resource.TestCheckResourceAttr("permio_group_members.eng", "members.#", "1"),
				),
			},
			{
				Config: cfg("v2", `[permio_permission.read.name, permio_permission.write.name]`),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("permio_permission.read", "description", "v2"),
					resource.TestCheckResourceAttr("permio_role.editor", "permissions.#", "2"),
				),
			},
			{
				Config: checkCfg,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrPair("data.permio_role.editor", "id", "permio_role.editor", "id"),
					resource.TestCheckResourceAttr("data.permio_check.inherited", "allowed", "true"),
				),
			},
			{ResourceName: "permio_permission.read", ImportState: true, ImportStateVerify: true, ImportStateVerifyIgnore: []string{"timeouts"},
				ImportStateId: project + "/" + prefix + ".doc.read"},
			{ResourceName: "permio_role.editor", ImportState: true, ImportStateVerify: true, ImportStateVerifyIgnore: []string{"timeouts"},
				ImportStateIdFunc: func(s *terraform.State) (string, error) {
					return project + "/" + s.RootModule().Resources["permio_role.editor"].Primary.ID, nil
				}},
			{ResourceName: "permio_group.eng", ImportState: true, ImportStateVerify: true, ImportStateVerifyIgnore: []string{"timeouts"},
				ImportStateId: project + "/" + prefix + "-eng"},
			{ResourceName: "permio_group_members.eng", ImportState: true, ImportStateVerify: true, ImportStateVerifyIgnore: []string{"timeouts"},
				ImportStateId: project + "/" + prefix + "-eng"},
			{ResourceName: "permio_grant.direct", ImportState: true, ImportStateVerify: true, ImportStateVerifyIgnore: []string{"timeouts"},
				ImportStateId: project + "|" + user + "|/" + prefix + "/workspaces/acme/docs/1"},
			// Rename a permission that a role uses: the role keeps it under the new name.
			{
				Config: cfgNamed("document.read", "v2", `[permio_permission.read.name, permio_permission.write.name]`),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("permio_permission.read", "name", prefix+".document.read"),
					resource.TestCheckTypeSetElemAttr("permio_role.editor", "permissions.*", prefix+".document.read"),
					func(*terraform.State) error {
						if _, err := c.API.GetPermission(t.Context(), &pb.GetPermissionRequest{ProjectName: project, Name: prefix + ".doc.read"}); !client.IsNotFound(err) {
							return fmt.Errorf("old permission still exists (err=%v)", err)
						}
						return nil
					},
				),
			},
		},
	})
}
