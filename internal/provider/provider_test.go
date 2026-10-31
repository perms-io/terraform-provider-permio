package provider

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"slices"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
	pb "github.com/perms-io/permio-go/proto/permissions/v1"

	"github.com/perms-io/terraform-provider-permio/internal/client"
	"github.com/perms-io/terraform-provider-permio/internal/fakeserver"
)

// testEnv is an in-process fake Permio API and a provider wired to it.
type testEnv struct {
	t         *testing.T
	fake      *fakeserver.Server
	lis       *fakeserver.Listener
	client    *client.Client
	factories map[string]func() (tfprotov6.ProviderServer, error)
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	// The tests use the provider configuration below; make sure the environment cannot override it.
	for _, env := range []string{EnvAPIKey, EnvAPIURL, EnvProject} {
		t.Setenv(env, "")
	}
	fake := fakeserver.New()
	lis := fakeserver.Start(fake)
	t.Cleanup(lis.Stop)

	tweak := func(c *client.Config) {
		c.Insecure = true
		c.DialOptions = lis.DialOptions()
		c.MaxRetries = -1
	}
	cfg := client.Config{APIKey: fakeserver.FullAccessKey, Endpoint: fakeserver.Target}
	tweak(&cfg)
	c, err := client.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })

	return &testEnv{
		t:      t,
		fake:   fake,
		lis:    lis,
		client: c,
		factories: map[string]func() (tfprotov6.ProviderServer, error){
			"permio": providerserver.NewProtocol6WithError(New("test", WithClientConfig(tweak))()),
		},
	}
}

// config prepends a provider block that uses the full-access key.
func (e *testEnv) config(body string) string {
	return e.configWithKey(fakeserver.FullAccessKey, body)
}

func (e *testEnv) configWithKey(key, body string) string {
	return fmt.Sprintf(`
provider "permio" {
  api_key = %q
  api_url = %q
}
`, key, fakeserver.Target) + body
}

func (e *testEnv) run(steps ...resource.TestStep) {
	e.t.Helper()
	resource.UnitTest(e.t, resource.TestCase{ProtoV6ProviderFactories: e.factories, Steps: steps})
}

func ctx() context.Context { return context.Background() }

type tfState = terraform.State

func tfjsonPath(attr string) tfjsonpath.Path { return tfjsonpath.New(attr) }

func knownString(v string) knownvalue.Check { return knownvalue.StringExact(v) }

// --- assertions against the fake API ---

func (e *testEnv) checkPermission(name, description string) resource.TestCheckFunc {
	return func(*terraform.State) error {
		p, err := e.client.API.GetPermission(ctx(), &pb.GetPermissionRequest{ProjectName: "default", Name: name})
		if err != nil {
			return fmt.Errorf("permission %q: %v", name, err)
		}
		if p.GetDescription() != description {
			return fmt.Errorf("permission %q description = %q, want %q", name, p.GetDescription(), description)
		}
		return nil
	}
}

func (e *testEnv) checkNoPermission(name string) resource.TestCheckFunc {
	return func(*terraform.State) error {
		_, err := e.client.API.GetPermission(ctx(), &pb.GetPermissionRequest{ProjectName: "default", Name: name})
		if !client.IsNotFound(err) {
			return fmt.Errorf("permission %q still exists (err=%v)", name, err)
		}
		return nil
	}
}

func (e *testEnv) checkRole(name string, perms ...string) resource.TestCheckFunc {
	return func(*terraform.State) error {
		r, err := e.client.FindRoleByName(ctx(), "default", name)
		if err != nil || r == nil {
			return fmt.Errorf("role %q not found (err=%v)", name, err)
		}
		got := sortedCopy(client.PermissionNames(r))
		if !slices.Equal(got, sortedCopy(perms)) {
			return fmt.Errorf("role %q permissions = %v, want %v", name, got, perms)
		}
		return nil
	}
}

func (e *testEnv) checkMembers(group string, want ...string) resource.TestCheckFunc {
	return func(*terraform.State) error {
		got, err := e.client.ListAllGroupMembers(ctx(), "default", group)
		if err != nil {
			return err
		}
		if !slices.Equal(got, sortedCopy(want)) {
			return fmt.Errorf("group %q members = %v, want %v", group, got, want)
		}
		return nil
	}
}

func (e *testEnv) grant(principal, uri string) (perms, roles []string, err error) {
	r, err := e.client.API.GetUserPermissionsAndRolesOnResource(ctx(), &pb.GetUserPermissionsAndRolesOnResourceRequest{ProjectName: "default", UserId: principal, ResourceUri: uri})
	if err != nil {
		return nil, nil, err
	}
	return sortedCopy(r.GetPermissions()), sortedCopy(r.GetRoles()), nil
}

func (e *testEnv) checkGrant(principal, uri string, wantPerms []string, wantRoles func() []string) resource.TestCheckFunc {
	return func(*terraform.State) error {
		perms, roles, err := e.grant(principal, uri)
		if err != nil {
			return err
		}
		var want []string
		if wantRoles != nil {
			want = sortedCopy(wantRoles())
		}
		if !slices.Equal(perms, sortedCopy(wantPerms)) || !slices.Equal(roles, want) {
			return fmt.Errorf("grant %s on %s = perms %v roles %v, want perms %v roles %v", principal, uri, perms, roles, wantPerms, want)
		}
		return nil
	}
}

// roleID returns the ID of a role by name, for use in checks that run after the role exists.
func (e *testEnv) roleID(name string) func() []string {
	return func() []string {
		r, err := e.client.FindRoleByName(ctx(), "default", name)
		if err != nil || r == nil {
			e.t.Fatalf("role %q not found (err=%v)", name, err)
		}
		return []string{r.GetId()}
	}
}

// diagErr turns error diagnostics into an error.
func diagErr(d diag.Diagnostics) error {
	if d.HasError() {
		return fmt.Errorf("%v", d)
	}
	return nil
}

func (e *testEnv) must(err error) {
	e.t.Helper()
	if err != nil {
		e.t.Fatal(err)
	}
}

func TestMain(m *testing.M) {
	// resource.UnitTest needs a terraform binary. Use TF_ACC_TERRAFORM_PATH if it is set; otherwise the testing
	// framework looks for terraform on PATH (or downloads it).
	os.Exit(m.Run())
}

func TestProvider_missingAPIKey(t *testing.T) {
	e := newTestEnv(t)
	e.run(resource.TestStep{
		Config: `
provider "permio" {
  api_url = "passthrough:///bufnet"
}
data "permio_permission" "x" { name = "anything" }
`,
		ExpectError: regexp.MustCompile(`Missing Permio API key`),
	})
}

func TestProvider_envFallbacks(t *testing.T) {
	e := newTestEnv(t)
	t.Setenv(EnvAPIKey, fakeserver.FullAccessKey)
	t.Setenv(EnvAPIURL, fakeserver.Target)
	e.must(func() error {
		_, err := e.client.API.CreatePermission(ctx(), &pb.CreatePermissionRequest{ProjectName: "default", Name: "env.read"})
		return err
	}())
	e.run(resource.TestStep{
		Config: `
provider "permio" {}
data "permio_permission" "x" { name = "env.read" }
`,
		Check: resource.TestCheckResourceAttr("data.permio_permission.x", "project", "default"),
	})
}

func TestProvider_checkOnlyKeyCannotManage(t *testing.T) {
	e := newTestEnv(t)
	e.run(resource.TestStep{
		Config:      e.configWithKey(fakeserver.CheckOnlyKey, `resource "permio_permission" "x" { name = "doc.read" }`),
		ExpectError: regexp.MustCompile(`(?s)not allowed.*full-access API key`),
	})
}

func TestProvider_wrongProjectIsDenied(t *testing.T) {
	e := newTestEnv(t)
	e.run(resource.TestStep{
		Config: e.config(`resource "permio_permission" "x" {
  project = "other"
  name    = "doc.read"
}`),
		ExpectError: regexp.MustCompile(`scoped to a single project`),
	})
}
