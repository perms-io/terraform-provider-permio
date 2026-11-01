// Package provider implements the Permio Terraform provider.
package provider

import (
	"context"
	"fmt"
	"os"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/perms-io/terraform-provider-permio/internal/client"
)

// Environment variables the provider reads when an argument is not set.
const (
	EnvAPIKey  = "PERMIO_API_KEY"
	EnvAPIURL  = "PERMIO_API_URL"
	EnvProject = "PERMIO_PROJECT"
)

var _ provider.Provider = (*PermioProvider)(nil)

// PermioProvider is the Permio provider.
type PermioProvider struct {
	version string
	// configure adjusts the client configuration; tests use it to dial an in-process server.
	configure []func(*client.Config)
}

// Option customises the provider. Options exist for tests.
type Option func(*PermioProvider)

// WithClientConfig registers a function that adjusts the client configuration before the client is created.
func WithClientConfig(f func(*client.Config)) Option {
	return func(p *PermioProvider) { p.configure = append(p.configure, f) }
}

// New returns a function that creates the provider.
func New(version string, opts ...Option) func() provider.Provider {
	return func() provider.Provider {
		p := &PermioProvider{version: version}
		for _, opt := range opts {
			opt(p)
		}
		return p
	}
}

type providerModel struct {
	APIKey  types.String `tfsdk:"api_key"`
	APIURL  types.String `tfsdk:"api_url"`
	Project types.String `tfsdk:"project"`
}

// providerData is what resources and data sources receive from Configure.
type providerData struct {
	client  *client.Client
	project string
}

func (p *PermioProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "permio"
	resp.Version = p.version
}

func (p *PermioProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "The Permio provider manages permissions, roles, groups, group memberships and grants in a " +
			"[Permio](https://perms.io) project, and can evaluate permission checks.",
		Attributes: map[string]schema.Attribute{
			"api_key": schema.StringAttribute{
				MarkdownDescription: "Permio API key (`perms_...`). Can also be set with the `PERMIO_API_KEY` environment " +
					"variable. An API key belongs to one organisation and one project. Managing objects needs a full-access " +
					"key; a check-only key is enough for the data sources.",
				Optional:  true,
				Sensitive: true,
			},
			"api_url": schema.StringAttribute{
				MarkdownDescription: "Address of the Permio API. Defaults to `" + client.DefaultEndpoint + "`, which is " +
					"what you want; there is normally no need to set it. Can also be set with the `PERMIO_API_URL` " +
					"environment variable.",
				Optional: true,
			},
			"project": schema.StringAttribute{
				MarkdownDescription: "Default project for resources and data sources that do not set `project`. Defaults " +
					"to `default`. Can also be set with the `PERMIO_PROJECT` environment variable.",
				Optional:   true,
				Validators: []validator.String{projectValidator()},
			},
		},
	}
}

func (p *PermioProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var cfg providerModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	if resp.Diagnostics.HasError() {
		return
	}

	for attr, v := range map[string]types.String{"api_key": cfg.APIKey, "api_url": cfg.APIURL, "project": cfg.Project} {
		if v.IsUnknown() {
			resp.Diagnostics.AddAttributeError(path.Root(attr), "Unknown provider configuration",
				"The provider cannot be configured because "+attr+" is not known until apply. Set it to a value known at plan time.")
		}
	}
	if resp.Diagnostics.HasError() {
		return
	}

	apiKey := stringOrEnv(cfg.APIKey, EnvAPIKey, "")
	apiURL := stringOrEnv(cfg.APIURL, EnvAPIURL, client.DefaultEndpoint)
	project := stringOrEnv(cfg.Project, EnvProject, client.DefaultProject)

	if apiKey == "" {
		resp.Diagnostics.AddAttributeError(path.Root("api_key"), "Missing Permio API key",
			"Set the provider's api_key argument or the "+EnvAPIKey+" environment variable to a Permio API key.")
		return
	}
	if err := validateProjectName(project); err != nil {
		resp.Diagnostics.AddAttributeError(path.Root("project"), "Invalid project", fmt.Sprintf("The project %q %v.", project, err))
		return
	}

	ccfg := client.Config{
		APIKey:    apiKey,
		Endpoint:  apiURL,
		UserAgent: "terraform-provider-permio/" + p.version,
	}
	for _, f := range p.configure {
		f(&ccfg)
	}
	c, err := client.New(ccfg)
	if err != nil {
		resp.Diagnostics.AddError("Unable to create Permio client", err.Error())
		return
	}

	data := &providerData{client: c, project: project}
	resp.DataSourceData = data
	resp.ResourceData = data
}

func (p *PermioProvider) Resources(context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		NewPermissionResource,
		NewRoleResource,
		NewGroupResource,
		NewGroupMembersResource,
		NewGroupMemberResource,
		NewGrantResource,
	}
}

func (p *PermioProvider) DataSources(context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{
		NewPermissionDataSource,
		NewRoleDataSource,
		NewGroupDataSource,
		NewCheckDataSource,
	}
}

func stringOrEnv(v types.String, env, def string) string {
	if !v.IsNull() && !v.IsUnknown() && v.ValueString() != "" {
		return v.ValueString()
	}
	if e := os.Getenv(env); e != "" {
		return e
	}
	return def
}
