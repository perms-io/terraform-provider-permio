package provider

import (
	"context"
	"fmt"

	pb "github.com/PrivateJAR/permio-go/proto/permissions/v1"
	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/PrivateJAR/terraform-provider-permio/internal/client"
)

// ---------------------------------------------------------------------------------------------------------------
// permio_permission

var _ datasource.DataSourceWithConfigure = (*permissionDataSource)(nil)

// NewPermissionDataSource returns the permio_permission data source.
func NewPermissionDataSource() datasource.DataSource { return &permissionDataSource{} }

type permissionDataSource struct{ pd *providerData }

type permissionDataModel struct {
	ID          types.String `tfsdk:"id"`
	Project     types.String `tfsdk:"project"`
	Name        types.String `tfsdk:"name"`
	Description types.String `tfsdk:"description"`
}

func (d *permissionDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_permission"
}

func (d *permissionDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Looks up a permission by name.",
		Attributes: map[string]schema.Attribute{
			"id":          schema.StringAttribute{MarkdownDescription: "Permission ID.", Computed: true},
			"project":     dataSourceProjectAttribute(),
			"name":        schema.StringAttribute{MarkdownDescription: "Permission name.", Required: true, Validators: permissionNameValidators()},
			"description": schema.StringAttribute{MarkdownDescription: "Description of the permission.", Computed: true},
		},
	}
}

func (d *permissionDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.pd = providerDataFrom(req.ProviderData, &resp.Diagnostics)
}

func (d *permissionDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var m permissionDataModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() || !requireClient(d.pd, &resp.Diagnostics) {
		return
	}
	project := projectOf(m.Project, d.pd)
	p, err := d.pd.client.API.GetPermission(ctx, &pb.GetPermissionRequest{ProjectName: project, Name: m.Name.ValueString()})
	if err != nil {
		client.AddError(&resp.Diagnostics, fmt.Sprintf("Unable to read permission %q", m.Name.ValueString()), err)
		return
	}
	m.ID = types.StringValue(p.GetId())
	m.Project = types.StringValue(project)
	m.Description = types.StringValue(p.GetDescription())
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}

// ---------------------------------------------------------------------------------------------------------------
// permio_role

var _ datasource.DataSourceWithConfigure = (*roleDataSource)(nil)

// NewRoleDataSource returns the permio_role data source.
func NewRoleDataSource() datasource.DataSource { return &roleDataSource{} }

type roleDataSource struct{ pd *providerData }

type roleDataModel struct {
	ID          types.String `tfsdk:"id"`
	Project     types.String `tfsdk:"project"`
	Name        types.String `tfsdk:"name"`
	Description types.String `tfsdk:"description"`
	Permissions types.Set    `tfsdk:"permissions"`
}

func (d *roleDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_role"
}

func (d *roleDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Looks up a role by name (or by ID). Use its `id` in `permio_grant.roles`.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				MarkdownDescription: "Role ID. Set either `name` or `id`.",
				Optional:            true,
				Computed:            true,
				Validators: append(roleIDValidators(),
					stringvalidator.ExactlyOneOf(path.MatchRoot("name"), path.MatchRoot("id"))),
			},
			"project": dataSourceProjectAttribute(),
			"name": schema.StringAttribute{
				MarkdownDescription: "Exact role name. Set either `name` or `id`.",
				Optional:            true,
				Computed:            true,
				Validators:          roleNameValidators(),
			},
			"description": schema.StringAttribute{MarkdownDescription: "Description of the role.", Computed: true},
			"permissions": schema.SetAttribute{MarkdownDescription: "Names of the role's permissions.", Computed: true, ElementType: types.StringType},
		},
	}
}

func (d *roleDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.pd = providerDataFrom(req.ProviderData, &resp.Diagnostics)
}

func (d *roleDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var m roleDataModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() || !requireClient(d.pd, &resp.Diagnostics) {
		return
	}
	project := projectOf(m.Project, d.pd)
	var role *pb.Role
	var err error
	if !m.ID.IsNull() {
		role, err = getRole(ctx, d.pd.client, project, m.ID.ValueString())
	} else {
		role, err = d.pd.client.FindRoleByName(ctx, project, m.Name.ValueString())
	}
	if err != nil {
		client.AddError(&resp.Diagnostics, "Unable to read role", err)
		return
	}
	if role == nil {
		resp.Diagnostics.AddError("Role not found", fmt.Sprintf("No role with ID %q or name %q exists in project %q.", m.ID.ValueString(), m.Name.ValueString(), project))
		return
	}
	m.ID = types.StringValue(role.GetId())
	m.Project = types.StringValue(project)
	m.Name = types.StringValue(role.GetName())
	m.Description = types.StringValue(role.GetDescription())
	m.Permissions = stringsToSet(client.PermissionNames(role))
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}

// ---------------------------------------------------------------------------------------------------------------
// permio_group

var _ datasource.DataSourceWithConfigure = (*groupDataSource)(nil)

// NewGroupDataSource returns the permio_group data source.
func NewGroupDataSource() datasource.DataSource { return &groupDataSource{} }

type groupDataSource struct{ pd *providerData }

type groupDataModel struct {
	ID          types.String `tfsdk:"id"`
	Project     types.String `tfsdk:"project"`
	Name        types.String `tfsdk:"name"`
	Description types.String `tfsdk:"description"`
	Principal   types.String `tfsdk:"principal"`
	Members     types.Set    `tfsdk:"members"`
}

func (d *groupDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_group"
}

func (d *groupDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Looks up a group and its members.",
		Attributes: map[string]schema.Attribute{
			"id":          schema.StringAttribute{MarkdownDescription: "Group ID.", Computed: true},
			"project":     dataSourceProjectAttribute(),
			"name":        schema.StringAttribute{MarkdownDescription: "Group name (slug).", Required: true, Validators: groupNameValidators()},
			"description": schema.StringAttribute{MarkdownDescription: "Description of the group.", Computed: true},
			"principal":   schema.StringAttribute{MarkdownDescription: "Principal ID to grant to: `group:<name>`.", Computed: true},
			"members":     schema.SetAttribute{MarkdownDescription: "Principal IDs of the group's members.", Computed: true, ElementType: types.StringType},
		},
	}
}

func (d *groupDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.pd = providerDataFrom(req.ProviderData, &resp.Diagnostics)
}

func (d *groupDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var m groupDataModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() || !requireClient(d.pd, &resp.Diagnostics) {
		return
	}
	project, name := projectOf(m.Project, d.pd), m.Name.ValueString()
	g, err := d.pd.client.API.GetGroup(ctx, &pb.GetGroupRequest{ProjectName: project, Name: name})
	if err != nil {
		client.AddError(&resp.Diagnostics, fmt.Sprintf("Unable to read group %q", name), err)
		return
	}
	members, err := d.pd.client.ListAllGroupMembers(ctx, project, name)
	if err != nil {
		client.AddError(&resp.Diagnostics, fmt.Sprintf("Unable to list the members of group %q", name), err)
		return
	}
	m.ID = types.StringValue(g.GetId())
	m.Project = types.StringValue(project)
	m.Description = types.StringValue(g.GetDescription())
	m.Principal = types.StringValue(groupPrincipal(g))
	m.Members = stringsToSet(members)
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}

// ---------------------------------------------------------------------------------------------------------------
// permio_check

var _ datasource.DataSourceWithConfigure = (*checkDataSource)(nil)

// NewCheckDataSource returns the permio_check data source.
func NewCheckDataSource() datasource.DataSource { return &checkDataSource{} }

type checkDataSource struct{ pd *providerData }

type checkDataModel struct {
	Project     types.String `tfsdk:"project"`
	Principal   types.String `tfsdk:"principal"`
	Resource    types.String `tfsdk:"resource"`
	Permissions types.Set    `tfsdk:"permissions"`
	Allowed     types.Bool   `tfsdk:"allowed"`
	Missing     types.Set    `tfsdk:"missing"`
}

func (d *checkDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_check"
}

func (d *checkDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Checks whether a principal holds permissions on a resource, exactly as your application's " +
			"permission checks would: counting grants on the resource and its ancestors, `_` wildcard grants, roles and " +
			"group memberships. Useful for policy tests, with `check` blocks or `terraform test`.\n\n" +
			"Data sources are read during planning, so a check that depends on grants created in the same run sees them " +
			"only once they exist (on the next plan, or in a later `terraform test` run block).",
		Attributes: map[string]schema.Attribute{
			"project": dataSourceProjectAttribute(),
			"principal": schema.StringAttribute{
				MarkdownDescription: "Principal ID to check: a user or service ID, or `group:<name>`.",
				Required:            true,
				Validators:          []validator.String{principalValidator()},
			},
			"resource": schema.StringAttribute{
				MarkdownDescription: "Resource URI to check.",
				Required:            true,
				Validators:          []validator.String{resourceURIValidator()},
			},
			"permissions": schema.SetAttribute{
				MarkdownDescription: "Permission names the principal must hold (1 to 100).",
				Required:            true,
				ElementType:         types.StringType,
				Validators:          []validator.Set{setvalidator.SizeBetween(1, 100), setvalidator.ValueStringsAre(stringvalidator.LengthAtLeast(1))},
			},
			"allowed": schema.BoolAttribute{MarkdownDescription: "Whether the principal holds every permission on the resource.", Computed: true},
			"missing": schema.SetAttribute{MarkdownDescription: "The requested permissions the principal does not hold.", Computed: true, ElementType: types.StringType},
		},
	}
}

func (d *checkDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.pd = providerDataFrom(req.ProviderData, &resp.Diagnostics)
}

func (d *checkDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var m checkDataModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() || !requireClient(d.pd, &resp.Diagnostics) {
		return
	}
	project := projectOf(m.Project, d.pd)
	perms := setToStrings(ctx, m.Permissions, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	res, err := d.pd.client.API.Check(ctx, &pb.CheckPermissionRequest{
		ProjectName: project, PrincipalId: m.Principal.ValueString(), ResourceUris: []string{m.Resource.ValueString()}, Permissions: perms,
	})
	if err != nil {
		client.AddError(&resp.Diagnostics, "Unable to check permissions", err)
		return
	}
	var missing []string
	for _, mp := range res.GetMissingPermissions() {
		missing = append(missing, mp.GetMissingPermissions()...)
	}
	m.Project = types.StringValue(project)
	m.Allowed = types.BoolValue(res.GetPassed())
	m.Missing = stringsToSet(missing)
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}
