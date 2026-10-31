package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework-timeouts/resource/timeouts"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	pb "github.com/perms-io/permio-go/proto/permissions/v1"

	"github.com/perms-io/terraform-provider-permio/internal/client"
)

var (
	_ resource.ResourceWithConfigure   = (*groupResource)(nil)
	_ resource.ResourceWithImportState = (*groupResource)(nil)
	_ resource.ResourceWithModifyPlan  = (*groupResource)(nil)
)

// NewGroupResource returns the permio_group resource.
func NewGroupResource() resource.Resource { return &groupResource{} }

type groupResource struct{ pd *providerData }

type groupModel struct {
	ID          types.String   `tfsdk:"id"`
	Project     types.String   `tfsdk:"project"`
	Name        types.String   `tfsdk:"name"`
	Description types.String   `tfsdk:"description"`
	Principal   types.String   `tfsdk:"principal"`
	Timeouts    timeouts.Value `tfsdk:"timeouts"`
}

func (r *groupResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_group"
}

func (r *groupResource) Schema(ctx context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "A group: a named set of principals in a project. Grants made to the group's `principal` " +
			"(`group:<name>`) apply to every member. Groups cannot contain groups.\n\n" +
			"Manage members with `permio_group_members` (authoritative) or `permio_group_member` (one member each).\n\n" +
			"Groups cannot be renamed, because `group:<name>` is the principal ID their grants are stored under, so " +
			"changing `name` replaces the group. Deleting a group also deletes its memberships and every grant made to it.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				MarkdownDescription: "Group ID assigned by Permio.",
				Computed:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"project": resourceProjectAttribute(),
			"name": schema.StringAttribute{
				MarkdownDescription: "Group slug: 1 to 64 lower-case letters, digits and hyphens. Unique in the project. " +
					"Changing it replaces the group.",
				Required:      true,
				Validators:    groupNameValidators(),
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"description": schema.StringAttribute{
				MarkdownDescription: "Description of the group, at most 1024 characters.",
				Optional:            true,
				Computed:            true,
				Default:             stringdefault.StaticString(""),
				Validators:          []validator.String{stringvalidator.LengthAtMost(maxGroupDescription)},
			},
			"principal": schema.StringAttribute{
				MarkdownDescription: "Principal ID to grant to: `group:<name>`. Use it as `permio_grant.principal`.",
				Computed:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
		},
		Blocks: map[string]schema.Block{
			"timeouts": timeouts.Block(ctx, timeouts.Opts{Create: true, Read: true, Update: true, Delete: true}),
		},
	}
}

func (r *groupResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.pd = providerDataFrom(req.ProviderData, &resp.Diagnostics)
}

func (r *groupResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	planProject(ctx, r.pd, req, resp)
	if req.Plan.Raw.IsNull() {
		return
	}
	// The principal is known from the name at plan time, so grants can refer to it before the group exists.
	var name types.String
	resp.Diagnostics.Append(resp.Plan.GetAttribute(ctx, path.Root("name"), &name)...)
	if !name.IsUnknown() && !name.IsNull() {
		resp.Diagnostics.Append(resp.Plan.SetAttribute(ctx, path.Root("principal"), groupPrincipalPrefix+name.ValueString())...)
	}
}

func setGroupFromAPI(m *groupModel, project string, g *pb.Group) {
	m.ID = types.StringValue(g.GetId())
	m.Project = types.StringValue(project)
	m.Name = types.StringValue(g.GetName())
	m.Description = types.StringValue(g.GetDescription())
	m.Principal = types.StringValue(groupPrincipal(g))
}

// groupPrincipal returns the principal ID that grants to the group are made to, as reported by the API. The API
// always reports "group:<name>", which is also what the resource plans before the group exists; the fallback only
// covers an API that leaves the field out.
func groupPrincipal(g *pb.Group) string {
	if p := g.GetPrincipalId(); p != "" {
		return p
	}
	return groupPrincipalPrefix + g.GetName()
}

func (r *groupResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan groupModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() || !requireClient(r.pd, &resp.Diagnostics) {
		return
	}
	t, d := plan.Timeouts.Create(ctx, defaultCreateTimeout)
	ctx, cancel := withTimeout(ctx, t, d, &resp.Diagnostics)
	defer cancel()

	project, name := projectOf(plan.Project, r.pd), plan.Name.ValueString()
	g, err := r.pd.client.API.CreateGroup(ctx, &pb.CreateGroupRequest{ProjectName: project, Name: name, Description: plan.Description.ValueString()})
	if client.IsAlreadyExists(err) {
		resp.Diagnostics.AddError("Group already exists",
			fmt.Sprintf("A group called %q already exists in project %q. Import it with: terraform import <address> %s/%s", name, project, project, name))
		return
	}
	if err != nil {
		client.AddError(&resp.Diagnostics, "Unable to create group", err)
		return
	}
	setGroupFromAPI(&plan, project, g)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *groupResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state groupModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() || !requireClient(r.pd, &resp.Diagnostics) {
		return
	}
	t, d := state.Timeouts.Read(ctx, defaultReadTimeout)
	ctx, cancel := withTimeout(ctx, t, d, &resp.Diagnostics)
	defer cancel()

	project := projectOf(state.Project, r.pd)
	g, err := r.pd.client.API.GetGroup(ctx, &pb.GetGroupRequest{ProjectName: project, Name: state.Name.ValueString()})
	if client.IsNotFound(err) {
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		client.AddError(&resp.Diagnostics, "Unable to read group", err)
		return
	}
	setGroupFromAPI(&state, project, g)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *groupResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan groupModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() || !requireClient(r.pd, &resp.Diagnostics) {
		return
	}
	t, d := plan.Timeouts.Update(ctx, defaultUpdateTimeout)
	ctx, cancel := withTimeout(ctx, t, d, &resp.Diagnostics)
	defer cancel()

	project := projectOf(plan.Project, r.pd)
	g, err := r.pd.client.API.UpdateGroup(ctx, &pb.UpdateGroupRequest{ProjectName: project, Name: plan.Name.ValueString(), Description: plan.Description.ValueString()})
	if err != nil {
		client.AddError(&resp.Diagnostics, "Unable to update group", err)
		return
	}
	setGroupFromAPI(&plan, project, g)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *groupResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state groupModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() || !requireClient(r.pd, &resp.Diagnostics) {
		return
	}
	t, d := state.Timeouts.Delete(ctx, defaultDeleteTimeout)
	ctx, cancel := withTimeout(ctx, t, d, &resp.Diagnostics)
	defer cancel()

	_, err := r.pd.client.API.DeleteGroup(ctx, &pb.DeleteGroupRequest{ProjectName: projectOf(state.Project, r.pd), Name: state.Name.ValueString()})
	if err != nil && !client.IsNotFound(err) {
		client.AddError(&resp.Diagnostics, "Unable to delete group", err)
	}
}

func (r *groupResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	project, name, err := splitProjectID(req.ID, r.pd)
	if err == nil {
		err = validateGroupName(name)
		if err != nil {
			err = fmt.Errorf("the group %q %v", name, err)
		}
	}
	if err != nil {
		resp.Diagnostics.AddError("Invalid import ID", importIDError(req.ID, `"<project>/<group>" or "<group>"`, `default/engineering`, err))
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("project"), project)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("name"), name)...)
}
