package provider

import (
	"context"
	"github.com/hashicorp/terraform-plugin-framework-timeouts/resource/timeouts"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/PrivateJAR/terraform-provider-permio/internal/client"
)

var (
	_ resource.ResourceWithConfigure   = (*groupMemberResource)(nil)
	_ resource.ResourceWithImportState = (*groupMemberResource)(nil)
	_ resource.ResourceWithModifyPlan  = (*groupMemberResource)(nil)
)

// NewGroupMemberResource returns the permio_group_member resource.
func NewGroupMemberResource() resource.Resource { return &groupMemberResource{} }

type groupMemberResource struct{ pd *providerData }

type groupMemberModel struct {
	ID        types.String   `tfsdk:"id"`
	Project   types.String   `tfsdk:"project"`
	Group     types.String   `tfsdk:"group"`
	Principal types.String   `tfsdk:"principal"`
	Timeouts  timeouts.Value `tfsdk:"timeouts"`
}

func (r *groupMemberResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_group_member"
}

func (r *groupMemberResource) Schema(ctx context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "One member of a group. This resource is **non-authoritative**: it only manages its own " +
			"membership and leaves other members alone, so several `permio_group_member` resources (and members added " +
			"outside Terraform) can coexist on one group.\n\n" +
			"Do not use it on a group that is also managed by `permio_group_members`, which removes every member it " +
			"does not list.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				MarkdownDescription: "`<project>/<group>/<principal>`, which is also the import ID.",
				Computed:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"project": resourceProjectAttribute(),
			"group": schema.StringAttribute{
				MarkdownDescription: "Name (slug) of the group, for example `permio_group.engineering.name`.",
				Required:            true,
				Validators:          groupNameValidators(),
				PlanModifiers:       []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"principal": schema.StringAttribute{
				MarkdownDescription: "Principal ID of the member. Group principals (`group:...`) are not allowed.",
				Required:            true,
				Validators:          []validator.String{memberValidator()},
				PlanModifiers:       []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
		},
		Blocks: map[string]schema.Block{
			"timeouts": timeouts.Block(ctx, timeouts.Opts{Create: true, Read: true, Delete: true}),
		},
	}
}

func (r *groupMemberResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.pd = providerDataFrom(req.ProviderData, &resp.Diagnostics)
}

func (r *groupMemberResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	planProject(ctx, r.pd, req, resp)
}

func (r *groupMemberResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan groupMemberModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() || !requireClient(r.pd, &resp.Diagnostics) {
		return
	}
	t, d := plan.Timeouts.Create(ctx, defaultCreateTimeout)
	ctx, cancel := withTimeout(ctx, t, d, &resp.Diagnostics)
	defer cancel()

	project, group, principal := projectOf(plan.Project, r.pd), plan.Group.ValueString(), plan.Principal.ValueString()
	if err := r.pd.client.AddGroupMembers(ctx, project, group, []string{principal}); err != nil {
		client.AddError(&resp.Diagnostics, "Unable to add group member", err)
		return
	}
	plan.ID = types.StringValue(project + "/" + group + "/" + principal)
	plan.Project = types.StringValue(project)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *groupMemberResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state groupMemberModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() || !requireClient(r.pd, &resp.Diagnostics) {
		return
	}
	t, d := state.Timeouts.Read(ctx, defaultReadTimeout)
	ctx, cancel := withTimeout(ctx, t, d, &resp.Diagnostics)
	defer cancel()

	project, group, principal := projectOf(state.Project, r.pd), state.Group.ValueString(), state.Principal.ValueString()
	member, err := r.pd.client.IsGroupMember(ctx, project, group, principal)
	if err != nil {
		client.AddError(&resp.Diagnostics, "Unable to read group membership", err)
		return
	}
	if !member {
		resp.State.RemoveResource(ctx)
		return
	}
	state.ID = types.StringValue(project + "/" + group + "/" + principal)
	state.Project = types.StringValue(project)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *groupMemberResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	// Every attribute requires replacement, so only the timeouts can change.
	var plan groupMemberModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *groupMemberResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state groupMemberModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() || !requireClient(r.pd, &resp.Diagnostics) {
		return
	}
	t, d := state.Timeouts.Delete(ctx, defaultDeleteTimeout)
	ctx, cancel := withTimeout(ctx, t, d, &resp.Diagnostics)
	defer cancel()

	err := r.pd.client.RemoveGroupMembers(ctx, projectOf(state.Project, r.pd), state.Group.ValueString(), []string{state.Principal.ValueString()})
	if err != nil && !client.IsNotFound(err) {
		client.AddError(&resp.Diagnostics, "Unable to remove group member", err)
	}
}

func (r *groupMemberResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	project, group, principal, err := parseGroupMemberID(req.ID)
	if err != nil {
		resp.Diagnostics.AddError("Invalid import ID", importIDError(req.ID, `"<project>/<group>/<principal>"`,
			`default/engineering/user/alice@example.com`, err))
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("project"), project)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("group"), group)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("principal"), principal)...)
}
