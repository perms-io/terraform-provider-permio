package provider

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-timeouts/resource/timeouts"
	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
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
	_ resource.ResourceWithConfigure   = (*groupMembersResource)(nil)
	_ resource.ResourceWithImportState = (*groupMembersResource)(nil)
	_ resource.ResourceWithModifyPlan  = (*groupMembersResource)(nil)
)

// NewGroupMembersResource returns the permio_group_members resource.
func NewGroupMembersResource() resource.Resource { return &groupMembersResource{} }

type groupMembersResource struct{ pd *providerData }

type groupMembersModel struct {
	ID       types.String   `tfsdk:"id"`
	Project  types.String   `tfsdk:"project"`
	Group    types.String   `tfsdk:"group"`
	Members  types.Set      `tfsdk:"members"`
	Timeouts timeouts.Value `tfsdk:"timeouts"`
}

func (r *groupMembersResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_group_members"
}

func (r *groupMembersResource) Schema(ctx context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "The complete member list of a group. This resource is **authoritative**: on every apply " +
			"it adds the listed principals and removes any other member of the group, including members added outside " +
			"Terraform. Destroying it removes every member from the group (the group itself is kept).\n\n" +
			"Use at most one `permio_group_members` per group, and do not combine it with `permio_group_member` on the " +
			"same group: the two would keep undoing each other's changes.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				MarkdownDescription: "`<project>/<group>`.",
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
			"members": schema.SetAttribute{
				MarkdownDescription: "Principal IDs of all members. An empty set removes every member. Group principals " +
					"(`group:...`) are not allowed, because groups cannot be nested.",
				Required:    true,
				ElementType: types.StringType,
				Validators:  []validator.Set{setvalidator.ValueStringsAre(memberValidator())},
			},
		},
		Blocks: map[string]schema.Block{
			"timeouts": timeouts.Block(ctx, timeouts.Opts{Create: true, Read: true, Update: true, Delete: true}),
		},
	}
}

func (r *groupMembersResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.pd = providerDataFrom(req.ProviderData, &resp.Diagnostics)
}

func (r *groupMembersResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	planProject(ctx, r.pd, req, resp)
}

// sync makes the group's members exactly desired.
func (r *groupMembersResource) sync(ctx context.Context, project, group string, desired []string) error {
	current, err := r.pd.client.ListAllGroupMembers(ctx, project, group)
	if err != nil {
		return err
	}
	if add := difference(desired, current); len(add) > 0 {
		if err := r.pd.client.AddGroupMembers(ctx, project, group, add); err != nil {
			return err
		}
	}
	if remove := difference(current, desired); len(remove) > 0 {
		if err := r.pd.client.RemoveGroupMembers(ctx, project, group, remove); err != nil {
			return err
		}
	}
	return nil
}

func (r *groupMembersResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan groupMembersModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() || !requireClient(r.pd, &resp.Diagnostics) {
		return
	}
	t, d := plan.Timeouts.Create(ctx, defaultCreateTimeout)
	ctx, cancel := withTimeout(ctx, t, d, &resp.Diagnostics)
	defer cancel()

	project, group := projectOf(plan.Project, r.pd), plan.Group.ValueString()
	desired := setToStrings(ctx, plan.Members, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.sync(ctx, project, group, desired); err != nil {
		client.AddError(&resp.Diagnostics, "Unable to set group members", err)
		return
	}
	plan.ID = types.StringValue(project + "/" + group)
	plan.Project = types.StringValue(project)
	plan.Members = stringsToSet(desired)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *groupMembersResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state groupMembersModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() || !requireClient(r.pd, &resp.Diagnostics) {
		return
	}
	t, d := state.Timeouts.Read(ctx, defaultReadTimeout)
	ctx, cancel := withTimeout(ctx, t, d, &resp.Diagnostics)
	defer cancel()

	project, group := projectOf(state.Project, r.pd), state.Group.ValueString()
	members, err := r.pd.client.ListAllGroupMembers(ctx, project, group)
	if client.IsNotFound(err) {
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		client.AddError(&resp.Diagnostics, "Unable to read group members", err)
		return
	}
	state.ID = types.StringValue(project + "/" + group)
	state.Project = types.StringValue(project)
	state.Members = stringsToSet(members)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *groupMembersResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan groupMembersModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() || !requireClient(r.pd, &resp.Diagnostics) {
		return
	}
	t, d := plan.Timeouts.Update(ctx, defaultUpdateTimeout)
	ctx, cancel := withTimeout(ctx, t, d, &resp.Diagnostics)
	defer cancel()

	project, group := projectOf(plan.Project, r.pd), plan.Group.ValueString()
	desired := setToStrings(ctx, plan.Members, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.sync(ctx, project, group, desired); err != nil {
		client.AddError(&resp.Diagnostics, "Unable to update group members", err)
		return
	}
	plan.ID = types.StringValue(project + "/" + group)
	plan.Project = types.StringValue(project)
	plan.Members = stringsToSet(desired)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *groupMembersResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state groupMembersModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() || !requireClient(r.pd, &resp.Diagnostics) {
		return
	}
	t, d := state.Timeouts.Delete(ctx, defaultDeleteTimeout)
	ctx, cancel := withTimeout(ctx, t, d, &resp.Diagnostics)
	defer cancel()

	err := r.sync(ctx, projectOf(state.Project, r.pd), state.Group.ValueString(), nil)
	if err != nil && !client.IsNotFound(err) {
		client.AddError(&resp.Diagnostics, "Unable to remove group members", err)
	}
}

func (r *groupMembersResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	project, group, ok := splitProjectID(req.ID, r.pd)
	if !ok || strings.Contains(group, "/") || !groupNamePattern.MatchString(group) {
		resp.Diagnostics.AddError("Invalid import ID", fmt.Sprintf("Expected \"<project>/<group name>\" or \"<group name>\", got %q.", req.ID))
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("project"), project)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("group"), group)...)
}
