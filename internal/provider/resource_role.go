package provider

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	pb "github.com/PrivateJAR/permio-go/proto/permissions/v1"
	"github.com/hashicorp/terraform-plugin-framework-timeouts/resource/timeouts"
	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"google.golang.org/grpc/codes"

	"github.com/PrivateJAR/terraform-provider-permio/internal/client"
)

var (
	_ resource.ResourceWithConfigure   = (*roleResource)(nil)
	_ resource.ResourceWithImportState = (*roleResource)(nil)
	_ resource.ResourceWithModifyPlan  = (*roleResource)(nil)
)

// NewRoleResource returns the permio_role resource.
func NewRoleResource() resource.Resource { return &roleResource{} }

type roleResource struct{ pd *providerData }

type roleModel struct {
	ID          types.String   `tfsdk:"id"`
	Project     types.String   `tfsdk:"project"`
	Name        types.String   `tfsdk:"name"`
	Description types.String   `tfsdk:"description"`
	Permissions types.Set      `tfsdk:"permissions"`
	Timeouts    timeouts.Value `tfsdk:"timeouts"`
}

func (r *roleResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_role"
}

func (r *roleResource) Schema(ctx context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "A role: a named set of permissions. Grant a role to a principal with `permio_grant`, using " +
			"the role's `id`.\n\nRole names are unique across the whole organisation, not just the project. A role can be " +
			"renamed in place.\n\n" +
			"If a permission that the role contains is deleted outside Terraform, Permio keeps referring to it from " +
			"the role, and the API then rejects every change to the role until the permission exists again. The " +
			"provider reports this as a warning that names the permission, keeps it in the role's state so that the " +
			"plan stays clean, and explains how to fix it: recreate the permission.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				MarkdownDescription: "Role ID assigned by Permio. Grants refer to roles by this ID.",
				Computed:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"project": resourceProjectAttribute(),
			"name": schema.StringAttribute{
				MarkdownDescription: "Role name: 1 to 128 characters, no control characters. Unique in the organisation.",
				Required:            true,
				Validators:          roleNameValidators(),
			},
			"description": schema.StringAttribute{
				MarkdownDescription: "Description of the role.",
				Optional:            true,
				Computed:            true,
				Default:             stringdefault.StaticString(""),
			},
			"permissions": schema.SetAttribute{
				MarkdownDescription: "Names of the permissions in the role. A role needs at least one permission, and " +
					"every permission must exist in the project.",
				Required:    true,
				ElementType: types.StringType,
				Validators: []validator.Set{
					setvalidator.SizeAtLeast(1),
					setvalidator.ValueStringsAre(permissionNameValidators()...),
				},
			},
		},
		Blocks: map[string]schema.Block{
			"timeouts": timeouts.Block(ctx, timeouts.Opts{Create: true, Read: true, Update: true, Delete: true}),
		},
	}
}

func (r *roleResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.pd = providerDataFrom(req.ProviderData, &resp.Diagnostics)
}

func (r *roleResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	planProject(ctx, r.pd, req, resp)
}

func (r *roleResource) setFromAPI(m *roleModel, project string, role *pb.Role) {
	m.ID = types.StringValue(role.GetId())
	m.Project = types.StringValue(project)
	m.Name = types.StringValue(role.GetName())
	m.Description = types.StringValue(role.GetDescription())
	m.Permissions = stringsToSet(client.PermissionNames(role))
}

func (r *roleResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan roleModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() || !requireClient(r.pd, &resp.Diagnostics) {
		return
	}
	t, d := plan.Timeouts.Create(ctx, defaultCreateTimeout)
	ctx, cancel := withTimeout(ctx, t, d, &resp.Diagnostics)
	defer cancel()

	project, name := projectOf(plan.Project, r.pd), plan.Name.ValueString()
	perms := setToStrings(ctx, plan.Permissions, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	// CreateRole silently returns an identical existing role, so check first to avoid taking over a role that
	// something else manages.
	existing, err := r.pd.client.FindRoleByName(ctx, project, name)
	if err != nil {
		client.AddError(&resp.Diagnostics, "Unable to check for an existing role", err)
		return
	}
	if existing != nil {
		resp.Diagnostics.AddError("Role already exists",
			fmt.Sprintf("A role called %q already exists in project %q (ID %s). Import it with: terraform import <address> %s/%s", name, project, existing.GetId(), project, existing.GetId()))
		return
	}

	role, err := r.pd.client.API.CreateRole(ctx, &pb.CreateRoleRequest{ProjectName: project, Name: name, Description: plan.Description.ValueString(), Permissions: perms})
	if err != nil {
		client.AddError(&resp.Diagnostics, "Unable to create role", err, internalHint(err,
			"Role names are unique across the organisation: check that no other project already has a role called "+name+"."))
		return
	}
	r.setFromAPI(&plan, project, role)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// getRole reads a role, or returns nil if it does not exist. GetRole fails with Internal for a role that refers to
// a permission which no longer exists; listing roles does not, so it is used as a fallback.
func getRole(ctx context.Context, c *client.Client, project, id string) (*pb.Role, error) {
	role, _, err := readRole(ctx, c, project, id)
	return role, err
}

// readRole is getRole that also reports whether the role had to be read from the role list because GetRole
// failed. That means the role refers to at least one permission that no longer exists, and the role returned
// leaves such permissions out (the list skips them). The API cannot update or delete such a role.
func readRole(ctx context.Context, c *client.Client, project, id string) (role *pb.Role, broken bool, err error) {
	role, err = c.API.GetRole(ctx, &pb.GetRoleRequest{ProjectName: project, Id: id})
	switch {
	case err == nil:
		return role, false, nil
	case client.IsNotFound(err):
		return nil, false, nil
	case client.Code(err) == codes.Internal:
		listed, listErr := c.FindRoleByID(ctx, project, id)
		if listErr != nil || listed == nil {
			return nil, false, err
		}
		return listed, true, nil
	default:
		return nil, false, err
	}
}

// deletedPermissions returns the names among candidates that no longer exist in the project.
func deletedPermissions(ctx context.Context, c *client.Client, project string, candidates []string) ([]string, error) {
	var deleted []string
	for _, name := range candidates {
		_, err := c.API.GetPermission(ctx, &pb.GetPermissionRequest{ProjectName: project, Name: name})
		switch {
		case client.IsNotFound(err):
			deleted = append(deleted, name)
		case err != nil:
			return nil, err
		}
	}
	return deleted, nil
}

const brokenRoleSummary = "Role refers to a permission that no longer exists"

// brokenRoleDetail explains a role that refers to deleted permissions, and what to do about it.
func brokenRoleDetail(role *pb.Role, project string, deleted []string) string {
	which := "at least one permission that no longer exists in project " + strconv.Quote(project) +
		" (the API does not say which: compare the role's permissions with the ones you expect)"
	if len(deleted) > 0 {
		quoted := make([]string, len(deleted))
		for i, n := range deleted {
			quoted[i] = strconv.Quote(n)
		}
		which = "the permission(s) " + strings.Join(quoted, ", ") + ", which no longer exist in project " + strconv.Quote(project)
	}
	return fmt.Sprintf("The role %q (ID %s) refers to %s. Permio does not remove a deleted permission from roles. "+
		"The role does not grant a permission that no longer exists, and until the permission exists again the "+
		"Permio API rejects every change to the role, including removing the permission from it and deleting the "+
		"role.\n\n"+
		"To fix it, recreate the permission with the same name in the same project (for example by restoring its "+
		"permio_permission resource) and apply. The role then grants it again, and you can remove the permission "+
		"from the role's permissions, and delete it, as usual.\n\n"+
		"Until then, keep the permission in the role's permissions: Terraform keeps it in the role's state, so the "+
		"plan does not try to change the role. Removing it from the configuration makes the next apply fail with "+
		"this error.", role.GetName(), role.GetId(), which)
}

// explainBrokenRole adds a clear error if a failed change to a role failed because the role refers to a deleted
// permission, and reports whether it did.
func explainBrokenRole(ctx context.Context, c *client.Client, project, id string, known []string, summary string, diags *diag.Diagnostics) bool {
	role, broken, err := readRole(ctx, c, project, id)
	if err != nil || !broken {
		return false
	}
	deleted, err := deletedPermissions(ctx, c, project, difference(known, client.PermissionNames(role)))
	if err != nil {
		return false
	}
	diags.AddError(summary, brokenRoleDetail(role, project, deleted))
	return true
}

func (r *roleResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state roleModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() || !requireClient(r.pd, &resp.Diagnostics) {
		return
	}
	t, d := state.Timeouts.Read(ctx, defaultReadTimeout)
	ctx, cancel := withTimeout(ctx, t, d, &resp.Diagnostics)
	defer cancel()

	project := projectOf(state.Project, r.pd)
	known := setToStrings(ctx, state.Permissions, &resp.Diagnostics)
	role, broken, err := readRole(ctx, r.pd.client, project, state.ID.ValueString())
	if err != nil {
		client.AddError(&resp.Diagnostics, "Unable to read role", err)
		return
	}
	if role == nil {
		resp.State.RemoveResource(ctx)
		return
	}
	r.setFromAPI(&state, project, role)
	if broken {
		// The role still refers to permissions that were deleted, and the API cannot change it until they exist
		// again. Keep the deleted permissions that the state already has, so that the plan does not try (and fail)
		// to add them back, and say what is wrong on every plan.
		listed := client.PermissionNames(role)
		deleted, err := deletedPermissions(ctx, r.pd.client, project, difference(known, listed))
		if err != nil {
			client.AddError(&resp.Diagnostics, "Unable to read role", err)
			return
		}
		state.Permissions = stringsToSet(append(listed, deleted...))
		resp.Diagnostics.AddWarning(brokenRoleSummary, brokenRoleDetail(role, project, deleted))
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *roleResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state roleModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() || !requireClient(r.pd, &resp.Diagnostics) {
		return
	}
	t, d := plan.Timeouts.Update(ctx, defaultUpdateTimeout)
	ctx, cancel := withTimeout(ctx, t, d, &resp.Diagnostics)
	defer cancel()

	project := projectOf(plan.Project, r.pd)
	perms := setToStrings(ctx, plan.Permissions, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	role, err := r.pd.client.API.UpdateRole(ctx, &pb.UpdateRoleRequest{
		ProjectName: project, Id: plan.ID.ValueString(), Name: plan.Name.ValueString(), Description: plan.Description.ValueString(), Permissions: perms,
	})
	if err != nil {
		known := setToStrings(ctx, state.Permissions, &resp.Diagnostics)
		if !explainBrokenRole(ctx, r.pd.client, project, plan.ID.ValueString(), known, "Unable to update role", &resp.Diagnostics) {
			client.AddError(&resp.Diagnostics, "Unable to update role", err)
		}
		return
	}
	r.setFromAPI(&plan, project, role)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *roleResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state roleModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() || !requireClient(r.pd, &resp.Diagnostics) {
		return
	}
	t, d := state.Timeouts.Delete(ctx, defaultDeleteTimeout)
	ctx, cancel := withTimeout(ctx, t, d, &resp.Diagnostics)
	defer cancel()

	project := projectOf(state.Project, r.pd)
	_, err := r.pd.client.API.DeleteRole(ctx, &pb.DeleteRoleRequest{ProjectName: project, Id: state.ID.ValueString()})
	if err != nil && !client.IsNotFound(err) {
		known := setToStrings(ctx, state.Permissions, &resp.Diagnostics)
		if !explainBrokenRole(ctx, r.pd.client, project, state.ID.ValueString(), known, "Unable to delete role", &resp.Diagnostics) {
			client.AddError(&resp.Diagnostics, "Unable to delete role", err)
		}
	}
}

func (r *roleResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	project, ref, err := parseRoleID(req.ID)
	if err != nil {
		resp.Diagnostics.AddError("Invalid import ID", importIDError(req.ID, `"<project>/<role ID>" or "<project>/<role name>"`,
			`default/Document editor`, err))
		return
	}
	if !requireClient(r.pd, &resp.Diagnostics) {
		return
	}
	// Accept a role ID or, failing that, a role name.
	id := ""
	if roleIDPattern.MatchString(ref) {
		role, err := getRole(ctx, r.pd.client, project, ref)
		if err != nil {
			client.AddError(&resp.Diagnostics, "Unable to read role", err)
			return
		}
		if role != nil {
			id = role.GetId()
		}
	}
	if id == "" {
		role, err := r.pd.client.FindRoleByName(ctx, project, ref)
		if err != nil {
			client.AddError(&resp.Diagnostics, "Unable to look up role", err)
			return
		}
		if role == nil {
			resp.Diagnostics.AddError("Role not found", fmt.Sprintf("No role with ID or name %q exists in project %q.", ref, project))
			return
		}
		id = role.GetId()
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("project"), project)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), id)...)
}
