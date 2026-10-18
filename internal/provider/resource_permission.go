package provider

import (
	"context"
	"fmt"
	"slices"
	"strings"

	pb "github.com/PrivateJAR/permio-go/proto/permissions/v1"
	"github.com/hashicorp/terraform-plugin-framework-timeouts/resource/timeouts"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"google.golang.org/protobuf/proto"

	"github.com/PrivateJAR/terraform-provider-permio/internal/client"
)

var (
	_ resource.ResourceWithConfigure   = (*permissionResource)(nil)
	_ resource.ResourceWithImportState = (*permissionResource)(nil)
	_ resource.ResourceWithModifyPlan  = (*permissionResource)(nil)
)

// NewPermissionResource returns the permio_permission resource.
func NewPermissionResource() resource.Resource { return &permissionResource{} }

type permissionResource struct{ pd *providerData }

type permissionModel struct {
	ID          types.String   `tfsdk:"id"`
	Project     types.String   `tfsdk:"project"`
	Name        types.String   `tfsdk:"name"`
	Description types.String   `tfsdk:"description"`
	Timeouts    timeouts.Value `tfsdk:"timeouts"`
}

func (r *permissionResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_permission"
}

func (r *permissionResource) Schema(ctx context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "A permission: an action that can be performed on a resource, such as `document.read`. " +
			"Permissions are granted to principals directly or through roles.\n\n" +
			"Permission names are unique across the whole organisation, not just the project.\n\n" +
			"Renaming a permission is done in place. Roles in the project that contain the permission keep it under " +
			"its new name: if any role contains it, the provider creates the permission under the new name, moves " +
			"those roles over and deletes the old one (so `id` changes). Grants are not rewritten, so grant the new name " +
			"(for example by referencing `permio_permission.<name>.name` from `permio_grant`).\n\n" +
			"Deleting a permission first removes it from the roles in the project that contain it, because the API " +
			"cannot read a role that refers to a deleted permission. It fails if the permission is a role's only one.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				MarkdownDescription: "Permission ID assigned by Permio.",
				Computed:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"project": resourceProjectAttribute(),
			"name": schema.StringAttribute{
				MarkdownDescription: "Permission name: 1 to 128 letters, digits, `.`, `_` and `-`. Unique in the organisation.",
				Required:            true,
				Validators:          permissionNameValidators(),
			},
			"description": schema.StringAttribute{
				MarkdownDescription: "Description of the permission.",
				Optional:            true,
				Computed:            true,
				Default:             stringdefault.StaticString(""),
			},
		},
		Blocks: map[string]schema.Block{
			"timeouts": timeouts.Block(ctx, timeouts.Opts{Create: true, Read: true, Update: true, Delete: true}),
		},
	}
}

func (r *permissionResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.pd = providerDataFrom(req.ProviderData, &resp.Diagnostics)
}

func (r *permissionResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	planProject(ctx, r.pd, req, resp)
	if req.State.Raw.IsNull() || req.Plan.Raw.IsNull() {
		return
	}
	var prior, planned types.String
	resp.Diagnostics.Append(req.State.GetAttribute(ctx, path.Root("name"), &prior)...)
	resp.Diagnostics.Append(resp.Plan.GetAttribute(ctx, path.Root("name"), &planned)...)
	if planned.IsUnknown() || prior.ValueString() != planned.ValueString() {
		// A rename may recreate the permission under a new ID.
		resp.Diagnostics.Append(resp.Plan.SetAttribute(ctx, path.Root("id"), types.StringUnknown())...)
	}
}

func (r *permissionResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan permissionModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() || !requireClient(r.pd, &resp.Diagnostics) {
		return
	}
	t, d := plan.Timeouts.Create(ctx, defaultCreateTimeout)
	ctx, cancel := withTimeout(ctx, t, d, &resp.Diagnostics)
	defer cancel()

	project, name := projectOf(plan.Project, r.pd), plan.Name.ValueString()
	api := r.pd.client.API

	// CreatePermission silently returns an identical existing permission, so check first to avoid taking over a
	// permission that something else manages.
	existing, err := api.GetPermission(ctx, &pb.GetPermissionRequest{ProjectName: project, Name: name})
	switch {
	case err == nil:
		resp.Diagnostics.AddError("Permission already exists",
			fmt.Sprintf("The permission %q already exists in project %q (ID %s). Import it with: terraform import <address> %s/%s", name, project, existing.GetId(), project, name))
		return
	case !client.IsNotFound(err):
		client.AddError(&resp.Diagnostics, "Unable to check for an existing permission", err)
		return
	}

	p, err := api.CreatePermission(ctx, &pb.CreatePermissionRequest{ProjectName: project, Name: name, Description: plan.Description.ValueString()})
	if err != nil {
		client.AddError(&resp.Diagnostics, "Unable to create permission", err, internalHint(err,
			"Permission names are unique across the organisation: check that no other project already has a permission called "+name+"."))
		return
	}
	plan.ID = types.StringValue(p.GetId())
	plan.Project = types.StringValue(project)
	plan.Description = types.StringValue(p.GetDescription())
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *permissionResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state permissionModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() || !requireClient(r.pd, &resp.Diagnostics) {
		return
	}
	t, d := state.Timeouts.Read(ctx, defaultReadTimeout)
	ctx, cancel := withTimeout(ctx, t, d, &resp.Diagnostics)
	defer cancel()

	project := projectOf(state.Project, r.pd)
	p, err := r.pd.client.API.GetPermission(ctx, &pb.GetPermissionRequest{ProjectName: project, Name: state.Name.ValueString()})
	if client.IsNotFound(err) {
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		client.AddError(&resp.Diagnostics, "Unable to read permission", err)
		return
	}
	state.ID = types.StringValue(p.GetId())
	state.Project = types.StringValue(project)
	state.Name = types.StringValue(p.GetName())
	state.Description = types.StringValue(p.GetDescription())
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *permissionResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state permissionModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() || !requireClient(r.pd, &resp.Diagnostics) {
		return
	}
	t, d := plan.Timeouts.Update(ctx, defaultUpdateTimeout)
	ctx, cancel := withTimeout(ctx, t, d, &resp.Diagnostics)
	defer cancel()

	project := projectOf(plan.Project, r.pd)
	oldName, newName, desc := state.Name.ValueString(), plan.Name.ValueString(), plan.Description.ValueString()
	api := r.pd.client.API

	var result *pb.Permission
	var err error
	if oldName == newName {
		result, err = api.UpdatePermission(ctx, &pb.UpdatePermissionRequest{ProjectName: project, Name: oldName, Description: desc})
		if err != nil {
			client.AddError(&resp.Diagnostics, "Unable to update permission", err)
			return
		}
	} else {
		result, err = r.rename(ctx, project, oldName, newName, desc, &resp.Diagnostics)
		if err != nil {
			return
		}
	}
	plan.ID = types.StringValue(result.GetId())
	plan.Project = types.StringValue(project)
	plan.Description = types.StringValue(result.GetDescription())
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// rename renames a permission. The API's rename does not update roles that contain the permission, and a role that
// refers to a permission that no longer exists can no longer be read or updated. So when roles contain the
// permission, the new permission is created alongside the old one, the roles are switched over, and the old one is
// deleted.
func (r *permissionResource) rename(ctx context.Context, project, oldName, newName, desc string, diags *diag.Diagnostics) (*pb.Permission, error) {
	api := r.pd.client.API
	roles, err := r.pd.client.ListAllRoles(ctx, project, "")
	if err != nil {
		diags.AddError("Unable to list roles", client.Describe(err))
		return nil, err
	}
	var referencing []*pb.Role
	for _, role := range roles {
		if slices.Contains(client.PermissionNames(role), oldName) {
			referencing = append(referencing, role)
		}
	}

	if len(referencing) == 0 {
		p, err := api.UpdatePermission(ctx, &pb.UpdatePermissionRequest{ProjectName: project, Name: oldName, NewName: proto.String(newName), Description: desc})
		if err != nil {
			client.AddError(diags, "Unable to rename permission", err, internalHint(err,
				"Permission names are unique across the organisation: check that no other permission is called "+newName+"."))
			return nil, err
		}
		return p, nil
	}

	p, err := api.CreatePermission(ctx, &pb.CreatePermissionRequest{ProjectName: project, Name: newName, Description: desc})
	if err != nil {
		client.AddError(diags, "Unable to create the renamed permission", err, internalHint(err,
			"Permission names are unique across the organisation: check that no other permission is called "+newName+"."))
		return nil, err
	}
	for _, role := range referencing {
		perms := client.PermissionNames(role)
		for i, n := range perms {
			if n == oldName {
				perms[i] = newName
			}
		}
		perms = slices.Compact(sortedCopy(perms))
		if _, err := api.UpdateRole(ctx, &pb.UpdateRoleRequest{ProjectName: project, Id: role.GetId(), Name: role.GetName(), Description: role.GetDescription(), Permissions: perms}); err != nil {
			diags.AddError("Unable to move role to the renamed permission",
				fmt.Sprintf("Updating role %q (%s) failed: %s\n\nBoth permissions %q and %q now exist; re-run apply to finish the rename.", role.GetName(), role.GetId(), client.Describe(err), oldName, newName))
			return nil, err
		}
	}
	if err := deletePermission(ctx, r.pd.client, project, oldName); err != nil {
		diags.AddError("Unable to delete the old permission", client.Describe(err))
		return nil, err
	}
	return p, nil
}

func (r *permissionResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state permissionModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() || !requireClient(r.pd, &resp.Diagnostics) {
		return
	}
	t, d := state.Timeouts.Delete(ctx, defaultDeleteTimeout)
	ctx, cancel := withTimeout(ctx, t, d, &resp.Diagnostics)
	defer cancel()

	project, name := projectOf(state.Project, r.pd), state.Name.ValueString()
	c := r.pd.client

	roles, err := c.ListAllRoles(ctx, project, "")
	if err != nil {
		client.AddError(&resp.Diagnostics, "Unable to list roles", err)
		return
	}
	for _, role := range roles {
		perms := client.PermissionNames(role)
		if !slices.Contains(perms, name) {
			continue
		}
		remaining := slices.DeleteFunc(perms, func(n string) bool { return n == name })
		if len(remaining) == 0 {
			resp.Diagnostics.AddError("Permission is still a role's only permission",
				fmt.Sprintf("The permission %q is the only permission of role %q (%s), and a role must have at least one permission. Change or delete the role first.", name, role.GetName(), role.GetId()))
			return
		}
		if _, err := c.API.UpdateRole(ctx, &pb.UpdateRoleRequest{ProjectName: project, Id: role.GetId(), Name: role.GetName(), Description: role.GetDescription(), Permissions: sortedCopy(remaining)}); err != nil {
			client.AddError(&resp.Diagnostics, fmt.Sprintf("Unable to remove the permission from role %q", role.GetName()), err)
			return
		}
	}

	if err := deletePermission(ctx, c, project, name); err != nil {
		client.AddError(&resp.Diagnostics, "Unable to delete permission", err)
	}
}

// deletePermission deletes a permission, treating a permission that does not exist as deleted. (The API reports
// Internal rather than success for a permission that does not exist.)
func deletePermission(ctx context.Context, c *client.Client, project, name string) error {
	if _, err := c.API.DeletePermission(ctx, &pb.DeletePermissionRequest{ProjectName: project, Name: name}); err != nil {
		if _, getErr := c.API.GetPermission(ctx, &pb.GetPermissionRequest{ProjectName: project, Name: name}); client.IsNotFound(getErr) {
			return nil
		}
		return err
	}
	return nil
}

func (r *permissionResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	project, name, ok := splitProjectID(req.ID, r.pd)
	if !ok || !permissionPattern.MatchString(name) {
		resp.Diagnostics.AddError("Invalid import ID", fmt.Sprintf("Expected \"<project>/<name>\" or \"<name>\", got %q.", req.ID))
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("project"), project)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("name"), name)...)
}

// splitProjectID splits an import ID of the form "<project>/<rest>" or "<rest>" (using the provider's project).
func splitProjectID(id string, pd *providerData) (project, rest string, ok bool) {
	if p, r, found := strings.Cut(id, "/"); found {
		if !projectPattern.MatchString(p) || len(p) > 32 || r == "" {
			return "", "", false
		}
		return p, r, true
	}
	if id == "" || pd == nil {
		return "", "", false
	}
	return pd.project, id, true
}

func sortedCopy(s []string) []string {
	out := slices.Clone(s)
	slices.Sort(out)
	return out
}
