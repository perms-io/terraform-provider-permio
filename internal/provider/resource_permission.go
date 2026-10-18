package provider

import (
	"context"
	"encoding/json"
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
			"those roles over and deletes the old one (so `id` changes). If that is interrupted, the next apply finishes " +
			"it. A rename fails, rather than taking the permission over, if a permission with the new name already " +
			"exists. Grants are not rewritten, so grant the new name (for example by referencing " +
			"`permio_permission.<name>.name` from `permio_grant`).\n\n" +
			"The API does not remove a deleted permission from roles, and a role that refers to a deleted permission " +
			"can no longer be changed or deleted, so the provider never leaves a role referring to one:\n\n" +
			"* **Destroying** a permission first removes it from the roles in the project that contain it, with a " +
			"warning that names them (managed roles that still list it then show a change on the next plan). It " +
			"fails if the permission is a role's only one.\n" +
			"* **Replacing** a permission (for example because `project` changed, or with `-replace`) fails while any " +
			"role contains it, and the error names the roles, because the roles would otherwise lose the permission " +
			"until a later apply. Remove it from the roles first.",
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
	// Delete runs both for a destroy and for the first half of a replacement, and has to tell them apart: see
	// deleteChecked. Only a planned destroy is marked.
	if req.Plan.Raw.IsNull() {
		resp.Diagnostics.Append(resp.Private.SetKey(ctx, plannedDestroyKey, []byte("true"))...)
		return
	}
	resp.Diagnostics.Append(resp.Private.SetKey(ctx, plannedDestroyKey, nil)...)
	if req.State.Raw.IsNull() {
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
		// An interrupted rename may have got as far as deleting the old permission.
		p, err = r.renamedTo(ctx, project, req.Private, resp.Private, &resp.Diagnostics)
		if p == nil && err == nil {
			resp.State.RemoveResource(ctx)
			return
		}
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

// renamedTo returns the permission that an interrupted rename created, if private state records one and it still
// exists, and clears the record. It returns nil if there is none.
func (r *permissionResource) renamedTo(ctx context.Context, project string, from, to privateState, diags *diag.Diagnostics) (*pb.Permission, error) {
	pending := getPendingRename(ctx, from, diags)
	if pending == nil {
		return nil, nil
	}
	p, err := r.pd.client.API.GetPermission(ctx, &pb.GetPermissionRequest{ProjectName: project, Name: pending.Name})
	if client.IsNotFound(err) || (err == nil && p.GetId() != pending.ID) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	setPendingRename(ctx, to, nil, diags)
	return p, nil
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
	pending := getPendingRename(ctx, req.Private, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	var result *pb.Permission
	if oldName == newName && pending == nil {
		var err error
		result, err = r.pd.client.API.UpdatePermission(ctx, &pb.UpdatePermissionRequest{ProjectName: project, Name: oldName, Description: desc})
		if err != nil {
			client.AddError(&resp.Diagnostics, "Unable to update permission", err)
			return
		}
	} else {
		result = r.rename(ctx, project, oldName, newName, desc, pending, resp.Private, &resp.Diagnostics)
		if result == nil {
			return
		}
	}
	plan.ID = types.StringValue(result.GetId())
	plan.Project = types.StringValue(project)
	plan.Description = types.StringValue(result.GetDescription())
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// pendingRenameKey is the private state key that records a rename that created the new permission but has not yet
// finished moving roles to it and deleting the old one. It lets a later apply tell a permission that this resource
// created from one that something else manages.
const pendingRenameKey = "pending_rename"

type pendingRename struct {
	Name string `json:"name"`
	ID   string `json:"id"`
}

type privateState interface {
	GetKey(ctx context.Context, key string) ([]byte, diag.Diagnostics)
	SetKey(ctx context.Context, key string, value []byte) diag.Diagnostics
}

func getPendingRename(ctx context.Context, p privateState, diags *diag.Diagnostics) *pendingRename {
	if p == nil {
		return nil
	}
	raw, d := p.GetKey(ctx, pendingRenameKey)
	diags.Append(d...)
	if len(raw) == 0 {
		return nil
	}
	var pr pendingRename
	if err := json.Unmarshal(raw, &pr); err != nil || pr.Name == "" || pr.ID == "" {
		return nil // unreadable; treat as absent, which fails safe (an existing permission is then never adopted)
	}
	return &pr
}

func setPendingRename(ctx context.Context, p privateState, pr *pendingRename, diags *diag.Diagnostics) {
	var raw []byte
	if pr != nil {
		raw, _ = json.Marshal(pr)
	}
	diags.Append(p.SetKey(ctx, pendingRenameKey, raw)...)
}

// rename renames a permission. The API's rename does not update roles that contain the permission, and a role that
// refers to a permission that no longer exists can no longer be read or updated. So when roles contain the
// permission, the new permission is created alongside the old one, the roles are switched over, and the old one is
// deleted.
//
// The three steps are not atomic. The new permission's ID is recorded in private state as soon as it is created, so
// if a later step fails, the next apply recognises the permission it created and finishes the remaining steps. A
// permission with the new name that this resource did not create is never taken over.
func (r *permissionResource) rename(ctx context.Context, project, oldName, newName, desc string, pending *pendingRename, private privateState, diags *diag.Diagnostics) *pb.Permission {
	api := r.pd.client.API

	if pending != nil && pending.Name != newName {
		diags.AddError("An earlier rename did not finish", fmt.Sprintf(
			"An earlier apply started renaming the permission %q to %q but did not finish: %q may exist, and roles may "+
				"already use it instead of %q.\n\nSet name to %q and apply to finish that rename first. You can then "+
				"rename the permission again.", oldName, pending.Name, pending.Name, oldName, pending.Name))
		return nil
	}

	// CreatePermission returns an identical existing permission instead of failing, so check first.
	target, err := api.GetPermission(ctx, &pb.GetPermissionRequest{ProjectName: project, Name: newName})
	switch {
	case err == nil && pending != nil && pending.ID == target.GetId():
		// Created by an earlier, interrupted attempt: finish it.
		return r.finishRename(ctx, project, oldName, target, desc, private, diags)
	case err == nil:
		diags.AddError("Permission already exists", fmt.Sprintf(
			"The permission %q cannot be renamed to %q, because a permission called %q already exists in project %q "+
				"(ID %s) and was not created by this resource.\n\n"+
				"If something else manages it, choose another name. If you want this resource to manage it instead, "+
				"move any roles over to it, delete %q, then run: terraform state rm <address> and terraform import "+
				"<address> %s/%s",
			oldName, newName, newName, project, target.GetId(), oldName, project, newName))
		return nil
	case !client.IsNotFound(err):
		client.AddError(diags, "Unable to check for an existing permission", err)
		return nil
	}
	if pending != nil {
		// The permission the earlier attempt created is gone, so start again.
		setPendingRename(ctx, private, nil, diags)
	}

	referencing, err := r.rolesUsing(ctx, project, oldName)
	if err != nil {
		client.AddError(diags, "Unable to list roles", err)
		return nil
	}
	if len(referencing) == 0 {
		p, err := api.UpdatePermission(ctx, &pb.UpdatePermissionRequest{ProjectName: project, Name: oldName, NewName: proto.String(newName), Description: desc})
		if err != nil {
			client.AddError(diags, "Unable to rename permission", err, internalHint(err,
				"Permission names are unique across the organisation: check that no other project has a permission called "+newName+"."))
			return nil
		}
		return p
	}

	created, err := api.CreatePermission(ctx, &pb.CreatePermissionRequest{ProjectName: project, Name: newName, Description: desc})
	if err != nil {
		client.AddError(diags, "Unable to create the renamed permission", err, internalHint(err,
			"Permission names are unique across the organisation: check that no other project has a permission called "+newName+"."))
		return nil
	}
	setPendingRename(ctx, private, &pendingRename{Name: newName, ID: created.GetId()}, diags)
	if diags.HasError() {
		return nil
	}
	return r.finishRename(ctx, project, oldName, created, desc, private, diags)
}

// finishRename moves the roles that still use oldName to target and deletes oldName. Every step is safe to repeat.
func (r *permissionResource) finishRename(ctx context.Context, project, oldName string, target *pb.Permission, desc string, private privateState, diags *diag.Diagnostics) *pb.Permission {
	api := r.pd.client.API
	newName := target.GetName()
	retry := fmt.Sprintf("\n\nBoth %q and %q exist. Run apply again to finish the rename: it carries on from where it stopped.", oldName, newName)

	roles, err := r.rolesUsing(ctx, project, oldName)
	if err != nil {
		diags.AddError("Unable to list roles", client.Describe(err)+retry)
		return nil
	}
	for _, role := range roles {
		perms := client.PermissionNames(role)
		for i, n := range perms {
			if n == oldName {
				perms[i] = newName
			}
		}
		perms = slices.Compact(sortedCopy(perms))
		if _, err := api.UpdateRole(ctx, &pb.UpdateRoleRequest{ProjectName: project, Id: role.GetId(), Name: role.GetName(), Description: role.GetDescription(), Permissions: perms}); err != nil {
			diags.AddError("Unable to move role to the renamed permission",
				fmt.Sprintf("Updating role %q (%s) failed: %s%s", role.GetName(), role.GetId(), client.Describe(err), retry))
			return nil
		}
	}
	if err := deletePermission(ctx, r.pd.client, project, oldName); err != nil {
		diags.AddError("Unable to delete the old permission", client.Describe(err)+retry)
		return nil
	}
	if target.GetDescription() != desc {
		target, err = api.UpdatePermission(ctx, &pb.UpdatePermissionRequest{ProjectName: project, Name: newName, Description: desc})
		if err != nil {
			client.AddError(diags, "Unable to update the renamed permission's description", err)
			return nil
		}
	}
	setPendingRename(ctx, private, nil, diags)
	return target
}

// rolesUsing returns the roles in the project that contain the permission.
func (r *permissionResource) rolesUsing(ctx context.Context, project, name string) ([]*pb.Role, error) {
	roles, err := r.pd.client.ListAllRoles(ctx, project, "")
	if err != nil {
		return nil, err
	}
	var using []*pb.Role
	for _, role := range roles {
		if slices.Contains(client.PermissionNames(role), name) {
			using = append(using, role)
		}
	}
	return using, nil
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

	project := projectOf(state.Project, r.pd)
	marker, d := req.Private.GetKey(ctx, plannedDestroyKey)
	resp.Diagnostics.Append(d...)
	destroying := string(marker) == "true"
	if !r.deleteChecked(ctx, project, state.Name.ValueString(), destroying, &resp.Diagnostics) {
		return
	}
	// Also delete a permission that an interrupted rename created, if it is still there.
	if pending := getPendingRename(ctx, req.Private, &resp.Diagnostics); pending != nil {
		p, err := r.pd.client.API.GetPermission(ctx, &pb.GetPermissionRequest{ProjectName: project, Name: pending.Name})
		switch {
		case err == nil && p.GetId() == pending.ID:
			r.deleteChecked(ctx, project, pending.Name, destroying, &resp.Diagnostics)
		case err != nil && !client.IsNotFound(err):
			client.AddError(&resp.Diagnostics, "Unable to read the permission created by an interrupted rename", err)
		}
	}
}

// plannedDestroyKey marks, in the planned private state, a plan that destroys the permission (rather than
// replacing it).
const plannedDestroyKey = "planned_destroy"

// deleteChecked deletes a permission that roles in the project may still contain. The API does not remove a deleted
// permission from roles, and a role that refers to a deleted permission can no longer be read, changed or deleted,
// so the permission is never deleted while a role contains it.
//
//   - When the permission is being destroyed, it is first removed from those roles, with a warning that names them.
//     Terraform orders a destroy before the update of roles that stop using the permission in the same apply, so
//     refusing here would make that common change impossible to apply. Managed roles that still list the
//     permission show up as a change on the next plan. A role whose only permission it is cannot lose it, which is
//     an error.
//   - When it is being replaced (for example because its project changed, or with -replace), the roles would lose
//     it with nothing to add it back until a later apply, so the replacement fails instead, naming the roles. So does
//     a delete that was not planned as a destroy, which is the safe default.
func (r *permissionResource) deleteChecked(ctx context.Context, project, name string, destroying bool, diags *diag.Diagnostics) bool {
	roles, err := r.rolesUsing(ctx, project, name)
	if err != nil {
		client.AddError(diags, "Unable to list roles", err)
		return false
	}
	if len(roles) > 0 {
		if !destroying {
			diags.AddError("Permission is still used by roles", permissionInUseDetail(project, name, roles))
			return false
		}
		var only []*pb.Role
		for _, role := range roles {
			if len(client.PermissionNames(role)) == 1 {
				only = append(only, role)
			}
		}
		if len(only) > 0 {
			diags.AddError("Permission is a role's only permission", fmt.Sprintf(
				"The permission %q cannot be deleted, because it is the only permission of %s, and a role needs at "+
					"least one. Give the role another permission or delete it first (if Terraform manages the role, "+
					"apply that change first, for example with -target).", name, roleList(only)))
			return false
		}
		for _, role := range roles {
			remaining := slices.DeleteFunc(client.PermissionNames(role), func(n string) bool { return n == name })
			if _, err := r.pd.client.API.UpdateRole(ctx, &pb.UpdateRoleRequest{ProjectName: project, Id: role.GetId(), Name: role.GetName(), Description: role.GetDescription(), Permissions: sortedCopy(remaining)}); err != nil {
				client.AddError(diags, fmt.Sprintf("Unable to remove the permission from role %q", role.GetName()), err)
				return false
			}
		}
		diags.AddWarning("Permission removed from roles", fmt.Sprintf(
			"Before deleting the permission %q, the provider removed it from %s, because the Permio API does not do "+
				"that itself and a role that refers to a deleted permission can no longer be changed or deleted. If "+
				"Terraform manages any of these roles and their configuration still lists the permission, the next "+
				"plan shows them as changed.", name, roleList(roles)))
	}
	if err := deletePermission(ctx, r.pd.client, project, name); err != nil {
		client.AddError(diags, "Unable to delete permission", err)
		return false
	}
	return true
}

func roleList(roles []*pb.Role) string {
	names := make([]string, len(roles))
	for i, role := range roles {
		names[i] = fmt.Sprintf("role %q (ID %s)", role.GetName(), role.GetId())
	}
	return strings.Join(names, ", ")
}

func permissionInUseDetail(project, name string, roles []*pb.Role) string {
	var b strings.Builder
	fmt.Fprintf(&b, "The permission %q is being replaced, but these roles in project %q contain it:\n", name, project)
	for _, role := range roles {
		fmt.Fprintf(&b, "  - %q (ID %s)", role.GetName(), role.GetId())
		if len(client.PermissionNames(role)) == 1 {
			b.WriteString(" (its only permission)")
		}
		b.WriteString("\n")
	}
	b.WriteString("\nThe Permio API does not remove a deleted permission from roles, so replacing it would mean taking " +
		"it away from these roles until a later apply adds the new one back, and a role whose only permission it " +
		"is cannot lose it at all. The permission was not changed.\n\n" +
		"Remove the permission from these roles first (or move the roles too, if the permission's project is " +
		"changing, because a role can only contain permissions from its own project), then apply again. To change " +
		"only the permission's name, rename it in place instead: that keeps the roles.")
	return b.String()
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
	project, name, err := splitProjectID(req.ID, r.pd)
	if err == nil && !permissionPattern.MatchString(name) {
		err = fmt.Errorf("the permission name %q must contain only letters, digits, '.', '_' and '-'", name)
	}
	if err != nil {
		resp.Diagnostics.AddError("Invalid import ID", importIDError(req.ID, `"<project>/<name>" or "<name>"`, `default/document.read`, err))
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("project"), project)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("name"), name)...)
}

func sortedCopy(s []string) []string {
	out := slices.Clone(s)
	slices.Sort(out)
	return out
}
