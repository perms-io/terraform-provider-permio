package provider

import (
	"context"
	"fmt"
	"slices"
	"strings"

	pb "github.com/PrivateJAR/permio-go/proto/permissions/v1"
	"github.com/hashicorp/terraform-plugin-framework-timeouts/resource/timeouts"
	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/setdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/PrivateJAR/terraform-provider-permio/internal/client"
)

var (
	_ resource.ResourceWithConfigure      = (*grantResource)(nil)
	_ resource.ResourceWithImportState    = (*grantResource)(nil)
	_ resource.ResourceWithModifyPlan     = (*grantResource)(nil)
	_ resource.ResourceWithValidateConfig = (*grantResource)(nil)
)

// NewGrantResource returns the permio_grant resource.
func NewGrantResource() resource.Resource { return &grantResource{} }

type grantResource struct{ pd *providerData }

type grantModel struct {
	ID          types.String   `tfsdk:"id"`
	Project     types.String   `tfsdk:"project"`
	Principal   types.String   `tfsdk:"principal"`
	Resource    types.String   `tfsdk:"resource"`
	Roles       types.Set      `tfsdk:"roles"`
	Permissions types.Set      `tfsdk:"permissions"`
	Timeouts    timeouts.Value `tfsdk:"timeouts"`
}

func (r *grantResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_grant"
}

func (r *grantResource) Schema(ctx context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	emptySet := setdefault.StaticValue(types.SetValueMust(types.StringType, nil))
	resp.Schema = schema.Schema{
		MarkdownDescription: "The roles and permissions granted to one principal (a user, service or group) directly on " +
			"one resource URI.\n\n" +
			"This resource is **authoritative** for its (principal, resource) pair: it manages the complete set of roles " +
			"and permissions granted directly to the principal on exactly that resource URI. On create and on every " +
			"apply it grants what is missing and revokes anything else granted on the pair, including grants made " +
			"outside Terraform. Destroying it revokes everything granted on the pair.\n\n" +
			"**Use exactly one `permio_grant` per principal and resource.** Two resources for the same pair would keep " +
			"revoking each other's grants.\n\n" +
			"Grants are inherited: a grant on `/workspaces/acme` also applies to `/workspaces/acme/docs/1`, and a `_` " +
			"segment matches any single segment (`/workspaces/_/billing`). Inherited grants on other URIs are separate " +
			"pairs and are not touched by this resource.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				MarkdownDescription: "`<project>|<principal>|<resource>`.",
				Computed:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"project": resourceProjectAttribute(),
			"principal": schema.StringAttribute{
				MarkdownDescription: "Principal ID: a user or service ID from your system, or a group's principal " +
					"(`group:<name>`, for example `permio_group.engineering.principal`). Changing it replaces the grant.",
				Required:      true,
				Validators:    []validator.String{principalValidator()},
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"resource": schema.StringAttribute{
				MarkdownDescription: "Resource URI, such as `/workspaces/acme/projects/42`. It must start with `/`, must " +
					"not contain empty segments, a trailing `/`, whitespace, or any of `( ) [ ] { } * + ? | ^ $ \\`, and is " +
					"at most 2048 bytes. A `_` segment matches any single segment. Changing it replaces the grant.",
				Required:      true,
				Validators:    []validator.String{resourceURIValidator()},
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"roles": schema.SetAttribute{
				MarkdownDescription: "IDs of the roles to grant (for example `permio_role.editor.id`), not role names.",
				Optional:            true,
				Computed:            true,
				Default:             emptySet,
				ElementType:         types.StringType,
				Validators:          []validator.Set{setvalidator.ValueStringsAre(roleIDValidators()...)},
			},
			"permissions": schema.SetAttribute{
				MarkdownDescription: "Names of the permissions to grant directly.",
				Optional:            true,
				Computed:            true,
				Default:             emptySet,
				ElementType:         types.StringType,
				Validators:          []validator.Set{setvalidator.ValueStringsAre(permissionNameValidators()...)},
			},
		},
		Blocks: map[string]schema.Block{
			"timeouts": timeouts.Block(ctx, timeouts.Opts{Create: true, Read: true, Update: true, Delete: true}),
		},
	}
}

func (r *grantResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.pd = providerDataFrom(req.ProviderData, &resp.Diagnostics)
}

func (r *grantResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var cfg grantModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if cfg.Roles.IsUnknown() || cfg.Permissions.IsUnknown() {
		return
	}
	if len(cfg.Roles.Elements()) == 0 && len(cfg.Permissions.Elements()) == 0 {
		resp.Diagnostics.AddAttributeError(path.Root("roles"), "Nothing to grant",
			"Set at least one role or permission. To revoke everything on the pair, remove the permio_grant resource.")
	}
}

func (r *grantResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	planProject(ctx, r.pd, req, resp)
}

func grantID(project, principal, uri string) string { return project + "|" + principal + "|" + uri }

// directGrant returns the roles and permissions granted directly to principal on exactly uri.
func (r *grantResource) directGrant(ctx context.Context, project, principal, uri string) (perms, roles []string, err error) {
	resp, err := r.pd.client.API.GetUserPermissionsAndRolesOnResource(ctx, &pb.GetUserPermissionsAndRolesOnResourceRequest{
		ProjectName: project, UserId: principal, ResourceUri: uri,
	})
	if err != nil {
		return nil, nil, err
	}
	return sortedCopy(resp.GetPermissions()), sortedCopy(resp.GetRoles()), nil
}

// existing narrows permission names and role IDs to the ones that still exist in the project. A grant can refer
// to a permission or role that was deleted (or a permission that was renamed): the API keeps such names on the
// grant but rejects them in a revoke, so they cannot be managed.
func (r *grantResource) existing(ctx context.Context, project string, perms, roles []string) ([]string, []string, error) {
	if len(perms) > 0 {
		all, err := r.pd.client.ListAllPermissions(ctx, project)
		if err != nil {
			return nil, nil, err
		}
		names := make([]string, 0, len(all))
		for _, p := range all {
			names = append(names, p.GetName())
		}
		perms = slices.DeleteFunc(slices.Clone(perms), func(n string) bool { return !slices.Contains(names, n) })
	}
	if len(roles) > 0 {
		all, err := r.pd.client.ListAllRoles(ctx, project, "")
		if err != nil {
			return nil, nil, err
		}
		ids := make([]string, 0, len(all))
		for _, ro := range all {
			ids = append(ids, ro.GetId())
		}
		roles = slices.DeleteFunc(slices.Clone(roles), func(id string) bool { return !slices.Contains(ids, id) })
	}
	return perms, roles, nil
}

// revoke revokes the given permissions and roles, skipping any that no longer exist.
func (r *grantResource) revoke(ctx context.Context, project, principal, uri string, perms, roles []string) error {
	if len(perms) == 0 && len(roles) == 0 {
		return nil
	}
	perms, roles, err := r.existing(ctx, project, perms, roles)
	if err != nil {
		return err
	}
	if len(perms) == 0 && len(roles) == 0 {
		return nil
	}
	_, err = r.pd.client.API.RevokeUserPermissionsAndRolesOnResource(ctx, &pb.RevokeUserPermissionsAndRolesOnResourceRequest{
		ProjectName: project, UserId: principal, ResourceUri: uri, Permissions: perms, Roles: roles,
	})
	return err
}

// apply makes the direct grant on the pair exactly the desired roles and permissions. Missing grants are added
// before extra ones are revoked, so swapping one role for another never leaves the principal without either.
func (r *grantResource) apply(ctx context.Context, project, principal, uri string, wantPerms, wantRoles []string, diags *diag.Diagnostics) {
	havePerms, haveRoles, err := r.directGrant(ctx, project, principal, uri)
	if err != nil {
		client.AddError(diags, "Unable to read the current grant", err)
		return
	}
	addPerms, addRoles := difference(wantPerms, havePerms), difference(wantRoles, haveRoles)
	if len(addPerms) > 0 || len(addRoles) > 0 {
		_, err := r.pd.client.API.GrantUserPermissionsAndRolesOnResource(ctx, &pb.GrantUserPermissionsAndRolesOnResourceRequest{
			ProjectName: project, UserId: principal, ResourceUri: uri, Permissions: addPerms, Roles: addRoles,
		})
		if err != nil {
			client.AddError(diags, "Unable to grant roles and permissions", err,
				"Every permission and role must exist in the project, and roles are referred to by ID (permio_role.<name>.id), not by name.")
			return
		}
	}
	if err := r.revoke(ctx, project, principal, uri, difference(havePerms, wantPerms), difference(haveRoles, wantRoles)); err != nil {
		client.AddError(diags, "Unable to revoke roles and permissions", err)
	}
}

func (r *grantResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan grantModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() || !requireClient(r.pd, &resp.Diagnostics) {
		return
	}
	t, d := plan.Timeouts.Create(ctx, defaultCreateTimeout)
	ctx, cancel := withTimeout(ctx, t, d, &resp.Diagnostics)
	defer cancel()

	project, principal, uri := projectOf(plan.Project, r.pd), plan.Principal.ValueString(), plan.Resource.ValueString()
	perms := setToStrings(ctx, plan.Permissions, &resp.Diagnostics)
	roles := setToStrings(ctx, plan.Roles, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	r.apply(ctx, project, principal, uri, perms, roles, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	plan.ID = types.StringValue(grantID(project, principal, uri))
	plan.Project = types.StringValue(project)
	plan.Permissions = stringsToSet(perms)
	plan.Roles = stringsToSet(roles)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *grantResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state grantModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() || !requireClient(r.pd, &resp.Diagnostics) {
		return
	}
	t, d := state.Timeouts.Read(ctx, defaultReadTimeout)
	ctx, cancel := withTimeout(ctx, t, d, &resp.Diagnostics)
	defer cancel()

	project, principal, uri := projectOf(state.Project, r.pd), state.Principal.ValueString(), state.Resource.ValueString()
	perms, roles, err := r.directGrant(ctx, project, principal, uri)
	if client.IsNotFound(err) {
		// The principal is a group that no longer exists, and its grants went with it.
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		client.AddError(&resp.Diagnostics, "Unable to read grant", err)
		return
	}

	// Names that Terraform does not already track are checked: ones that refer to deleted permissions or roles
	// cannot be revoked and are ignored, so they do not cause a permanent diff.
	known := setToStrings(ctx, state.Permissions, &resp.Diagnostics)
	knownRoles := setToStrings(ctx, state.Roles, &resp.Diagnostics)
	newPerms, newRoles := difference(perms, known), difference(roles, knownRoles)
	if len(newPerms) > 0 || len(newRoles) > 0 {
		livePerms, liveRoles, err := r.existing(ctx, project, newPerms, newRoles)
		if err != nil {
			client.AddError(&resp.Diagnostics, "Unable to read grant", err)
			return
		}
		perms = slices.DeleteFunc(perms, func(n string) bool { return slices.Contains(newPerms, n) && !slices.Contains(livePerms, n) })
		roles = slices.DeleteFunc(roles, func(n string) bool { return slices.Contains(newRoles, n) && !slices.Contains(liveRoles, n) })
	}

	if len(perms) == 0 && len(roles) == 0 {
		resp.State.RemoveResource(ctx)
		return
	}
	state.ID = types.StringValue(grantID(project, principal, uri))
	state.Project = types.StringValue(project)
	state.Permissions = stringsToSet(perms)
	state.Roles = stringsToSet(roles)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *grantResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan grantModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() || !requireClient(r.pd, &resp.Diagnostics) {
		return
	}
	t, d := plan.Timeouts.Update(ctx, defaultUpdateTimeout)
	ctx, cancel := withTimeout(ctx, t, d, &resp.Diagnostics)
	defer cancel()

	project, principal, uri := projectOf(plan.Project, r.pd), plan.Principal.ValueString(), plan.Resource.ValueString()
	perms := setToStrings(ctx, plan.Permissions, &resp.Diagnostics)
	roles := setToStrings(ctx, plan.Roles, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	r.apply(ctx, project, principal, uri, perms, roles, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	plan.ID = types.StringValue(grantID(project, principal, uri))
	plan.Project = types.StringValue(project)
	plan.Permissions = stringsToSet(perms)
	plan.Roles = stringsToSet(roles)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *grantResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state grantModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() || !requireClient(r.pd, &resp.Diagnostics) {
		return
	}
	t, d := state.Timeouts.Delete(ctx, defaultDeleteTimeout)
	ctx, cancel := withTimeout(ctx, t, d, &resp.Diagnostics)
	defer cancel()

	project, principal, uri := projectOf(state.Project, r.pd), state.Principal.ValueString(), state.Resource.ValueString()
	perms, roles, err := r.directGrant(ctx, project, principal, uri)
	if client.IsNotFound(err) {
		return // the group, and with it the grant, is gone
	}
	if err != nil {
		client.AddError(&resp.Diagnostics, "Unable to read grant", err)
		return
	}
	if err := r.revoke(ctx, project, principal, uri, perms, roles); err != nil {
		client.AddError(&resp.Diagnostics, "Unable to revoke grant", err)
	}
}

// parseGrantID parses "<project>|<principal>|<resource>", or "<principal>|<resource>" for the provider's project.
// The resource URI cannot contain "|", and neither can a project name, so the principal is everything in between.
func parseGrantID(id string, pd *providerData) (project, principal, uri string, ok bool) {
	last := strings.LastIndex(id, "|")
	if last < 0 {
		return "", "", "", false
	}
	uri, rest := id[last+1:], id[:last]
	if first := strings.Index(rest, "|"); first >= 0 {
		project, principal = rest[:first], rest[first+1:]
	} else if pd != nil {
		project, principal = pd.project, rest
	} else {
		return "", "", "", false
	}
	if !projectPattern.MatchString(project) || len(project) > 32 || validatePrincipal(principal) != nil || validateResourceURI(uri) != nil {
		return "", "", "", false
	}
	return project, principal, uri, true
}

func (r *grantResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	project, principal, uri, ok := parseGrantID(req.ID, r.pd)
	if !ok {
		resp.Diagnostics.AddError("Invalid import ID", fmt.Sprintf(
			"Expected \"<project>|<principal>|<resource URI>\" (or \"<principal>|<resource URI>\" for the provider's project), got %q.", req.ID))
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("project"), project)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("principal"), principal)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("resource"), uri)...)
	// Read fills in everything granted on the pair.
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("permissions"), types.SetValueMust(types.StringType, nil))...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("roles"), types.SetValueMust(types.StringType, nil))...)
}
