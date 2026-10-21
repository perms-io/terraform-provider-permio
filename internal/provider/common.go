package provider

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	dsschema "github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"google.golang.org/grpc/codes"

	"github.com/PrivateJAR/terraform-provider-permio/internal/client"
)

const (
	defaultCreateTimeout = 5 * time.Minute
	defaultReadTimeout   = 2 * time.Minute
	defaultUpdateTimeout = 5 * time.Minute
	defaultDeleteTimeout = 5 * time.Minute
)

// providerDataFrom extracts the provider data passed to Configure. It returns nil (without error) before the
// provider is configured.
func providerDataFrom(raw any, diags *diag.Diagnostics) *providerData {
	if raw == nil {
		return nil
	}
	pd, ok := raw.(*providerData)
	if !ok {
		diags.AddError("Unexpected provider data", fmt.Sprintf("Expected *providerData, got %T. This is a bug in the provider.", raw))
		return nil
	}
	return pd
}

// requireClient reports an error if the provider has not been configured.
func requireClient(pd *providerData, diags *diag.Diagnostics) bool {
	if pd == nil || pd.client == nil {
		diags.AddError("Provider not configured", "The Permio provider has not been configured. This is a bug in the provider or Terraform.")
		return false
	}
	return true
}

func resourceProjectAttribute() schema.StringAttribute {
	return schema.StringAttribute{
		MarkdownDescription: "Project the object belongs to. Defaults to the provider's `project`. Changing it " +
			"replaces the object. API keys are scoped to one project, so this must be the key's project.",
		Optional:   true,
		Computed:   true,
		Validators: []validator.String{projectValidator()},
	}
}

func dataSourceProjectAttribute() dsschema.StringAttribute {
	return dsschema.StringAttribute{
		MarkdownDescription: "Project to read from. Defaults to the provider's `project`.",
		Optional:            true,
		Computed:            true,
		Validators:          []validator.String{projectValidator()},
	}
}

// planProject fills in the project from the provider when the configuration leaves it out, and requires replacement
// when the project changes.
func planProject(ctx context.Context, pd *providerData, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	if req.Plan.Raw.IsNull() {
		return // destroy
	}
	var configured types.String
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("project"), &configured)...)
	if resp.Diagnostics.HasError() {
		return
	}
	planned := configured
	if configured.IsNull() && pd != nil {
		planned = types.StringValue(pd.project)
		resp.Diagnostics.Append(resp.Plan.SetAttribute(ctx, path.Root("project"), planned)...)
	}
	if req.State.Raw.IsNull() || planned.IsUnknown() || planned.IsNull() {
		return
	}
	var prior types.String
	resp.Diagnostics.Append(req.State.GetAttribute(ctx, path.Root("project"), &prior)...)
	if !prior.IsNull() && prior.ValueString() != planned.ValueString() {
		resp.RequiresReplace = append(resp.RequiresReplace, path.Root("project"))
	}
}

// projectOf returns the configured project, or the provider's default.
func projectOf(v types.String, pd *providerData) string {
	if !v.IsNull() && !v.IsUnknown() && v.ValueString() != "" {
		return v.ValueString()
	}
	return pd.project
}

// setToStrings returns the elements of a set of strings, sorted.
func setToStrings(ctx context.Context, s types.Set, diags *diag.Diagnostics) []string {
	if s.IsNull() || s.IsUnknown() {
		return nil
	}
	var out []string
	diags.Append(s.ElementsAs(ctx, &out, false)...)
	sort.Strings(out)
	return out
}

// stringsToSet returns a set of strings (never null).
func stringsToSet(items []string) types.Set {
	sorted := slices.Clone(items)
	sort.Strings(sorted)
	sorted = slices.Compact(sorted)
	elems := make([]attr.Value, 0, len(sorted))
	for _, it := range sorted {
		elems = append(elems, types.StringValue(it))
	}
	return types.SetValueMust(types.StringType, elems)
}

// difference returns the items of a that are not in b, in the order they appear in a.
func difference(a, b []string) []string {
	if len(a) == 0 {
		return nil
	}
	exclude := make(map[string]struct{}, len(b))
	for _, x := range b {
		exclude[x] = struct{}{}
	}
	var out []string
	for _, x := range a {
		if _, ok := exclude[x]; !ok {
			out = append(out, x)
		}
	}
	return out
}

// withTimeout returns a context limited by the configured or default timeout.
func withTimeout(ctx context.Context, d time.Duration, diags diag.Diagnostics, into *diag.Diagnostics) (context.Context, context.CancelFunc) {
	into.Append(diags...)
	return context.WithTimeout(ctx, d)
}

// internalHint returns hint if err is an Internal error, which is how the API reports a name that is already taken.
func internalHint(err error, hint string) string {
	if client.Code(err) == codes.Internal {
		return hint
	}
	return ""
}
