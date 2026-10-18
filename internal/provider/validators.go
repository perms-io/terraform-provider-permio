package provider

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"unicode"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
)

// Validation rules, taken from the PermissionsService request validation and the service's own checks.
var (
	projectPattern    = regexp.MustCompile(`^[a-z0-9-]+$`)
	permissionPattern = regexp.MustCompile(`^[a-zA-Z0-9._-]+$`)
	roleIDPattern     = regexp.MustCompile(`^[a-zA-Z0-9._-]+$`)
	roleNamePattern   = regexp.MustCompile(`^[^\x00-\x1f\x7f]+$`)
	groupNamePattern  = regexp.MustCompile(`^[a-z0-9-]+$`)
)

const (
	maxResourceURILength   = 2048
	maxGroupDescription    = 1024
	groupPrincipalPrefix   = "group:"
	resourceURIForbiddenIn = `()[]{}*+?|^$\`
)

func projectValidator() validator.String {
	return stringvalidator.All(
		stringvalidator.LengthBetween(1, 32),
		stringvalidator.RegexMatches(projectPattern, "must contain only lower-case letters, digits and hyphens"),
	)
}

func permissionNameValidators() []validator.String {
	return []validator.String{
		stringvalidator.LengthBetween(1, 128),
		stringvalidator.RegexMatches(permissionPattern, "must contain only letters, digits, '.', '_' and '-'"),
	}
}

func roleIDValidators() []validator.String {
	return []validator.String{
		stringvalidator.LengthBetween(1, 128),
		stringvalidator.RegexMatches(roleIDPattern, "must be a role ID (letters, digits, '.', '_' and '-'); use permio_role.<name>.id rather than the role's name"),
	}
}

func roleNameValidators() []validator.String {
	return []validator.String{
		stringvalidator.UTF8LengthBetween(1, 128),
		stringvalidator.RegexMatches(roleNamePattern, "must not contain control characters"),
	}
}

func groupNameValidators() []validator.String {
	return []validator.String{
		stringvalidator.LengthBetween(1, 64),
		stringvalidator.RegexMatches(groupNamePattern, "must be a slug: lower-case letters, digits and hyphens"),
	}
}

// validateResourceURI applies the service's resource URI rules: it starts with "/", has no empty segments (so no
// "//" and no trailing "/"), has no whitespace or control characters, no regular expression metacharacters
// ( ) [ ] { } * + ? | ^ $ \, is a valid URI reference and is at most 2048 bytes long. A "_" segment is a wildcard
// that matches any single segment.
func validateResourceURI(uri string) error {
	switch {
	case uri == "":
		return fmt.Errorf("must not be empty")
	case len(uri) > maxResourceURILength:
		return fmt.Errorf("must be at most %d bytes long", maxResourceURILength)
	case !strings.HasPrefix(uri, "/"):
		return fmt.Errorf("must start with \"/\"")
	}
	for _, r := range uri {
		if unicode.IsControl(r) || unicode.IsSpace(r) {
			return fmt.Errorf("must not contain whitespace or control characters")
		}
	}
	if strings.ContainsAny(uri, resourceURIForbiddenIn) {
		return fmt.Errorf("must not contain any of the characters %s", resourceURIForbiddenIn)
	}
	for _, seg := range strings.Split(uri[1:], "/") {
		if seg == "" {
			return fmt.Errorf("must not contain empty segments (\"//\" or a trailing \"/\")")
		}
	}
	if _, err := url.Parse(uri); err != nil {
		return fmt.Errorf("must be a valid URI reference: %v", err)
	}
	return nil
}

// validatePrincipal checks a principal ID: any non-empty string, except that "group:<name>" must name a valid
// group slug.
func validatePrincipal(p string) error {
	if p == "" {
		return fmt.Errorf("must not be empty")
	}
	if name, ok := strings.CutPrefix(p, groupPrincipalPrefix); ok {
		if name == "" || len(name) > 64 || !groupNamePattern.MatchString(name) {
			return fmt.Errorf("principal IDs starting with %q are reserved for groups, and %q is not a valid group name (lower-case letters, digits and hyphens, at most 64)", groupPrincipalPrefix, name)
		}
	}
	return nil
}

// validateMember checks a group member principal ID: non-empty and not a group, because groups cannot be nested.
func validateMember(p string) error {
	if p == "" {
		return fmt.Errorf("must not be empty")
	}
	if strings.HasPrefix(p, groupPrincipalPrefix) {
		return fmt.Errorf("groups cannot be members of groups (principal IDs starting with %q are reserved for groups)", groupPrincipalPrefix)
	}
	return nil
}

// funcValidator adapts a func(string) error to a string validator.
type funcValidator struct {
	desc string
	fn   func(string) error
}

func (v funcValidator) Description(context.Context) string         { return v.desc }
func (v funcValidator) MarkdownDescription(context.Context) string { return v.desc }

func (v funcValidator) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	if err := v.fn(req.ConfigValue.ValueString()); err != nil {
		resp.Diagnostics.AddAttributeError(req.Path, "Invalid value", fmt.Sprintf("%q %v.", req.ConfigValue.ValueString(), err))
	}
}

func resourceURIValidator() validator.String {
	return funcValidator{desc: "must be a valid Permio resource URI", fn: validateResourceURI}
}

func principalValidator() validator.String {
	return funcValidator{desc: "must be a principal ID or group:<slug>", fn: validatePrincipal}
}

func memberValidator() validator.String {
	return funcValidator{desc: "must be a principal ID that is not a group", fn: validateMember}
}
