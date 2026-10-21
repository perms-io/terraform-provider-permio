package provider

import (
	"fmt"
	"strings"
)

// Import ID formats.
//
// The parts of an import ID are separated by characters that cannot appear in the parts they separate, so that every
// ID has exactly one reading:
//
//   - project names are lower-case letters, digits and hyphens, so they never contain "/" or "|";
//   - group names and permission names never contain "/";
//   - resource URIs never contain "|" (and always start with "/");
//   - principal IDs and role names can contain any character, so they always come last, or between two separators
//     that the other parts cannot contain.
//
// The project can only be left out where the rest of the ID cannot contain the separator.

// splitProjectID splits an import ID of the form "<project>/<name>", or "<name>" for the provider's project, where
// the name cannot contain "/" (permission and group names).
func splitProjectID(id string, pd *providerData) (project, name string, err error) {
	if p, rest, found := strings.Cut(id, "/"); found {
		if err := validateProjectName(p); err != nil {
			return "", "", fmt.Errorf("the project %q %v", p, err)
		}
		if rest == "" {
			return "", "", fmt.Errorf("the name after the project is empty")
		}
		return p, rest, nil
	}
	if id == "" {
		return "", "", fmt.Errorf("the ID is empty")
	}
	if pd == nil {
		return "", "", fmt.Errorf("the provider is not configured, so the project must be given")
	}
	return pd.project, id, nil
}

// parseRoleID parses "<project>/<role ID or name>". The project is required because role names can contain "/".
func parseRoleID(id string) (project, ref string, err error) {
	p, ref, found := strings.Cut(id, "/")
	if !found {
		return "", "", fmt.Errorf("the project is missing")
	}
	if err := validateProjectName(p); err != nil {
		return "", "", fmt.Errorf("the project %q %v", p, err)
	}
	if ref == "" {
		return "", "", fmt.Errorf("the role ID or name after the project is empty")
	}
	return p, ref, nil
}

// parseGrantID parses "<project>|<principal>|<resource URI>". The project ends at the first "|" (project names
// cannot contain "|") and the resource URI starts after the last "|" (resource URIs cannot contain "|"), so the
// principal is everything in between and may itself contain "|", as Auth0 user IDs such as "auth0|abc123" do.
func parseGrantID(id string) (project, principal, uri string, err error) {
	first, last := strings.Index(id, "|"), strings.LastIndex(id, "|")
	if first < 0 || first == last {
		return "", "", "", fmt.Errorf("it must have three parts separated by \"|\"")
	}
	project, principal, uri = id[:first], id[first+1:last], id[last+1:]
	if err := validateProjectName(project); err != nil {
		return "", "", "", fmt.Errorf("the project %q %v", project, err)
	}
	if err := validatePrincipal(principal); err != nil {
		return "", "", "", fmt.Errorf("the principal %q %v", principal, err)
	}
	if err := validateResourceURI(uri); err != nil {
		return "", "", "", fmt.Errorf("the resource URI %q %v", uri, err)
	}
	return project, principal, uri, nil
}

// parseGroupMemberID parses "<project>/<group>/<principal>". Project and group names cannot contain "/", so the ID
// is split at the first two "/" and the principal is the rest, which may itself contain "/".
func parseGroupMemberID(id string) (project, group, principal string, err error) {
	parts := strings.SplitN(id, "/", 3)
	if len(parts) != 3 {
		return "", "", "", fmt.Errorf("it must have three parts separated by \"/\"")
	}
	project, group, principal = parts[0], parts[1], parts[2]
	if err := validateProjectName(project); err != nil {
		return "", "", "", fmt.Errorf("the project %q %v", project, err)
	}
	if err := validateGroupName(group); err != nil {
		return "", "", "", fmt.Errorf("the group %q %v", group, err)
	}
	if err := validateMember(principal); err != nil {
		return "", "", "", fmt.Errorf("the principal %q %v", principal, err)
	}
	return project, group, principal, nil
}

// importIDError formats an invalid import ID error.
func importIDError(id, format, example string, err error) string {
	return fmt.Sprintf("The import ID %q is not valid: %v.\n\nExpected %s, for example: %s", id, err, format, example)
}
