package provider

import (
	"slices"
	"strings"
	"testing"

	pb "github.com/PrivateJAR/permio-go/proto/permissions/v1"
)

func TestParseGrantID(t *testing.T) {
	cases := []struct {
		id                      string
		project, principal, uri string
		err                     string
	}{
		{id: "default|alice|/docs/1", project: "default", principal: "alice", uri: "/docs/1"},
		{id: "prod|group:eng|/w/_/billing", project: "prod", principal: "group:eng", uri: "/w/_/billing"},
		// Auth0 user IDs contain "|": the principal is everything between the first and the last "|".
		{id: "default|auth0|abc123|/docs/1", project: "default", principal: "auth0|abc123", uri: "/docs/1"},
		{id: "default|google-oauth2|1|2|/docs", project: "default", principal: "google-oauth2|1|2", uri: "/docs"},
		{id: "prod|user/with/slashes|/docs", project: "prod", principal: "user/with/slashes", uri: "/docs"},
		// The short form is no longer accepted: "auth0|abc123|/docs/1" would read as project "auth0".
		{id: "alice|/docs/1", err: `three parts`},
		{id: "alice", err: `three parts`},
		{id: "", err: `three parts`},
		{id: "default||/docs", err: `the principal "" must not be empty`},
		{id: "default|alice|docs", err: `the resource URI "docs" must start with "/"`},
		{id: "default|alice|", err: `the resource URI "" must not be empty`},
		{id: "BAD|alice|/docs", err: `the project "BAD" is not a valid project name`},
		{id: strings.Repeat("a", 33) + "|alice|/docs", err: `is not a valid project name`},
		{id: "default|group:Not_Valid|/docs", err: `reserved for groups`},
	}
	for _, c := range cases {
		project, principal, uri, err := parseGrantID(c.id)
		if c.err != "" {
			if err == nil || !strings.Contains(err.Error(), c.err) {
				t.Errorf("parseGrantID(%q) error = %v, want one containing %q", c.id, err, c.err)
			}
			continue
		}
		if err != nil || project != c.project || principal != c.principal || uri != c.uri {
			t.Errorf("parseGrantID(%q) = %q, %q, %q, %v; want %q, %q, %q", c.id, project, principal, uri, err, c.project, c.principal, c.uri)
		}
	}
}

func TestParseGroupMemberID(t *testing.T) {
	cases := []struct {
		id                        string
		project, group, principal string
		err                       string
	}{
		{id: "default/eng/alice", project: "default", group: "eng", principal: "alice"},
		// The principal may contain "/": the ID is split at the first two "/" only.
		{id: "default/eng/user/bob@example.com", project: "default", group: "eng", principal: "user/bob@example.com"},
		{id: "default/eng/auth0|abc", project: "default", group: "eng", principal: "auth0|abc"},
		// The short form is no longer accepted: "eng/user/bob" would read as project "eng".
		{id: "eng/alice", err: `three parts`},
		{id: "alice", err: `three parts`},
		{id: "default/eng/", err: `the principal "" must not be empty`},
		{id: "default/eng/group:other", err: `groups cannot be members`},
		{id: "default/Eng/alice", err: `the group "Eng" is not a valid group name`},
		{id: "default/" + strings.Repeat("g", 65) + "/alice", err: `is not a valid group name`},
		// This check used to miss the 32-character limit on project names.
		{id: strings.Repeat("p", 33) + "/eng/alice", err: `is not a valid project name`},
	}
	for _, c := range cases {
		project, group, principal, err := parseGroupMemberID(c.id)
		if c.err != "" {
			if err == nil || !strings.Contains(err.Error(), c.err) {
				t.Errorf("parseGroupMemberID(%q) error = %v, want one containing %q", c.id, err, c.err)
			}
			continue
		}
		if err != nil || project != c.project || group != c.group || principal != c.principal {
			t.Errorf("parseGroupMemberID(%q) = %q, %q, %q, %v; want %q, %q, %q", c.id, project, group, principal, err, c.project, c.group, c.principal)
		}
	}
}

func TestParseRoleID(t *testing.T) {
	for id, want := range map[string][2]string{
		"default/role-1":            {"default", "role-1"},
		"default/Document editor":   {"default", "Document editor"},
		"default/Docs/Editors (EU)": {"default", "Docs/Editors (EU)"},
	} {
		project, ref, err := parseRoleID(id)
		if err != nil || project != want[0] || ref != want[1] {
			t.Errorf("parseRoleID(%q) = %q, %q, %v; want %q, %q", id, project, ref, err, want[0], want[1])
		}
	}
	for id, want := range map[string]string{
		"role-1":        "the project is missing",
		"default/":      "is empty",
		"Not_Valid/x":   "not a valid project name",
		"/Docs/Editors": "not a valid project name",
	} {
		if _, _, err := parseRoleID(id); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("parseRoleID(%q) error = %v, want one containing %q", id, err, want)
		}
	}
}

func TestSplitProjectID(t *testing.T) {
	pd := &providerData{project: "default"}
	for id, want := range map[string][2]string{
		"doc.read":      {"default", "doc.read"},
		"prod/doc.read": {"prod", "doc.read"},
	} {
		project, name, err := splitProjectID(id, pd)
		if err != nil || project != want[0] || name != want[1] {
			t.Errorf("splitProjectID(%q) = %q, %q, %v; want %q, %q", id, project, name, err, want[0], want[1])
		}
	}
	for _, id := range []string{"", "prod/", "Prod/doc.read", strings.Repeat("p", 33) + "/doc.read"} {
		if _, _, err := splitProjectID(id, pd); err == nil {
			t.Errorf("splitProjectID(%q) succeeded, want an error", id)
		}
	}
}

func TestValidateProjectName(t *testing.T) {
	for _, ok := range []string{"default", "a", "my-project-2", strings.Repeat("a", 32)} {
		if err := validateProjectName(ok); err != nil {
			t.Errorf("validateProjectName(%q) = %v, want nil", ok, err)
		}
	}
	for _, bad := range []string{"", "Default", "has space", "a/b", "a|b", "under_score", strings.Repeat("a", 33)} {
		if err := validateProjectName(bad); err == nil {
			t.Errorf("validateProjectName(%q) = nil, want an error", bad)
		}
	}
}

func TestDifference(t *testing.T) {
	cases := []struct{ a, b, want []string }{
		{nil, nil, nil},
		{[]string{"a", "b", "c"}, nil, []string{"a", "b", "c"}},
		{[]string{"a", "b", "c"}, []string{"b"}, []string{"a", "c"}},
		{[]string{"c", "a", "b"}, []string{"a", "b", "c", "d"}, nil},
		{[]string{"x", "x", "y"}, []string{"y"}, []string{"x", "x"}},
	}
	for _, c := range cases {
		if got := difference(c.a, c.b); !slices.Equal(got, c.want) {
			t.Errorf("difference(%v, %v) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}

func TestGroupPrincipal(t *testing.T) {
	if got := groupPrincipal(&pb.Group{Name: "eng", PrincipalId: "group:eng"}); got != "group:eng" {
		t.Errorf("groupPrincipal = %q, want the API's value", got)
	}
	if got := groupPrincipal(&pb.Group{Name: "eng"}); got != "group:eng" {
		t.Errorf("groupPrincipal without principal_id = %q, want group:eng", got)
	}
}
