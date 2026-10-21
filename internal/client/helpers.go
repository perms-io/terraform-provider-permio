package client

import (
	"context"
	"fmt"
	"sort"

	paginationv1 "github.com/PrivateJAR/permio-go/proto/pagination/v1"
	pb "github.com/PrivateJAR/permio-go/proto/permissions/v1"
	"google.golang.org/protobuf/proto"
)

// PageSize is the largest page the API serves.
const PageSize = 100

// maxPages bounds pagination loops, in case a server keeps returning a cursor.
const maxPages = 10000

// MemberBatchSize is the largest number of principals AddGroupMembers and RemoveGroupMembers accept per call.
const MemberBatchSize = 100

func page(cursor string) *paginationv1.PaginationRequest {
	p := &paginationv1.PaginationRequest{Limit: proto.Int32(PageSize)}
	if cursor != "" {
		p.Cursor = proto.String(cursor)
	}
	return p
}

// ListAllPermissions returns every permission in a project.
func (c *Client) ListAllPermissions(ctx context.Context, project string) ([]*pb.Permission, error) {
	var out []*pb.Permission
	cursor := ""
	for range maxPages {
		resp, err := c.API.ListPermissions(ctx, &pb.ListPermissionsRequest{ProjectName: project, Pagination: page(cursor)})
		if err != nil {
			return nil, err
		}
		out = append(out, resp.GetPermissions()...)
		cursor = resp.GetPagination().GetNextCursor()
		if cursor == "" {
			return out, nil
		}
	}
	return nil, fmt.Errorf("too many pages of permissions")
}

// ListAllRoles returns every role in a project, optionally filtered by the API's name search (a case-insensitive
// substring match).
func (c *Client) ListAllRoles(ctx context.Context, project, search string) ([]*pb.Role, error) {
	var out []*pb.Role
	cursor := ""
	for range maxPages {
		req := &pb.ListRolesRequest{ProjectName: project, Pagination: page(cursor)}
		if search != "" {
			req.Search = proto.String(search)
		}
		resp, err := c.API.ListRoles(ctx, req)
		if err != nil {
			return nil, err
		}
		out = append(out, resp.GetRoles()...)
		cursor = resp.GetPagination().GetNextCursor()
		if cursor == "" {
			return out, nil
		}
	}
	return nil, fmt.Errorf("too many pages of roles")
}

// FindRoleByName returns the role with exactly this name in a project, or nil if there is none.
func (c *Client) FindRoleByName(ctx context.Context, project, name string) (*pb.Role, error) {
	roles, err := c.ListAllRoles(ctx, project, name)
	if err != nil {
		return nil, err
	}
	for _, r := range roles {
		if r.GetName() == name {
			return r, nil
		}
	}
	return nil, nil
}

// FindRoleByID returns the role with this ID by listing the project's roles, or nil if there is none. Unlike
// GetRole, listing tolerates roles that refer to permissions which no longer exist.
func (c *Client) FindRoleByID(ctx context.Context, project, id string) (*pb.Role, error) {
	roles, err := c.ListAllRoles(ctx, project, "")
	if err != nil {
		return nil, err
	}
	for _, r := range roles {
		if r.GetId() == id {
			return r, nil
		}
	}
	return nil, nil
}

// ListAllGroupMembers returns the principal IDs of every member of a group, sorted.
func (c *Client) ListAllGroupMembers(ctx context.Context, project, group string) ([]string, error) {
	var out []string
	cursor := ""
	for range maxPages {
		resp, err := c.API.ListGroupMembers(ctx, &pb.ListGroupMembersRequest{ProjectName: project, Name: group, Pagination: page(cursor)})
		if err != nil {
			return nil, err
		}
		for _, m := range resp.GetMembers() {
			out = append(out, m.GetPrincipalId())
		}
		cursor = resp.GetPagination().GetNextCursor()
		if cursor == "" {
			sort.Strings(out)
			return out, nil
		}
	}
	return nil, fmt.Errorf("too many pages of group members")
}

// IsGroupMember reports whether principal is a member of group, by listing the principal's groups (usually far
// fewer than a group's members).
func (c *Client) IsGroupMember(ctx context.Context, project, group, principal string) (bool, error) {
	cursor := ""
	for range maxPages {
		resp, err := c.API.ListGroupsForPrincipal(ctx, &pb.ListGroupsForPrincipalRequest{ProjectName: project, PrincipalId: principal, Pagination: page(cursor)})
		if err != nil {
			return false, err
		}
		for _, g := range resp.GetGroups() {
			if g.GetName() == group {
				return true, nil
			}
		}
		cursor = resp.GetPagination().GetNextCursor()
		if cursor == "" {
			return false, nil
		}
	}
	return false, fmt.Errorf("too many pages of groups")
}

// AddGroupMembers adds principals to a group in batches.
func (c *Client) AddGroupMembers(ctx context.Context, project, group string, principals []string) error {
	for _, batch := range batches(principals, MemberBatchSize) {
		if _, err := c.API.AddGroupMembers(ctx, &pb.AddGroupMembersRequest{ProjectName: project, Name: group, PrincipalIds: batch}); err != nil {
			return err
		}
	}
	return nil
}

// RemoveGroupMembers removes principals from a group in batches.
func (c *Client) RemoveGroupMembers(ctx context.Context, project, group string, principals []string) error {
	for _, batch := range batches(principals, MemberBatchSize) {
		if _, err := c.API.RemoveGroupMembers(ctx, &pb.RemoveGroupMembersRequest{ProjectName: project, Name: group, PrincipalIds: batch}); err != nil {
			return err
		}
	}
	return nil
}

func batches(items []string, size int) [][]string {
	var out [][]string
	for len(items) > 0 {
		n := min(size, len(items))
		out = append(out, items[:n])
		items = items[n:]
	}
	return out
}

// PermissionNames returns the names of a role's permissions.
func PermissionNames(r *pb.Role) []string {
	names := make([]string, 0, len(r.GetPermissions()))
	for _, p := range r.GetPermissions() {
		names = append(names, p.GetName())
	}
	return names
}
