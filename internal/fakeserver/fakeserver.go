// Package fakeserver is an in-memory implementation of the Permio PermissionsService for tests. It follows the
// semantics of the real service closely, including its validation rules, its authorisation model for API keys
// (scoped to one project; check-only keys can only read) and a few of its quirks that the provider must cope with
// (for example DeletePermission failing with Internal for a permission that does not exist, and GetRole failing
// for a role that refers to a deleted permission).
package fakeserver

import (
	"context"
	"fmt"
	"net"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	paginationv1 "github.com/PrivateJAR/permio-go/proto/pagination/v1"
	pb "github.com/PrivateJAR/permio-go/proto/permissions/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Key describes an API key known to the fake server.
type Key struct {
	Project    string
	FullAccess bool
}

// Default API keys for tests.
const (
	FullAccessKey = "perms_test_full_access"
	CheckOnlyKey  = "perms_test_check_only"
	OrgID         = "org-test"
)

type permission struct {
	id, project, name, description string
}

type role struct {
	id, project, name, description string
	permissions                    []string
}

type grantKey struct{ project, principal, resource string }

type grant struct {
	permissions []string
	roles       []string
}

type group struct {
	id, project, name, description string
	createdAt, updatedAt           time.Time
	members                        map[string]time.Time
}

// Server is the fake PermissionsService.
type Server struct {
	pb.UnimplementedPermissionsServiceServer

	mu          sync.Mutex
	keys        map[string]Key
	permissions map[string]*permission // by name; names are unique per organisation
	roles       map[string]*role       // by id
	grants      map[grantKey]*grant
	groups      map[string]*group // by project + "/" + name
	nextID      int
	calls       map[string]int
	failNext    map[string]codes.Code
}

// New returns a fake server with FullAccessKey and CheckOnlyKey for the "default" project.
func New() *Server {
	return &Server{
		keys: map[string]Key{
			FullAccessKey: {Project: "default", FullAccess: true},
			CheckOnlyKey:  {Project: "default", FullAccess: false},
		},
		permissions: map[string]*permission{},
		roles:       map[string]*role{},
		grants:      map[grantKey]*grant{},
		groups:      map[string]*group{},
		calls:       map[string]int{},
		failNext:    map[string]codes.Code{},
	}
}

// FailNext makes the next call of an RPC (by method name, e.g. "DeletePermission") fail with code, without
// running it, to simulate a transient failure part way through a sequence of calls.
func (s *Server) FailNext(method string, code codes.Code) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failNext[method] = code
}

// AddKey registers an API key.
func (s *Server) AddKey(key string, k Key) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keys[key] = k
}

// Calls returns how many times an RPC (by method name, e.g. "GrantUserPermissionsAndRolesOnResource") was called.
func (s *Server) Calls(method string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls[method]
}

// Listener is a running fake server on an in-memory listener.
type Listener struct {
	Server *Server
	lis    *bufconn.Listener
	grpc   *grpc.Server
}

// Start serves s on an in-memory listener until Stop is called.
func Start(s *Server) *Listener {
	lis := bufconn.Listen(1 << 20)
	gs := grpc.NewServer(grpc.UnaryInterceptor(s.countCalls))
	pb.RegisterPermissionsServiceServer(gs, s)
	go func() { _ = gs.Serve(lis) }()
	return &Listener{Server: s, lis: lis, grpc: gs}
}

// Stop stops the server.
func (l *Listener) Stop() { l.grpc.Stop() }

// Target is the gRPC target to dial with DialOptions.
const Target = "passthrough:///bufnet"

// DialOptions return the options that connect a gRPC client to the listener.
func (l *Listener) DialOptions() []grpc.DialOption {
	return []grpc.DialOption{
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return l.lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	}
}

func (s *Server) countCalls(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
	name := info.FullMethod[strings.LastIndex(info.FullMethod, "/")+1:]
	s.mu.Lock()
	s.calls[name]++
	code, fail := s.failNext[name]
	delete(s.failNext, name)
	s.mu.Unlock()
	if fail {
		return nil, status.Errorf(code, "injected failure of %s", name)
	}
	return handler(ctx, req)
}

type validatable interface{ ValidateAll() error }

// begin validates the request and authorises the caller for project. It returns with s.mu held on success.
func (s *Server) begin(ctx context.Context, req validatable, project string, write bool) error {
	if err := req.ValidateAll(); err != nil {
		return status.Errorf(codes.InvalidArgument, "invalid request: %v", err)
	}
	md, _ := metadata.FromIncomingContext(ctx)
	auth := md.Get("authorization")
	if len(auth) != 1 || !strings.HasPrefix(auth[0], "Bearer ") {
		return status.Error(codes.Unauthenticated, "missing API key")
	}
	s.mu.Lock()
	key, ok := s.keys[strings.TrimPrefix(auth[0], "Bearer ")]
	if !ok {
		s.mu.Unlock()
		return status.Error(codes.Unauthenticated, "invalid API key")
	}
	if key.Project != project || (write && !key.FullAccess) {
		s.mu.Unlock()
		return status.Errorf(codes.PermissionDenied, "missing permissions on project %q", project)
	}
	return nil
}

func (s *Server) newID(prefix string) string {
	s.nextID++
	return prefix + "-" + strconv.Itoa(s.nextID)
}

func (s *Server) permissionPB(p *permission) *pb.Permission {
	return &pb.Permission{Id: p.id, OrganisationId: OrgID, Name: p.name, Description: p.description, ProjectName: p.project}
}

func (s *Server) getPermission(project, name string) *permission {
	p, ok := s.permissions[name]
	if !ok || p.project != project {
		return nil
	}
	return p
}

// rolePB converts a role. With strict set it fails like the real GetRole when a permission no longer exists;
// otherwise it skips such permissions, like the real ListRoles.
func (s *Server) rolePB(r *role, strict bool) (*pb.Role, error) {
	out := &pb.Role{Id: r.id, OrganisationId: OrgID, Name: r.name, Description: r.description, ProjectName: r.project}
	for _, name := range r.permissions {
		p := s.getPermission(r.project, name)
		if p == nil {
			if strict {
				return nil, status.Error(codes.Internal, "failed to get role")
			}
			continue
		}
		out.Permissions = append(out.Permissions, s.permissionPB(p))
	}
	return out, nil
}

func (s *Server) missingPermissions(project string, names []string) []string {
	var missing []string
	for _, n := range names {
		if s.getPermission(project, n) == nil {
			missing = append(missing, n)
		}
	}
	return missing
}

func (s *Server) missingRoles(project string, ids []string) []string {
	var missing []string
	for _, id := range ids {
		if r, ok := s.roles[id]; !ok || r.project != project {
			missing = append(missing, id)
		}
	}
	return missing
}

// --- permissions ---

func (s *Server) CreatePermission(ctx context.Context, req *pb.CreatePermissionRequest) (*pb.Permission, error) {
	if err := s.begin(ctx, req, req.ProjectName, true); err != nil {
		return nil, err
	}
	defer s.mu.Unlock()
	if p, ok := s.permissions[req.Name]; ok {
		// The real service upserts on (name, organisation, description, project) under a unique (name,
		// organisation) index: an identical permission is returned, anything else is a duplicate key error.
		if p.project == req.ProjectName && p.description == req.Description {
			return s.permissionPB(p), nil
		}
		return nil, status.Error(codes.Internal, "failed to create permission")
	}
	p := &permission{id: s.newID("perm"), project: req.ProjectName, name: req.Name, description: req.Description}
	s.permissions[p.name] = p
	return s.permissionPB(p), nil
}

func (s *Server) GetPermission(ctx context.Context, req *pb.GetPermissionRequest) (*pb.Permission, error) {
	if err := s.begin(ctx, req, req.ProjectName, false); err != nil {
		return nil, err
	}
	defer s.mu.Unlock()
	p := s.getPermission(req.ProjectName, req.Name)
	if p == nil {
		return nil, status.Error(codes.NotFound, "permission not found")
	}
	return s.permissionPB(p), nil
}

func (s *Server) UpdatePermission(ctx context.Context, req *pb.UpdatePermissionRequest) (*pb.Permission, error) {
	if err := s.begin(ctx, req, req.ProjectName, true); err != nil {
		return nil, err
	}
	defer s.mu.Unlock()
	p := s.getPermission(req.ProjectName, req.Name)
	if p == nil {
		return nil, status.Error(codes.NotFound, "permission not found")
	}
	if req.NewName != nil && *req.NewName != "" && *req.NewName != p.name {
		if _, taken := s.permissions[*req.NewName]; taken {
			return nil, status.Error(codes.Internal, "failed to update permission")
		}
		// Like the real service, a rename does not rewrite roles or grants that refer to the old name.
		delete(s.permissions, p.name)
		p.name = *req.NewName
		s.permissions[p.name] = p
	}
	p.description = req.Description
	return s.permissionPB(p), nil
}

func (s *Server) DeletePermission(ctx context.Context, req *pb.DeletePermissionRequest) (*emptypb.Empty, error) {
	if err := s.begin(ctx, req, req.ProjectName, true); err != nil {
		return nil, err
	}
	defer s.mu.Unlock()
	if s.getPermission(req.ProjectName, req.Name) == nil {
		// The real service documents this as idempotent but fails with Internal.
		return nil, status.Error(codes.Internal, "failed to delete permission")
	}
	// Like the real service, roles and grants that refer to the permission are left alone.
	delete(s.permissions, req.Name)
	return &emptypb.Empty{}, nil
}

func (s *Server) ListPermissions(ctx context.Context, req *pb.ListPermissionsRequest) (*pb.ListPermissionsResponse, error) {
	if err := s.begin(ctx, req, req.ProjectName, false); err != nil {
		return nil, err
	}
	defer s.mu.Unlock()
	var all []*permission
	for _, p := range s.permissions {
		if p.project == req.ProjectName && matchesSearch(p.name, req.GetSearch()) {
			all = append(all, p)
		}
	}
	sort.Slice(all, func(i, j int) bool { return all[i].id < all[j].id })
	items, next := paginate(all, func(p *permission) string { return p.id }, req.GetPagination())
	resp := &pb.ListPermissionsResponse{Pagination: &paginationv1.PaginationResponse{NextCursor: next}}
	for _, p := range items {
		resp.Permissions = append(resp.Permissions, s.permissionPB(p))
	}
	return resp, nil
}

// --- roles ---

func (s *Server) validateRolePermissions(project string, names []string) error {
	if len(names) == 0 {
		// The real service checks permission.get on each permission and rejects an empty check.
		return status.Error(codes.InvalidArgument, "at least one resource uri and permission are required")
	}
	if missing := s.missingPermissions(project, names); len(missing) > 0 {
		return status.Errorf(codes.InvalidArgument, "specified permissions not found: %v", missing)
	}
	return nil
}

func (s *Server) CreateRole(ctx context.Context, req *pb.CreateRoleRequest) (*pb.Role, error) {
	if err := s.begin(ctx, req, req.ProjectName, true); err != nil {
		return nil, err
	}
	defer s.mu.Unlock()
	if err := s.validateRolePermissions(req.ProjectName, req.Permissions); err != nil {
		return nil, err
	}
	for _, r := range s.roles {
		if r.name == req.Name {
			if r.project == req.ProjectName && r.description == req.Description && slices.Equal(r.permissions, req.Permissions) {
				return s.rolePB(r, false)
			}
			return nil, status.Error(codes.Internal, "failed to create role")
		}
	}
	r := &role{id: s.newID("role"), project: req.ProjectName, name: req.Name, description: req.Description, permissions: slices.Clone(req.Permissions)}
	s.roles[r.id] = r
	return s.rolePB(r, false)
}

func (s *Server) GetRole(ctx context.Context, req *pb.GetRoleRequest) (*pb.Role, error) {
	if err := s.begin(ctx, req, req.ProjectName, false); err != nil {
		return nil, err
	}
	defer s.mu.Unlock()
	r, ok := s.roles[req.Id]
	if !ok || r.project != req.ProjectName {
		return nil, status.Error(codes.NotFound, "role not found")
	}
	return s.rolePB(r, true)
}

func (s *Server) UpdateRole(ctx context.Context, req *pb.UpdateRoleRequest) (*pb.Role, error) {
	if err := s.begin(ctx, req, req.ProjectName, true); err != nil {
		return nil, err
	}
	defer s.mu.Unlock()
	if err := s.validateRolePermissions(req.ProjectName, req.Permissions); err != nil {
		return nil, err
	}
	r, ok := s.roles[req.Id]
	if !ok || r.project != req.ProjectName {
		return nil, status.Error(codes.NotFound, "role not found")
	}
	if _, err := s.rolePB(r, true); err != nil {
		return nil, err // the real service reads the old role first
	}
	for _, other := range s.roles {
		if other.id != r.id && other.name == req.Name {
			return nil, status.Error(codes.Internal, "failed to update role")
		}
	}
	r.name, r.description, r.permissions = req.Name, req.Description, slices.Clone(req.Permissions)
	return s.rolePB(r, true)
}

func (s *Server) DeleteRole(ctx context.Context, req *pb.DeleteRoleRequest) (*emptypb.Empty, error) {
	if err := s.begin(ctx, req, req.ProjectName, true); err != nil {
		return nil, err
	}
	defer s.mu.Unlock()
	r, ok := s.roles[req.Id]
	if !ok || r.project != req.ProjectName {
		return nil, status.Error(codes.NotFound, "role not found")
	}
	if _, err := s.rolePB(r, true); err != nil {
		return nil, err
	}
	delete(s.roles, req.Id)
	return &emptypb.Empty{}, nil
}

func (s *Server) ListRoles(ctx context.Context, req *pb.ListRolesRequest) (*pb.ListRolesResponse, error) {
	if err := s.begin(ctx, req, req.ProjectName, false); err != nil {
		return nil, err
	}
	defer s.mu.Unlock()
	var all []*role
	for _, r := range s.roles {
		if r.project == req.ProjectName && matchesSearch(r.name, req.GetSearch()) {
			all = append(all, r)
		}
	}
	sort.Slice(all, func(i, j int) bool { return all[i].id < all[j].id })
	items, next := paginate(all, func(r *role) string { return r.id }, req.GetPagination())
	resp := &pb.ListRolesResponse{Pagination: &paginationv1.PaginationResponse{NextCursor: next}}
	for _, r := range items {
		out, _ := s.rolePB(r, false)
		resp.Roles = append(resp.Roles, out)
	}
	return resp, nil
}

// --- grants ---

func (s *Server) requireSubjectPrincipal(project, principal string) error {
	name, isGroup := strings.CutPrefix(principal, "group:")
	if !isGroup {
		return nil
	}
	if !validGroupName(name) {
		return status.Errorf(codes.InvalidArgument, "%q is not a valid group name", name)
	}
	if _, ok := s.groups[project+"/"+name]; !ok {
		return status.Errorf(codes.NotFound, "group %q not found", name)
	}
	return nil
}

func (s *Server) GrantUserPermissionsAndRolesOnResource(ctx context.Context, req *pb.GrantUserPermissionsAndRolesOnResourceRequest) (*emptypb.Empty, error) {
	if err := s.begin(ctx, req, req.ProjectName, true); err != nil {
		return nil, err
	}
	defer s.mu.Unlock()
	if err := validateResourceURI(req.ResourceUri); err != nil {
		return nil, err
	}
	if err := s.requireSubjectPrincipal(req.ProjectName, req.UserId); err != nil {
		return nil, err
	}
	mp, mr := s.missingPermissions(req.ProjectName, req.Permissions), s.missingRoles(req.ProjectName, req.Roles)
	if len(mp) > 0 || len(mr) > 0 {
		return nil, status.Errorf(codes.InvalidArgument, "invalid permissions: %v\n invalid roles: %v", mp, mr)
	}
	k := grantKey{req.ProjectName, req.UserId, req.ResourceUri}
	g, ok := s.grants[k]
	if !ok {
		g = &grant{}
		s.grants[k] = g
	}
	g.permissions = addToSet(g.permissions, req.Permissions)
	g.roles = addToSet(g.roles, req.Roles)
	return &emptypb.Empty{}, nil
}

func (s *Server) RevokeUserPermissionsAndRolesOnResource(ctx context.Context, req *pb.RevokeUserPermissionsAndRolesOnResourceRequest) (*emptypb.Empty, error) {
	if err := s.begin(ctx, req, req.ProjectName, true); err != nil {
		return nil, err
	}
	defer s.mu.Unlock()
	if err := validateResourceURI(req.ResourceUri); err != nil {
		return nil, err
	}
	mp, mr := s.missingPermissions(req.ProjectName, req.Permissions), s.missingRoles(req.ProjectName, req.Roles)
	if len(mp) > 0 || len(mr) > 0 {
		return nil, status.Errorf(codes.InvalidArgument, "invalid permissions: %v\n invalid roles: %v", mp, mr)
	}
	k := grantKey{req.ProjectName, req.UserId, req.ResourceUri}
	if g, ok := s.grants[k]; ok {
		g.permissions = pullAll(g.permissions, req.Permissions)
		g.roles = pullAll(g.roles, req.Roles)
		if len(g.permissions) == 0 && len(g.roles) == 0 {
			delete(s.grants, k)
		}
	}
	return &emptypb.Empty{}, nil
}

func (s *Server) GetUserPermissionsAndRolesOnResource(ctx context.Context, req *pb.GetUserPermissionsAndRolesOnResourceRequest) (*pb.GetUserPermissionsAndRolesOnResourceResponse, error) {
	if err := s.begin(ctx, req, req.ProjectName, false); err != nil {
		return nil, err
	}
	defer s.mu.Unlock()
	if err := validateResourceURI(req.ResourceUri); err != nil {
		return nil, err
	}
	if err := s.requireSubjectPrincipal(req.ProjectName, req.UserId); err != nil {
		return nil, err
	}
	resp := &pb.GetUserPermissionsAndRolesOnResourceResponse{ProjectName: req.ProjectName, UserId: req.UserId, ResourceUri: req.ResourceUri, Permissions: []string{}, Roles: []string{}}
	if g, ok := s.grants[grantKey{req.ProjectName, req.UserId, req.ResourceUri}]; ok {
		resp.Permissions = slices.Clone(g.permissions)
		resp.Roles = slices.Clone(g.roles)
	}
	return resp, nil
}

// SetGrantOutOfBand writes a grant directly, bypassing validation, to simulate data the API can leave behind (for
// example a grant that still names a deleted permission).
func (s *Server) SetGrantOutOfBand(project, principal, resource string, permissions, roles []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.grants[grantKey{project, principal, resource}] = &grant{permissions: slices.Clone(permissions), roles: slices.Clone(roles)}
}

// Check implements the real evaluation: grants on the resource, an ancestor, or a stored "_" wildcard URI that
// matches it, made to the principal or a group it belongs to, directly or through roles.
func (s *Server) Check(ctx context.Context, req *pb.CheckPermissionRequest) (*pb.CheckPermissionResponse, error) {
	if err := s.begin(ctx, req, req.ProjectName, false); err != nil {
		return nil, err
	}
	defer s.mu.Unlock()
	for _, uri := range req.ResourceUris {
		if err := validateResourceURI(uri); err != nil {
			return nil, err
		}
	}
	if err := s.requireSubjectPrincipal(req.ProjectName, req.PrincipalId); err != nil {
		return nil, err
	}
	principals := []string{req.PrincipalId}
	if !strings.HasPrefix(req.PrincipalId, "group:") {
		for _, g := range s.groups {
			if _, ok := g.members[req.PrincipalId]; ok && g.project == req.ProjectName {
				principals = append(principals, "group:"+g.name)
			}
		}
	}
	resp := &pb.CheckPermissionResponse{Passed: true}
	for _, uri := range req.ResourceUris {
		held := map[string]bool{}
		for k, g := range s.grants {
			if k.project != req.ProjectName || !slices.Contains(principals, k.principal) || !matchGrantURI(uri, k.resource) {
				continue
			}
			for _, p := range g.permissions {
				held[p] = true
			}
			for _, id := range g.roles {
				if r, ok := s.roles[id]; ok {
					for _, p := range r.permissions {
						held[p] = true
					}
				}
			}
		}
		var missing []string
		for _, p := range req.Permissions {
			if !held[p] {
				missing = append(missing, p)
			}
		}
		if len(missing) > 0 {
			resp.Passed = false
			resp.MissingPermissions = append(resp.MissingPermissions, &pb.MissingPermissions{ResourceUri: uri, MissingPermissions: missing})
		}
	}
	return resp, nil
}

// --- groups ---

func (s *Server) groupPB(g *group) *pb.Group {
	return &pb.Group{
		Id: g.id, OrganisationId: OrgID, ProjectName: g.project, Name: g.name, Description: g.description,
		PrincipalId: "group:" + g.name, CreatedAt: timestamppb.New(g.createdAt), UpdatedAt: timestamppb.New(g.updatedAt),
	}
}

func (s *Server) getGroup(project, name string) (*group, error) {
	g, ok := s.groups[project+"/"+name]
	if !ok {
		return nil, status.Error(codes.NotFound, "group not found")
	}
	return g, nil
}

func (s *Server) CreateGroup(ctx context.Context, req *pb.CreateGroupRequest) (*pb.Group, error) {
	if err := s.begin(ctx, req, req.ProjectName, true); err != nil {
		return nil, err
	}
	defer s.mu.Unlock()
	if _, ok := s.groups[req.ProjectName+"/"+req.Name]; ok {
		return nil, status.Error(codes.AlreadyExists, "a group with this name already exists in the project")
	}
	now := time.Now()
	g := &group{id: s.newID("group"), project: req.ProjectName, name: req.Name, description: req.Description, createdAt: now, updatedAt: now, members: map[string]time.Time{}}
	s.groups[req.ProjectName+"/"+req.Name] = g
	return s.groupPB(g), nil
}

func (s *Server) GetGroup(ctx context.Context, req *pb.GetGroupRequest) (*pb.Group, error) {
	if err := s.begin(ctx, req, req.ProjectName, false); err != nil {
		return nil, err
	}
	defer s.mu.Unlock()
	g, err := s.getGroup(req.ProjectName, req.Name)
	if err != nil {
		return nil, err
	}
	return s.groupPB(g), nil
}

func (s *Server) UpdateGroup(ctx context.Context, req *pb.UpdateGroupRequest) (*pb.Group, error) {
	if err := s.begin(ctx, req, req.ProjectName, true); err != nil {
		return nil, err
	}
	defer s.mu.Unlock()
	g, err := s.getGroup(req.ProjectName, req.Name)
	if err != nil {
		return nil, err
	}
	g.description = req.Description
	g.updatedAt = time.Now()
	return s.groupPB(g), nil
}

func (s *Server) DeleteGroup(ctx context.Context, req *pb.DeleteGroupRequest) (*emptypb.Empty, error) {
	if err := s.begin(ctx, req, req.ProjectName, true); err != nil {
		return nil, err
	}
	defer s.mu.Unlock()
	delete(s.groups, req.ProjectName+"/"+req.Name)
	for k := range s.grants {
		if k.project == req.ProjectName && k.principal == "group:"+req.Name {
			delete(s.grants, k)
		}
	}
	return &emptypb.Empty{}, nil
}

func (s *Server) ListGroups(ctx context.Context, req *pb.ListGroupsRequest) (*pb.ListGroupsResponse, error) {
	if err := s.begin(ctx, req, req.ProjectName, false); err != nil {
		return nil, err
	}
	defer s.mu.Unlock()
	var all []*group
	for _, g := range s.groups {
		if g.project == req.ProjectName && matchesSearch(g.name, req.GetSearch()) {
			all = append(all, g)
		}
	}
	sort.Slice(all, func(i, j int) bool { return all[i].name < all[j].name })
	items, next := paginate(all, func(g *group) string { return g.name }, req.GetPagination())
	resp := &pb.ListGroupsResponse{Groups: []*pb.Group{}, Pagination: &paginationv1.PaginationResponse{NextCursor: next}}
	for _, g := range items {
		resp.Groups = append(resp.Groups, s.groupPB(g))
	}
	return resp, nil
}

func rejectGroupMembers(ids []string) error {
	for _, id := range ids {
		if strings.HasPrefix(id, "group:") {
			return status.Errorf(codes.InvalidArgument, "%q cannot be a group member", id)
		}
	}
	return nil
}

func (s *Server) AddGroupMembers(ctx context.Context, req *pb.AddGroupMembersRequest) (*pb.AddGroupMembersResponse, error) {
	if err := s.begin(ctx, req, req.ProjectName, true); err != nil {
		return nil, err
	}
	defer s.mu.Unlock()
	if err := rejectGroupMembers(req.PrincipalIds); err != nil {
		return nil, err
	}
	g, err := s.getGroup(req.ProjectName, req.Name)
	if err != nil {
		return nil, err
	}
	resp := &pb.AddGroupMembersResponse{AddedPrincipalIds: []string{}, ExistingPrincipalIds: []string{}}
	for _, id := range req.PrincipalIds {
		if _, ok := g.members[id]; ok {
			resp.ExistingPrincipalIds = append(resp.ExistingPrincipalIds, id)
			continue
		}
		g.members[id] = time.Now()
		resp.AddedPrincipalIds = append(resp.AddedPrincipalIds, id)
	}
	return resp, nil
}

func (s *Server) RemoveGroupMembers(ctx context.Context, req *pb.RemoveGroupMembersRequest) (*pb.RemoveGroupMembersResponse, error) {
	if err := s.begin(ctx, req, req.ProjectName, true); err != nil {
		return nil, err
	}
	defer s.mu.Unlock()
	if err := rejectGroupMembers(req.PrincipalIds); err != nil {
		return nil, err
	}
	g, err := s.getGroup(req.ProjectName, req.Name)
	if err != nil {
		return nil, err
	}
	resp := &pb.RemoveGroupMembersResponse{RemovedPrincipalIds: []string{}, NotMemberPrincipalIds: []string{}}
	for _, id := range req.PrincipalIds {
		if _, ok := g.members[id]; !ok {
			resp.NotMemberPrincipalIds = append(resp.NotMemberPrincipalIds, id)
			continue
		}
		delete(g.members, id)
		resp.RemovedPrincipalIds = append(resp.RemovedPrincipalIds, id)
	}
	return resp, nil
}

func (s *Server) ListGroupMembers(ctx context.Context, req *pb.ListGroupMembersRequest) (*pb.ListGroupMembersResponse, error) {
	if err := s.begin(ctx, req, req.ProjectName, false); err != nil {
		return nil, err
	}
	defer s.mu.Unlock()
	g, err := s.getGroup(req.ProjectName, req.Name)
	if err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(g.members))
	for id := range g.members {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	items, next := paginate(ids, func(id string) string { return id }, req.GetPagination())
	resp := &pb.ListGroupMembersResponse{Members: []*pb.GroupMember{}, Pagination: &paginationv1.PaginationResponse{NextCursor: next}}
	for _, id := range items {
		resp.Members = append(resp.Members, &pb.GroupMember{PrincipalId: id, CreatedAt: timestamppb.New(g.members[id])})
	}
	return resp, nil
}

func (s *Server) ListGroupsForPrincipal(ctx context.Context, req *pb.ListGroupsForPrincipalRequest) (*pb.ListGroupsForPrincipalResponse, error) {
	if err := s.begin(ctx, req, req.ProjectName, false); err != nil {
		return nil, err
	}
	defer s.mu.Unlock()
	if err := rejectGroupMembers([]string{req.PrincipalId}); err != nil {
		return nil, err
	}
	var all []*group
	for _, g := range s.groups {
		if _, ok := g.members[req.PrincipalId]; ok && g.project == req.ProjectName {
			all = append(all, g)
		}
	}
	sort.Slice(all, func(i, j int) bool { return all[i].name < all[j].name })
	items, next := paginate(all, func(g *group) string { return g.name }, req.GetPagination())
	resp := &pb.ListGroupsForPrincipalResponse{Groups: []*pb.Group{}, Pagination: &paginationv1.PaginationResponse{NextCursor: next}}
	for _, g := range items {
		resp.Groups = append(resp.Groups, s.groupPB(g))
	}
	return resp, nil
}

// --- helpers ---

func matchesSearch(name, search string) bool {
	return search == "" || strings.Contains(strings.ToLower(name), strings.ToLower(search))
}

// paginate applies keyset pagination: items must be sorted by key; the cursor is the key of the last item served.
func paginate[T any](items []T, key func(T) string, p *paginationv1.PaginationRequest) ([]T, string) {
	limit := 10
	if p.GetLimit() != 0 {
		limit = int(p.GetLimit())
	}
	if c := p.GetCursor(); c != "" {
		i := sort.Search(len(items), func(i int) bool { return key(items[i]) > c })
		items = items[i:]
	}
	if len(items) > limit {
		return items[:limit], key(items[limit-1])
	}
	return items, ""
}

func addToSet(set, items []string) []string {
	for _, it := range items {
		if !slices.Contains(set, it) {
			set = append(set, it)
		}
	}
	return set
}

func pullAll(set, items []string) []string {
	return slices.DeleteFunc(set, func(s string) bool { return slices.Contains(items, s) })
}

func validGroupName(name string) bool {
	if name == "" || len(name) > 64 {
		return false
	}
	for _, r := range name {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
			return false
		}
	}
	return true
}

func splitURI(uri string) ([]string, error) {
	if uri == "" || len(uri) > 2048 || !strings.HasPrefix(uri, "/") {
		return nil, fmt.Errorf("invalid resource uri %q", uri)
	}
	segments := strings.Split(uri[1:], "/")
	for _, seg := range segments {
		if seg == "" || strings.ContainsAny(seg, " \t\r\n") {
			return nil, fmt.Errorf("invalid resource uri %q", uri)
		}
	}
	return segments, nil
}

func validateResourceURI(uri string) error {
	if _, err := splitURI(uri); err != nil {
		return status.Error(codes.InvalidArgument, err.Error())
	}
	return nil
}

// matchGrantURI reports whether a grant made on granted applies to checked: granted must be checked or an ancestor
// of it, segment by segment, where a granted "_" segment matches any one segment.
func matchGrantURI(checked, granted string) bool {
	c, err := splitURI(checked)
	if err != nil {
		return false
	}
	g, err := splitURI(granted)
	if err != nil || len(g) > len(c) {
		return false
	}
	for i, seg := range g {
		if seg != c[i] && seg != "_" {
			return false
		}
	}
	return true
}
