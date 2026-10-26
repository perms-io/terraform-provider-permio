package client

import (
	"context"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	pb "github.com/PrivateJAR/permio-go/proto/permissions/v1"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

func TestParseEndpoint(t *testing.T) {
	cases := []struct {
		in        string
		target    string
		plaintext bool
		err       bool
	}{
		{"", "api.perms.io:443", false, false},
		{"api.perms.io:443", "api.perms.io:443", false, false},
		{"api.perms.io", "api.perms.io:443", false, false},
		{"https://dev-api.perms.io", "dev-api.perms.io:443", false, false},
		{"https://dev-api.perms.io:8443/", "dev-api.perms.io:8443", false, false},
		{"http://localhost:8080", "localhost:8080", true, false},
		{"http://localhost", "localhost:80", true, false},
		{"passthrough:///bufnet", "passthrough:///bufnet", false, false},
		{"https://api.perms.io/v1", "", false, true},
	}
	for _, c := range cases {
		target, plaintext, err := parseEndpoint(c.in)
		if (err != nil) != c.err || target != c.target || plaintext != c.plaintext {
			t.Errorf("parseEndpoint(%q) = %q, %v, %v; want %q, %v, err=%v", c.in, target, plaintext, err, c.target, c.plaintext, c.err)
		}
	}
}

// testKey is a well-formed API key (valid checksum); the fake server accepts any key.
const testKey = "perms_TestClientKey0000000000000000000483gUu"

func TestNewRequiresAPIKey(t *testing.T) {
	if _, err := New(Config{}); err == nil {
		t.Fatal("expected an error without an API key")
	}
}

func TestNewRejectsMalformedAPIKey(t *testing.T) {
	if _, err := New(Config{APIKey: "perms_typo"}); err == nil {
		t.Fatal("expected an error for a malformed API key")
	}
}

// flakyServer fails the first failures calls of every RPC with Unavailable and records the authorization header.
type flakyServer struct {
	pb.UnimplementedPermissionsServiceServer
	mu       sync.Mutex
	failures int
	calls    map[string]int
	auth     []string
}

func (s *flakyServer) record(ctx context.Context, method string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	md, _ := metadata.FromIncomingContext(ctx)
	s.auth = append(s.auth, md.Get("authorization")...)
	s.calls[method]++
	if s.calls[method] <= s.failures {
		return status.Error(codes.Unavailable, "try again")
	}
	return nil
}

func (s *flakyServer) GetPermission(ctx context.Context, req *pb.GetPermissionRequest) (*pb.Permission, error) {
	if err := s.record(ctx, "get"); err != nil {
		return nil, err
	}
	return &pb.Permission{Name: req.Name}, nil
}

func (s *flakyServer) CreatePermission(ctx context.Context, req *pb.CreatePermissionRequest) (*pb.Permission, error) {
	if err := s.record(ctx, "create"); err != nil {
		return nil, err
	}
	return &pb.Permission{Name: req.Name}, nil
}

func startFlaky(t *testing.T, failures int) (*flakyServer, *Client) {
	t.Helper()
	srv := &flakyServer{failures: failures, calls: map[string]int{}}
	lis := bufconn.Listen(1 << 16)
	gs := grpc.NewServer()
	pb.RegisterPermissionsServiceServer(gs, srv)
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)

	c, err := New(Config{
		APIKey:         testKey,
		Endpoint:       "passthrough:///bufnet",
		Insecure:       true,
		RetryBaseDelay: time.Millisecond,
		DialOptions: []grpc.DialOption{grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		})},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return srv, c
}

func TestReadsAreRetriedOnUnavailable(t *testing.T) {
	srv, c := startFlaky(t, 2)
	p, err := c.API.GetPermission(context.Background(), &pb.GetPermissionRequest{ProjectName: "default", Name: "doc.read"})
	if err != nil {
		t.Fatalf("GetPermission: %v", err)
	}
	if p.GetName() != "doc.read" || srv.calls["get"] != 3 {
		t.Fatalf("got %q after %d calls, want doc.read after 3", p.GetName(), srv.calls["get"])
	}
	for _, a := range srv.auth {
		if a != "Bearer "+testKey {
			t.Fatalf("authorization header = %q", a)
		}
	}
}

func TestReadsGiveUpAfterMaxRetries(t *testing.T) {
	srv, c := startFlaky(t, 100)
	_, err := c.API.GetPermission(context.Background(), &pb.GetPermissionRequest{ProjectName: "default", Name: "doc.read"})
	if status.Code(err) != codes.Unavailable || srv.calls["get"] != 5 {
		t.Fatalf("err = %v after %d calls, want Unavailable after 5", err, srv.calls["get"])
	}
}

func TestWritesAreNotRetried(t *testing.T) {
	srv, c := startFlaky(t, 1)
	_, err := c.API.CreatePermission(context.Background(), &pb.CreatePermissionRequest{ProjectName: "default", Name: "doc.read"})
	if status.Code(err) != codes.Unavailable || srv.calls["create"] != 1 {
		t.Fatalf("err = %v after %d calls, want Unavailable after 1", err, srv.calls["create"])
	}
}

func TestAddError(t *testing.T) {
	var diags diag.Diagnostics
	AddError(&diags, "Unable to create role", status.Error(codes.PermissionDenied, "missing permissions"), "extra hint")
	if !diags.HasError() {
		t.Fatal("expected an error diagnostic")
	}
	detail := diags.Errors()[0].Detail()
	for _, want := range []string{"full-access API key", "missing permissions", "extra hint"} {
		if !strings.Contains(detail, want) {
			t.Errorf("detail %q does not contain %q", detail, want)
		}
	}
}

func TestBatches(t *testing.T) {
	items := make([]string, 250)
	got := batches(items, 100)
	if len(got) != 3 || len(got[0]) != 100 || len(got[2]) != 50 {
		t.Fatalf("batches = %d groups", len(got))
	}
	if batches(nil, 100) != nil {
		t.Fatal("expected no batches for no items")
	}
}
