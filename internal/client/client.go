// Package client is a small gRPC client for the Permio PermissionsService. It handles the connection, API key
// authentication, retries of read-only calls on transient failures, pagination and the mapping of API errors to
// Terraform diagnostics.
package client

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	permissionsv1 "github.com/PrivateJAR/permio-go/proto/permissions/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

const (
	// DefaultEndpoint is the production Permio API.
	DefaultEndpoint = "temp-api.perms.io:443"
	// DefaultProject is the project that every Permio organisation starts with.
	DefaultProject = "default"

	defaultCallTimeout = 60 * time.Second
)

// Config configures a Client.
type Config struct {
	// APIKey is the Permio API key ("perms_...") sent as a bearer token.
	APIKey string
	// Endpoint is the API address. It may be "host:port", "https://host[:port]", or "http://host:port" for a
	// plaintext connection to a local development server. Any other gRPC target (such as "passthrough:///name")
	// is passed through unchanged.
	Endpoint string
	// UserAgent is prepended to the gRPC user agent.
	UserAgent string
	// Insecure forces a plaintext connection.
	Insecure bool
	// DialOptions are appended to the dial options (used by tests to dial an in-process server).
	DialOptions []grpc.DialOption
	// MaxRetries is the number of times a read-only call is retried after an Unavailable error. Zero means the
	// default (4); a negative value disables retries.
	MaxRetries int
	// RetryBaseDelay is the delay before the first retry; later retries back off exponentially. Zero means 250ms.
	RetryBaseDelay time.Duration
}

// Client is a connection to the Permio API.
type Client struct {
	conn *grpc.ClientConn
	// API is the generated PermissionsService client. Calls through it are authenticated and, for read-only RPCs,
	// retried on transient errors.
	API permissionsv1.PermissionsServiceClient
}

// New creates a client. It does not block on connecting: the connection is established on the first call.
func New(cfg Config) (*Client, error) {
	if strings.TrimSpace(cfg.APIKey) == "" {
		return nil, errors.New("an API key is required")
	}
	target, plaintext, err := parseEndpoint(cfg.Endpoint)
	if err != nil {
		return nil, err
	}
	plaintext = plaintext || cfg.Insecure

	var transport credentials.TransportCredentials
	if plaintext {
		transport = insecure.NewCredentials()
	} else {
		transport = credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12})
	}

	retries := cfg.MaxRetries
	if retries == 0 {
		retries = 4
	}
	if retries < 0 {
		retries = 0
	}
	baseDelay := cfg.RetryBaseDelay
	if baseDelay == 0 {
		baseDelay = 250 * time.Millisecond
	}

	opts := []grpc.DialOption{
		grpc.WithTransportCredentials(transport),
		grpc.WithPerRPCCredentials(bearerToken{token: cfg.APIKey, requireTLS: !plaintext}),
		grpc.WithChainUnaryInterceptor(
			timeoutInterceptor(defaultCallTimeout),
			retryInterceptor(retries, baseDelay),
		),
	}
	if cfg.UserAgent != "" {
		opts = append(opts, grpc.WithUserAgent(cfg.UserAgent))
	}
	opts = append(opts, cfg.DialOptions...)

	conn, err := grpc.NewClient(target, opts...)
	if err != nil {
		return nil, fmt.Errorf("creating gRPC client for %q: %w", target, err)
	}
	return &Client{conn: conn, API: permissionsv1.NewPermissionsServiceClient(conn)}, nil
}

// Close closes the connection.
func (c *Client) Close() error {
	if c == nil || c.conn == nil {
		return nil
	}
	return c.conn.Close()
}

// parseEndpoint turns the configured API URL into a gRPC target and reports whether it asks for plaintext.
func parseEndpoint(endpoint string) (target string, plaintext bool, err error) {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		endpoint = DefaultEndpoint
	}
	switch {
	case strings.HasPrefix(endpoint, "https://"):
		endpoint = strings.TrimPrefix(endpoint, "https://")
	case strings.HasPrefix(endpoint, "http://"):
		endpoint = strings.TrimPrefix(endpoint, "http://")
		plaintext = true
	case strings.Contains(endpoint, "://"):
		// Another gRPC resolver scheme (dns:///, passthrough:///, unix://): use it as is.
		return endpoint, false, nil
	}
	endpoint = strings.TrimSuffix(endpoint, "/")
	if strings.Contains(endpoint, "/") {
		return "", false, fmt.Errorf("invalid API URL %q: expected host[:port]", endpoint)
	}
	if _, _, splitErr := net.SplitHostPort(endpoint); splitErr != nil {
		if plaintext {
			endpoint = net.JoinHostPort(endpoint, "80")
		} else {
			endpoint = net.JoinHostPort(endpoint, "443")
		}
	}
	return endpoint, plaintext, nil
}

// bearerToken sends "authorization: Bearer <token>" with every call.
type bearerToken struct {
	token      string
	requireTLS bool
}

func (b bearerToken) GetRequestMetadata(context.Context, ...string) (map[string]string, error) {
	return map[string]string{"authorization": "Bearer " + b.token}, nil
}

func (b bearerToken) RequireTransportSecurity() bool { return b.requireTLS }

// timeoutInterceptor gives calls without a deadline a default one, so a hung connection cannot stall Terraform
// forever.
func timeoutInterceptor(d time.Duration) grpc.UnaryClientInterceptor {
	return func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		if _, ok := ctx.Deadline(); !ok {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, d)
			defer cancel()
		}
		return invoker(ctx, method, req, reply, cc, opts...)
	}
}
