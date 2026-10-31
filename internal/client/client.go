// Package client connects the provider to the Permio PermissionsService through the public Go SDK
// (github.com/perms-io/permio-go), which handles API key validation and authentication, per-attempt timeouts and
// retries of read-only calls. This package adds the provider's endpoint handling, pagination helpers and the mapping
// of API errors to Terraform diagnostics.
package client

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	permio "github.com/perms-io/permio-go"
	permissionsv1 "github.com/perms-io/permio-go/proto/permissions/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

const (
	// DefaultEndpoint is the production Permio API.
	DefaultEndpoint = "api.perms.io:443"
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
	// MaxRetries is the number of times a read-only call is retried after an Unavailable or DeadlineExceeded error
	// (or a rate limit with a short server-given delay). Zero means the default (4); a negative value disables
	// retries.
	MaxRetries int
	// RetryBaseDelay is the delay before the first retry; later retries back off exponentially. Zero means 250ms.
	RetryBaseDelay time.Duration
}

// Client is a connection to the Permio API.
type Client struct {
	conn *grpc.ClientConn
	// SDK is the Permio Go SDK client wrapping the connection. It has no default project: the provider passes the
	// project on every request.
	SDK *permio.Client
	// API is the generated PermissionsService client. Calls through it are authenticated and, for read-only RPCs,
	// retried on transient errors. Errors are *permio.Error values, which status.Code and status.FromError read.
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

	if cfg.MaxRetries == 0 {
		cfg.MaxRetries = 4
	}
	if cfg.RetryBaseDelay == 0 {
		cfg.RetryBaseDelay = 250 * time.Millisecond
	}
	// Checked here so a malformed key fails before the connection is created.
	if _, err := permio.ValidateAPIKey(cfg.APIKey); err != nil {
		return nil, errors.New(strings.TrimPrefix(err.Error(), "permio: "))
	}

	// The provider dials itself so that api_url can also be any gRPC target (passthrough:///, unix://, ...); the
	// SDK then adds authentication, timeouts and retries on top of the connection.
	opts := []grpc.DialOption{grpc.WithTransportCredentials(transport)}
	if cfg.UserAgent != "" {
		opts = append(opts, grpc.WithUserAgent(cfg.UserAgent))
	}
	opts = append(opts, cfg.DialOptions...)

	conn, err := grpc.NewClient(target, opts...)
	if err != nil {
		return nil, fmt.Errorf("creating gRPC client for %q: %w", target, err)
	}
	sdk, err := permio.New(permio.Options{
		APIKey:  cfg.APIKey,
		Conn:    conn,
		Timeout: defaultCallTimeout,
		Retry:   permio.RetryOptions{MaxRetries: cfg.MaxRetries, BaseDelay: cfg.RetryBaseDelay, MaxDelay: 5 * time.Second},
	})
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return &Client{conn: conn, SDK: sdk, API: sdk.Permissions()}, nil
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
