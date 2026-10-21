package client

import (
	"context"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// isReadOnly reports whether a full gRPC method name is a read-only PermissionsService RPC, which is safe to retry.
func isReadOnly(fullMethod string) bool {
	name := fullMethod[strings.LastIndex(fullMethod, "/")+1:]
	switch {
	case strings.HasPrefix(name, "Get"), strings.HasPrefix(name, "List"):
		return true
	case name == "Check", name == "BatchCheck":
		return true
	}
	return false
}

// retryInterceptor retries read-only calls that fail with Unavailable, backing off exponentially. Mutating calls are
// never retried, because an Unavailable error does not say whether the server applied them.
func retryInterceptor(maxRetries int, baseDelay time.Duration) grpc.UnaryClientInterceptor {
	return func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		if !isReadOnly(method) {
			return invoker(ctx, method, req, reply, cc, opts...)
		}
		delay := baseDelay
		for attempt := 0; ; attempt++ {
			err := invoker(ctx, method, req, reply, cc, opts...)
			if err == nil || attempt >= maxRetries || status.Code(err) != codes.Unavailable {
				return err
			}
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return err
			case <-timer.C:
			}
			delay *= 2
			if delay > 5*time.Second {
				delay = 5 * time.Second
			}
		}
	}
}
