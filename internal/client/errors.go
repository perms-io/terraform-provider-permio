package client

import (
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// IsNotFound reports whether err is a gRPC NotFound error.
func IsNotFound(err error) bool { return status.Code(err) == codes.NotFound }

// IsAlreadyExists reports whether err is a gRPC AlreadyExists error.
func IsAlreadyExists(err error) bool { return status.Code(err) == codes.AlreadyExists }

// Code returns the gRPC code of err.
func Code(err error) codes.Code { return status.Code(err) }

// Describe turns an API error into a human-readable explanation for a diagnostic's detail.
func Describe(err error) string {
	st, ok := status.FromError(err)
	if !ok {
		return err.Error()
	}
	msg := st.Message()
	switch st.Code() {
	case codes.Unauthenticated:
		return fmt.Sprintf("The Permio API did not accept the API key (%s). Check the provider's api_key argument or the PERMIO_API_KEY environment variable, and that api_url points at the environment the key was issued for.", msg)
	case codes.PermissionDenied:
		return fmt.Sprintf("The API key is not allowed to do this (%s). Creating, changing or deleting permissions, roles, groups and grants needs a full-access API key; check-only keys can only read. API keys are scoped to a single project, so also check that the project matches the key's project.", msg)
	case codes.InvalidArgument:
		return fmt.Sprintf("The Permio API rejected the request as invalid: %s", msg)
	case codes.NotFound:
		return fmt.Sprintf("Not found: %s", msg)
	case codes.AlreadyExists:
		return fmt.Sprintf("Already exists: %s", msg)
	case codes.Unavailable:
		return fmt.Sprintf("The Permio API is unavailable (%s). Retry later, and check api_url.", msg)
	case codes.DeadlineExceeded:
		return fmt.Sprintf("The request to the Permio API timed out (%s).", msg)
	case codes.Canceled:
		return fmt.Sprintf("The request was cancelled (%s).", msg)
	case codes.Internal:
		return fmt.Sprintf("The Permio API returned an internal error: %s", msg)
	default:
		return fmt.Sprintf("%s: %s", st.Code(), msg)
	}
}

// AddError appends an error diagnostic for an API error. hint, if not empty, is appended to the detail.
func AddError(diags *diag.Diagnostics, summary string, err error, hint ...string) {
	detail := Describe(err)
	for _, h := range hint {
		if h != "" {
			detail += "\n\n" + h
		}
	}
	diags.AddError(summary, detail)
}
