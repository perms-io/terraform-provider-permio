package main

import (
	"context"
	"flag"
	"log"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"

	"github.com/perms-io/terraform-provider-permio/internal/provider"
)

// Generate the Registry documentation in docs/ from the provider schema, examples/ and templates/.
//go:generate go tool tfplugindocs generate --provider-name permio

// version is set by GoReleaser at build time.
var version = "dev"

func main() {
	var debug bool
	flag.BoolVar(&debug, "debug", false, "run the provider with support for debuggers like delve")
	flag.Parse()

	err := providerserver.Serve(context.Background(), provider.New(version), providerserver.ServeOpts{
		Address: "registry.terraform.io/privatejar/permio",
		Debug:   debug,
	})
	if err != nil {
		log.Fatal(err)
	}
}
