terraform {
  required_providers {
    permio = {
      source = "perms-io/permio"
    }
  }
}

# The API key is best supplied through the PERMIO_API_KEY environment variable.
provider "permio" {
  # api_key = "perms_..."            # or PERMIO_API_KEY
  # api_url = "dev-api.perms.io:443" # or PERMIO_API_URL; defaults to production
  project = "default" # or PERMIO_PROJECT
}
