terraform {
  required_providers {
    permio = {
      source = "perms-io/permio"
    }
  }
}

# The API key is best supplied through the PERMIO_API_KEY environment variable.
provider "permio" {
  # api_key = "perms_..." # or PERMIO_API_KEY
  project = "default" # or PERMIO_PROJECT
}
