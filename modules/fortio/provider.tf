##############################################################################
# Terraform Providers
##############################################################################

terraform {
  required_providers {
    ibm = {
      source                = "IBM-Cloud/ibm"
      version               = "1.47.0"
      configuration_aliases = [ibm.manager]
    }
    random = {
      source  = "hashicorp/random"
      version = "3.3.2"
    }
  }
  required_version = ">= 1.0.0"
}
