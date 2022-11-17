##############################################################################
# Terraform Providers
##############################################################################

terraform {
  required_providers {
    ibm = {
      source  = "IBM-Cloud/ibm"
      version = "1.47.0"
    }
    null = {
      source  = "hashicorp/null"
      version = "3.1.1"
    }
  }
  required_version = ">= 1.0.0"
}
