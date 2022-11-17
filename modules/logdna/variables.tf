##############################################################################
# Account Variables
##############################################################################

variable "plan" {
  description = "Type of service plan. See https://cloud.ibm.com/catalog/services/logdna for current plan definitions."
  type        = string
  validation {
    condition     = contains(["lite", "7-day", "14-day", "30-day", "hipaa"], var.plan)
    error_message = "Must provide a valid logdna plan."
  }
}

variable "default_receiver" {
  description = "Flag to select the instance to collect platform logs"
  type        = bool
  default     = false
}

variable "location" {
  description = "Region where LogDNA will be provisioned"
  type        = string
  validation {
    error_message = "Must use an IBM Cloud region. Use `ibmcloud regions` with the IBM Cloud CLI to see valid regions."
    condition = contains([
      "au-syd",
      "jp-tok",
      "eu-de",
      "eu-gb",
      "us-south",
      "us-east",
      "ca-tor",
      "jp-osa",
      "br-sao"
    ], var.location)
  }
}

variable "tags" {
  description = "Tags set for LogDNA instance"
  type        = list(string)
  default     = ["logging", "public"]
}

variable "name" {
  description = "Name of the resource instance"
  type        = string
}

variable "resource_group_name" {
  description = "Name of the resource group associated with the instance"
  type        = string
  validation {
    condition     = length(var.resource_group_name) <= 40 && can(regex("^[a-zA-Z0-9-_ ]+$", var.resource_group_name))
    error_message = "Use alphanumeric characters along with hyphens and underscores only."
  }
}
