##############################################################################
# Account Variables
##############################################################################

variable ibmcloud_api_key {
    description = "The IBM Cloud platform API key needed to deploy IAM enabled resources"
    type        = string
    sensitive   = true
}

variable region {
    description = "IBM Cloud VPC region where the volume worker will be created and used"
    type        = string

    validation  {
      error_message = "Must use an IBM Cloud VPC region. Use `ibmcloud is regions` with the IBM Cloud CLI to see valid regions."
      condition     = can(
        contains([
            "au-syd",
            "jp-tok",
            "eu-de",
            "eu-gb",
            "us-south",
            "us-east",
            "ca-tor",
            "jp-osa",
            "br-sao"
        ], var.region)
      )
    }
}

variable "manager_region" {
    description = "IBM Cloud region where the volume worker manager will be created, must be in a valid IBM Cloud Functions region"
    type        = string

    validation  {
      error_message = "Must use an IBM Cloud region compatible with IBM Cloud Functions."
      condition     = can(
        contains([
            "au-syd",
            "jp-tok",
            "eu-de",
            "eu-gb",
            "us-south",
            "us-east"
        ], var.manager_region)
      )
    }
}

variable "resource_group" {
    description = "The IBM resource group name to be associated with this IBM Cloud VPC CVAD deployment"
    type        = string
}

variable "max_worker_count" {
    description = "Max VSI workers"
    type        = number
    default     = 5
}

variable "iam_auth_endpoint" {
    description = "IAM Endpoint"
    type        = string
    default     = "https://iam.cloud.ibm.com/identity/token"
}

variable "github_pat" {
    description = "Personal access token, Internal IBM use only"
    default     = ""
    type        = string
    sensitive   = true
}

variable "resource_prefix" {
    description = "The prefix for resource names created for the volume worker"
    default     = "cvad-vol-worker"
    type        = string
}

variable "bucket_name" {
    description = "Name of COS bucket used for in/out jobs"
    type        = string
}

variable "repository_download_url" {
    description = "download URL of repository containing agent"
    type        = string
}

variable "repository_reference" {
    description = "Reference of repository at which to download"
    type        = string
}

variable "agent_repository_path" {
    description = "Location of agent in this repository"
    type        = string
    default     = "modules/fortio/agent.tar.gz"
}

variable "logdna_ingestion_key" {
    description = "LogDNA ingestion key. If set, worker logs are sent to IBM Log Analysis. Manager logs are always forwarded to the regional Log Analysis instance enabled to receive platform logs."
    type        = string
    default     = ""
    sensitive   = true
}
