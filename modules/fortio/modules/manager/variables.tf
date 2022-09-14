##############################################################################
# Account Variables
##############################################################################

variable "ibmcloud_api_key" {
  description = "The IBM Cloud platform API key needed to deploy IAM enabled resources"
  type        = string
  sensitive   = true
}

variable "region" {
  description = "IBM Cloud region where the volume worker manager will be created, must be in a valid IBM Cloud Functions region"
  type        = string

  validation {
    error_message = "Must use an IBM Cloud region compatible with IBM Cloud Functions."
    condition = can(
      contains([
        "au-syd",
        "jp-tok",
        "eu-de",
        "eu-gb",
        "us-south",
        "us-east"
      ], var.region)
    )
  }
}

variable "worker_region" {
  description = "IBM Cloud region where the volume worker was created"
  type        = string

  validation {
    error_message = "Must use an IBM Cloud VPC region. Use `ibmcloud is regions` with the IBM Cloud CLI to see valid regions."
    condition = can(
      contains([
        "au-syd",
        "br-sao",
        "ca-tor",
        "eu-de",
        "eu-gb",
        "jp-osa",
        "jp-tok",
        "us-east",
        "us-south"
      ], var.worker_region)
    )
  }
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
  default     = "daas-vol-worker"
  type        = string
}

variable "resource_group_id" {
  description = "The resource group for the manager to use"
  type        = string
}

variable "redis_url" {
  description = "The redis url for the manager to send jobs to"
  sensitive   = true
  type        = string
}

variable "redis_certbase64" {
  description = "CA Cert for Redis"
  sensitive   = true
  type        = string
}

variable "subnet_ids" {
  description = "A list of subnet ids by zone for the manager to create workers in"
  type        = list(object({ zone = string, id = string }))
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
}

variable "logdna_ingestion_key" {
  description = "LogDNA ingestion key.. If set, worker logs are sent to IBM Log Analysis. Manager logs are always forwarded to the regional Log Analysis instance enabled to receive platform logs."
  type        = string
  default     = ""
  sensitive   = true
}
