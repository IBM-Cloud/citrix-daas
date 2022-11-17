#############################################################################
# © Copyright IBM Corp. 2021, 2021

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

#     http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#############################################################################

##############################################################################
# Account Variables
##############################################################################

variable "ibmcloud_api_key" {
  description = "The IBM Cloud platform API key needed to deploy IAM enabled resources"
  type        = string
  sensitive   = true
}

variable "ibmcloud_account_id" {
  description = "The IBM Cloud account id needed to create a hosting connection from Citrix."
  type        = string
  validation {
    condition     = length(var.ibmcloud_account_id) == 32
    error_message = "Length of IBM Cloud account ID should be 32 characters."
  }
}

variable "ibmcloud_ssh_key_name" {
  description = "The IBM Cloud platform SSH key name used to deploy Citrix DaaS instances"
  type        = string
  validation {
    condition     = can(regex("^[a-z0-9-]{1,}$", var.ibmcloud_ssh_key_name))
    error_message = "Use lowercase alphanumeric characters and hyphens only (without spaces)."
  }
}

variable "resource_group" {
  description = "The IBM resource group name to be associated with this IBM Cloud VPC Citrix DaaS deployment"
  type        = string
  validation {
    condition     = length(var.resource_group) <= 40 && can(regex("^[a-zA-Z0-9-_ ]+$", var.resource_group))
    error_message = "Use alphanumeric characters along with hyphens and underscores only."
  }
}

variable "personal_access_token" {
  description = "Personal access token, Internal IBM use only"
  type        = string
  sensitive   = true
  default     = ""
}

variable "logdna_name" {
  description = "Name for LogDNA Instance. Random name will be generated if not set."
  type        = string
  default     = ""
}

variable "logdna_integration" {
  description = "Set to false if LogDNA not needed, only recommend disabling for non-production environments."
  type        = bool
  default     = false
}

variable "logdna_ingestion_key" {
  description = "Provide existing LogDNA instance ingestion key. If not set, a new instance of LogDNA will be created when `logdna_integration` is true."
  type        = string
  default     = ""
  sensitive   = true
  validation {
    condition = can(try(
      regex("^$", var.logdna_ingestion_key),
      regex("^[[:alnum:]]{32}$", var.logdna_ingestion_key)
    ))
    error_message = "If provided, ingestion key should be 32 lower alphanumeric characters in length."
  }
}

variable "logdna_plan" {
  description = "Service plan used for new LogDNA instance."
  type        = string
  default     = "7-day"
  validation {
    condition     = contains(["lite", "7-day", "14-day", "30-day", "hipaa"], var.logdna_plan)
    error_message = "Must provide a valid logdna plan."
  }
}

variable "logdna_enable_platform" {
  description = "Enables logging for the volume worker manager on LogDNA instance. Only one instance of LogDNA per region can be enabled for platform logs. See [Cloud Docs](https://cloud.ibm.com/docs/cvad?topic=cvad-post-provisioning-cvad-vpc#cvad-post-prov-vpc-logging)"
  type        = bool
  default     = false
}

variable "logdna_tags" {
  description = "Tags for new LogDNA instance."
  type        = list(string)
  default     = ["daas", "logging"]
}

variable "citrix_customer_id" {
  description = "The Citrix Cloud customer id needed to connect to Citrix"
  type        = string
}

variable "citrix_api_key_client_id" {
  description = "The Citrix Cloud API key client id needed to connect to Citrix"
  type        = string
}

variable "citrix_api_key_client_secret" {
  description = "The Citrix Cloud API key client secret needed to connect to Citrix"
  type        = string
  sensitive   = true
}

variable "resource_location_names" {
  description = "The Citrix resource location name to be associated with this IBM Cloud VPC Citrix DaaS deployment"
  type        = list(string)
  validation {
    condition     = length(var.resource_location_names) >= 1
    error_message = "There should at be least one resource location name specified."
  }
}

variable "region" {
  description = "IBM Cloud region where all resources will be deployed"
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
    ], var.region)
  }
}

variable "zones" {
  type        = list(string)
  description = "IBM Cloud zone name within the selected region where the Citrix DaaS infrastructure should be deployed. [Learn more](https://cloud.ibm.com/docs/vpc?topic=vpc-creating-a-vpc-in-a-different-region#get-zones-using-the-cli)"

  validation {
    condition     = length(var.zones) >= 1
    error_message = "There should be at least one zone specified."
  }
}

variable "address_prefix_cidrs" {
  type        = list(string)
  description = "Address prefixes to create in the VPC"
  default     = []
}

variable "subnet_cidrs" {
  type        = list(string)
  description = "Subnet cidrs to use in each zone, required when using `address_prefix_cidrs`"
  default     = []
}

variable "subnet_ipv4_count" {
  type        = number
  description = "Count of ipv4 address in each zone, ignored when using `address_prefix_cidrs`"
  default     = 256
  validation {
    condition     = can(regex("^8$|^16$|^32$|^64$|^128$|^256$|^512$|^1024$|^2048$|^4096$|^8192$|^16384$", var.subnet_ipv4_count))
    error_message = "Please enter the valid IPV4 address count for the subnet."
  }
}

variable "connector_per_zone" {
  type        = number
  description = "Number of connector instances per zone"
  default     = 2
  validation {
    condition     = var.connector_per_zone >= 1 && var.connector_per_zone <= 5
    error_message = "Depth must be between 1 and 5."
  }
}

variable "basename" {
  description = "Basename of the created resource"
  type        = string
  default     = "daas"
}

variable "active_directory_domain_name" {
  description = "Active Directory domain name"
  type        = string
}

variable "active_directory_vsi_name" {
  description = "Appended name of the created VSI"
  type        = string
  default     = "ad"
}

variable "active_directory_safe_mode_password" {
  description = "Safe mode password for the Active Directory administrator account. [Learn more for password complexity](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/password-must-meet-complexity-requirements)"
  type        = string
  sensitive   = true
  validation {
    condition = can(regex(
      "[A-Za-z0-9~!@#$%^&*_\\-+=`|\\(){}[\\]:;\"'<>,.?\\/]{8,}",
      var.active_directory_safe_mode_password
      )) && can(regex(
      "[[:upper:]]+",
      var.active_directory_safe_mode_password
      )) && can(regex(
      "[[:lower:]]+",
      var.active_directory_safe_mode_password
      )) && can(regex(
      "[[:digit:]]+",
      var.active_directory_safe_mode_password
      )) && can(regex(
      "[~!@#$%^&*_\\-+=`|\\(){}[\\]:;\"'<>,.?\\/]+",
      var.active_directory_safe_mode_password
    ))
    error_message = "Active Directory Safe Mode Password must be minimum eight characters, at least one uppercase letter, one lowercase letter, one number and one special character."
  }
}

variable "active_directory_topology" {
  description = "There are two topologies named IBM Cloud and Extended supported currently"
  type        = string
  default     = "IBM Cloud"

  validation {
    error_message = "IBM Cloud and Extended are the only supported Active Directory topologies."
    condition     = contains(["IBM Cloud", "Extended"], var.active_directory_topology)
  }
}

variable "deploy_custom_image_vsi" {
  description = "Deploy VSI for creating a custom image to be used for master image when set to true"
  type        = bool
  default     = false
}

variable "deploy_custom_image_fip" {
  description = "Deploy Floating IP to be used with custom image VSI when set to true"
  type        = bool
  default     = false
}

variable "control_plane_profile" {
  description = "Profile to use for creating Active Directory and Cloud Connector VSIs"
  type        = string
  default     = "cx2-4x8"
}

variable "custom_image_vsi_profile" {
  description = "Profile to use for creating custom image VSI"
  type        = string
  default     = "cx2-4x8"
}

variable "custom_image_vsi_image_name" {
  description = "Provide image name to be used for creating custom image VSI."
  type        = string
  default     = "ibm-windows-server-2022-full-standard-amd64-4"
}

variable "plugin_download_url" {
  description = "Deprecated, use `repository_download_url`"
  type        = string
  default     = ""
}

variable "repository_download_url" {
  description = "Used by Cloud Connector setup to download IBM Cloud VPC plugin."
  type        = string
  default     = "https://api.github.com/repos/IBM-Cloud/citrix-daas"
}

variable "repository_reference" {
  description = "Reference of repository at which to download"
  type        = string
  default     = "master"
}

variable "deploy_volume_worker" {
  description = "Enable the volume worker, uses FaaS to create workers for disk creation"
  type        = bool
  default     = false
}

variable "vda_security_group_name" {
  description = "Name for security group created for VDAs"
  type        = string
  default     = "vda-sg"
}

locals {
  repository_download_url = var.plugin_download_url != "" ? var.plugin_download_url : var.repository_download_url
}

variable "dedicated_host_per_zone" {
  type        = number
  description = "Number of dedicated hosts per zone. VDAs for these resource locations will be provisioned to dedicated hosts. Please ensure your VPC vCPU qouta is sufficient. All dedicated host vCPU will count against regional qouta, even while not allocated by VDAs."
  default     = 0
}

variable "dedicated_host_profile" {
  type        = string
  description = "Profile used for each 'dedicated_host_per_zone'. The dedicated host profile family must match the family to be used by VDAs. Dedicated hosts with instance storage are not supported at this time."
  default     = ""
}

variable "dedicated_control_plane" {
  type        = bool
  description = "Provision control plane virtual server instances (active directory, cloud connector, custom image) on dedicated host groups provisioned with `dedicated_host_per_zone` and `dedicated_host_profile`. Requires `custom_image_vsi_profile` and `control_plane_profile` to use the same profile family and class as `dedicated_host_profile`."
  default     = false
}

variable "accept_license" {
  type        = bool
  description = "Must be set true to accept IBM Cloud VPC Plugin for Citrix Virtual Apps and Desktop license agreement. [Learn more](https://www-40.ibm.com/software/sla/sladb.nsf/displayLIs/296A608D9ACE1F7900258832004E90A0?OpenDocument). You are accepting [License](https://www-40.ibm.com/software/sla/sladb.nsf/displayLIs/339A16A1DEC937F70025886A00497C8E?OpenDocument) if deploying volume worker."
  default     = false
  validation {
    condition     = var.accept_license
    error_message = "You must set the accept_license variable to true when deploying Citrix DaaS."
  }
}

locals {
  dedicated_host_family_map = {
    "cx2" = "compute"
    "mx2" = "memory"
    "bx2" = "balanced"
  }
  dedicated_host_class  = substr(var.dedicated_host_profile, 0, 3)
  dedicated_host_family = lookup(local.dedicated_host_family_map, local.dedicated_host_class, "")
}

variable "sites" {
  type        = list(string)
  description = "Site names to be used for active directory servers of different zones"
  default     = []
}

variable "boot_volume_capacity" {
  type        = number
  description = "Boot volume capacity for custom image and the instances created through Citrix Machine Creation Services."
  default     = 100
  validation {
    condition     = var.boot_volume_capacity >= 100 && var.boot_volume_capacity <= 250
    error_message = "Boot volume capacity must be between 100 and 250, inclusive."
  }
}

variable "identity_volume_encryption_crn" {
  type        = string
  description = "Identity volume encryption key crn to encrypt the identity disk."
  default     = ""
}
