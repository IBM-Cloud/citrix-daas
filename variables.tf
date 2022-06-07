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
}

variable "ibmcloud_ssh_key_name" {
    description = "The IBM Cloud platform SSH key name used to deploy CVAD instances"
    type        = string
}

variable "resource_group" {
    description = "The IBM resource group name to be associated with this IBM Cloud VPC CVAD deployment"
    type        = string
}

variable "personal_access_token" {
    description = "Personal access token used to get plugin installer from ghe."
    type        = string
    sensitive   = true
    default     = ""
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
    description = "The Citrix resource location name to be associated with this IBM Cloud VPC CVAD deployment"
    type        = list(string)
    validation {
        condition = length(var.resource_location_names) >= 1
        error_message = "There should at be least one resource location name specified."
    }
}

variable "region" {
    description = "IBM Cloud region where all resources will be deployed"
    type        = string

    validation  {
      error_message = "Must use an IBM Cloud region. Use `ibmcloud regions` with the IBM Cloud CLI to see valid regions."
      condition     = contains([
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
    description = "IBM Cloud zone name within the selected region where the CVAD infrastructure should be deployed. [Learn more](https://cloud.ibm.com/docs/vpc?topic=vpc-creating-a-vpc-in-a-different-region#get-zones-using-the-cli)"

    validation {
        condition = length(var.zones) >= 1
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
    description = "Subnet cidrs to use in each zone, requred when using `address_prefix_cidrs`"
    default     = []
}

variable "subnet_ipv4_count" {
    type        = number
    description = "Count of ipv4 address in each zone, ignored when using `address_prefix_cidrs`"
    default     = 256
}

variable "connector_per_zone" {
    type        = number
    description = "Number of connector instances per zone"
    default     = 2
    validation {
      condition     = var.connector_per_zone >= 1 && var.connector_per_zone <=5
      error_message = "Depth must be between 1 and 5."
    }
}

variable "basename" {
    description = "Basename of the created resource"
    type        = string
    default     = "cvad"
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
    description = "Safe mode password for the Active Directory administrator account."
    type        = string
    sensitive   = true
}

variable "active_directory_topology" {
    description = "There are two topologies named IBM Cloud and Extended supported currently"
    type        = string
    default     = "IBM Cloud"

    validation  {
      error_message = "IBM Cloud and Extended are the only supported Active Directory topologies."
      condition     = contains(["IBM Cloud", "Extended"], var.active_directory_topology)
    }
}

variable "deploy_custom_image_vsi" {
    description = "Deploy VSI for creating a custom image to be used for master image when set to true"
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

variable "plugin_download_url" {
    description = "Scheduled for deprecated, use `repository_download_url`"
    type        = string
    default     = ""
}

variable "repository_download_url" {
    description = "Used by Cloud Connector setup to download IBM Cloud VPC plugin."
    type        = string
    default     = "https://api.github.com/repos/IBM-Cloud/citrix-virtual-apps-and-desktops"
}

variable "repository_reference" {
    description = "Reference of repository at which to download"
    type        = string
    default     = "master"
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

locals {
    dedicated_host_family_map = {
        "cx2" = "compute"
        "mx2" = "memory"
        "bx2" = "balanced"
    }
    dedicated_host_class = substr(var.dedicated_host_profile, 0, 3)
    dedicated_host_family = lookup(local.dedicated_host_family_map, local.dedicated_host_class, "")
}
