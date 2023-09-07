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

#############################################################################
# Terraform Main IaC
##############################################################################

# Generate random identifier
resource "random_string" "resource_identifier" {
  length  = 5
  upper   = false
  numeric = false
  lower   = true
  special = false
}

# Generate random Active Directory join password
resource "random_password" "ad_join_pwd" {
  length           = 16
  special          = true
  override_special = "_%@"
}

module "logdna" {
  count               = var.logdna_ingestion_key == "" && var.logdna_integration ? 1 : 0
  source              = "./modules/logdna"
  plan                = var.logdna_plan
  default_receiver    = var.logdna_enable_platform
  location            = var.region
  name                = var.logdna_name != "" ? var.logdna_name : format("%s-%s", random_string.resource_identifier.result, var.region)
  resource_group_name = var.resource_group
  tags                = var.logdna_tags
}

# Define local variables for Virtual Server creation and Active Directory Cloudbase-Init scripts
locals {
  ingestion_key     = var.logdna_ingestion_key == "" && var.logdna_integration ? module.logdna[0].ingestion_key : var.logdna_ingestion_key
  uuid              = random_string.resource_identifier.result
  connector_name    = "cc"
  connector_reg_num = 5
  common_tpl = templatefile("${path.module}/scripts/common.ps1", {
    "ingestion_key" = local.ingestion_key,
    "region"        = var.region,
  })
  standard_tpl = templatefile("${path.module}/scripts/ad-userdata.ps1", {
    "common_ps"           = local.common_tpl,
    "ad_name"             = "${var.basename}-${local.uuid}-${var.active_directory_vsi_name}",
    "ad_domain_name"      = var.active_directory_domain_name,
    "connector_name"      = local.connector_name,
    "connector_reg_num"   = local.connector_reg_num,
    "resource_identifier" = local.uuid,
    "topology"            = var.active_directory_topology,
    "zones"               = join(",", var.zones),
    "zone_index"          = 0,
    "subnets"             = join(",", [for s in ibm_is_subnet.subnets : s.ipv4_cidr_block])
    "ad_join_pwd"         = random_password.ad_join_pwd.result,
    "ad_safe_pwd"         = var.active_directory_safe_mode_password,
    }
  )
  secondary_zones = [
    for i, zone in var.zones :
    zone if i != 0
  ]
  secondary_sites = [
    for i, site in var.sites :
    site if i != 0
  ]
}

# Get resource group
data "ibm_resource_group" "citrix_daas" {
  name = var.resource_group
}

# Create VPC
resource "ibm_is_vpc" "vpc" {
  name                        = "${var.basename}-${local.uuid}-vpc"
  resource_group              = data.ibm_resource_group.citrix_daas.id
  default_security_group_name = var.vda_security_group_name
  address_prefix_management   = length(var.address_prefix_cidrs) != 0 ? "manual" : "auto"
}

resource "ibm_is_vpc_address_prefix" "prefixes" {
  count = length(var.address_prefix_cidrs)
  name  = format("%s-prefix-%d", ibm_is_vpc.vpc.name, count.index)
  zone  = var.zones[count.index]
  vpc   = ibm_is_vpc.vpc.id
  cidr  = var.address_prefix_cidrs[count.index]
}

# Create dedicated host group
resource "ibm_is_dedicated_host_group" "dh_group" {
  for_each       = var.dedicated_host_per_zone > 0 ? toset(var.zones) : []
  name           = format("%s-%s-host-group", var.basename, each.value)
  resource_group = data.ibm_resource_group.citrix_daas.id
  zone           = each.value
  family         = local.dedicated_host_family
  class          = local.dedicated_host_class
}

# Create dedicated hosts per zone
resource "ibm_is_dedicated_host" "host" {
  count          = var.dedicated_host_per_zone * length(var.zones)
  name           = format("%s-%s-host-%d", var.basename, var.zones[floor(count.index / var.dedicated_host_per_zone)], 1 + count.index % var.dedicated_host_per_zone)
  resource_group = data.ibm_resource_group.citrix_daas.id
  profile        = var.dedicated_host_profile
  host_group     = ibm_is_dedicated_host_group.dh_group[var.zones[floor(count.index / var.dedicated_host_per_zone)]].id
}

# Create one subnet per zone
resource "ibm_is_subnet" "subnets" {
  depends_on = [
    ibm_is_vpc_address_prefix.prefixes
  ]

  count                    = length(var.zones)
  name                     = "${var.basename}-subnet-${count.index + 1}"
  vpc                      = ibm_is_vpc.vpc.id
  zone                     = var.zones[count.index]
  total_ipv4_address_count = length(var.address_prefix_cidrs) == 0 ? var.subnet_ipv4_count : null
  ipv4_cidr_block          = length(var.address_prefix_cidrs) != 0 ? var.subnet_cidrs[count.index] : null
  resource_group           = data.ibm_resource_group.citrix_daas.id
  public_gateway           = ibm_is_public_gateway.gateway[count.index].id
}

# Create security groups
resource "ibm_is_security_group" "master_prep_sg" {
  name           = "master-prep-sg"
  vpc            = ibm_is_vpc.vpc.id
  resource_group = data.ibm_resource_group.citrix_daas.id
}

resource "ibm_is_security_group" "master_prep_rhel_sg" {
  name           = "master-prep-rhel-sg"
  vpc            = ibm_is_vpc.vpc.id
  resource_group = data.ibm_resource_group.citrix_daas.id
}

resource "ibm_is_security_group" "active_directory_sg" {
  name           = "active-directory-sg"
  vpc            = ibm_is_vpc.vpc.id
  resource_group = data.ibm_resource_group.citrix_daas.id
}

resource "ibm_is_security_group" "connector_sg" {
  name           = "connector-sg"
  vpc            = ibm_is_vpc.vpc.id
  resource_group = data.ibm_resource_group.citrix_daas.id
}

resource "ibm_is_security_group" "custom_image_sg" {
  count          = var.deploy_custom_image_vsi ? 1 : 0
  name           = "custom-image-sg"
  vpc            = ibm_is_vpc.vpc.id
  resource_group = data.ibm_resource_group.citrix_daas.id
}

# Create security group rules

# This will allow all outbound traffic from rhel master prep server for registration during cloud-init
resource "ibm_is_security_group_rule" "egress_master_prep_rhel_all" {
  group     = ibm_is_security_group.master_prep_rhel_sg.id
  direction = "outbound"
  remote    = "0.0.0.0/0"
}

# This inbound rule allows all traffic from connectors to active directory
resource "ibm_is_security_group_rule" "ingress_active_directory_from_connector_all" {
  group     = ibm_is_security_group.active_directory_sg.id
  direction = "inbound"
  remote    = ibm_is_security_group.connector_sg.id
}

# This inbound rule allows all traffic from vda[default_security_group] to active directory
resource "ibm_is_security_group_rule" "ingress_active_directory_from_vda_all" {
  group     = ibm_is_security_group.active_directory_sg.id
  direction = "inbound"
  remote    = ibm_is_vpc.vpc.default_security_group
}

# This allows tcp from custom image to active directory. It won't exist unless custom image is ordered
resource "ibm_is_security_group_rule" "ingress_active_directory_from_custom_image_tcp" {
  count     = var.deploy_custom_image_vsi ? 1 : 0
  group     = ibm_is_security_group.active_directory_sg.id
  direction = "inbound"
  remote    = ibm_is_security_group.custom_image_sg[count.index].id

  tcp {
    port_min = 53
    port_max = 53
  }
}

# This allows udp from custom image to active directory. It won't exist unless custom image is ordered
resource "ibm_is_security_group_rule" "ingress_active_directory_from_custom_image_udp" {
  count     = var.deploy_custom_image_vsi ? 1 : 0
  group     = ibm_is_security_group.active_directory_sg.id
  direction = "inbound"
  remote    = ibm_is_security_group.custom_image_sg[count.index].id

  udp {
    port_min = 53
    port_max = 53
  }
}

# This allows all traffic from an active directory in one zone to active directories in other zones
# It won't exist unless the number of zones provided by user are more than one
resource "ibm_is_security_group_rule" "ingress_active_directory_from_active_directory_all" {
  count     = length(local.secondary_zones) > 0 ? 1 : 0
  group     = ibm_is_security_group.active_directory_sg.id
  direction = "inbound"
  remote    = ibm_is_security_group.active_directory_sg.id
}

# This rule will allow all the outbound traffic from the active directory
resource "ibm_is_security_group_rule" "egress_active_directory_all" {
  group     = ibm_is_security_group.active_directory_sg.id
  direction = "outbound"
  remote    = "0.0.0.0/0"
}

# This inbound rule allows all traffic from vda[default_security_group] to connectors
resource "ibm_is_security_group_rule" "ingress_connector_from_vda_all" {
  group     = ibm_is_security_group.connector_sg.id
  direction = "inbound"
  remote    = ibm_is_vpc.vpc.default_security_group
}

# This inbound rule allows all traffic from active directory to connectors
resource "ibm_is_security_group_rule" "ingress_connector_from_active_directory_all" {
  group     = ibm_is_security_group.connector_sg.id
  direction = "inbound"
  remote    = ibm_is_security_group.active_directory_sg.id
}

# This inbound rule allows all traffic from a connector to other connectors
resource "ibm_is_security_group_rule" "ingress_connector_from_connector_all" {
  group     = ibm_is_security_group.connector_sg.id
  direction = "inbound"
  remote    = ibm_is_security_group.connector_sg.id
}

# This rule will allow all the outbound traffic from the connectors
resource "ibm_is_security_group_rule" "egress_connector_all" {
  group     = ibm_is_security_group.connector_sg.id
  direction = "outbound"
  remote    = "0.0.0.0/0"
}

# This inbound rule allows all traffic from connectors to vda[default_security_group]
resource "ibm_is_security_group_rule" "ingress_vda_from_connector_all" {
  group     = ibm_is_vpc.vpc.default_security_group
  direction = "inbound"
  remote    = ibm_is_security_group.connector_sg.id
}

# This inbound rule allows all traffic from active directory to vda[default_security_group]
resource "ibm_is_security_group_rule" "ingress_vda_from_active_directory_all" {
  group     = ibm_is_vpc.vpc.default_security_group
  direction = "inbound"
  remote    = ibm_is_security_group.active_directory_sg.id
}

# This will allow users to rdp to the custom image instance from anywhere
# It won't exist unless custom image instance is ordered
resource "ibm_is_security_group_rule" "ingress_custom_image_rdp" {
  count     = var.deploy_custom_image_vsi ? 1 : 0
  group     = ibm_is_security_group.custom_image_sg[count.index].id
  direction = "inbound"
  remote    = "0.0.0.0/0"

  tcp {
    port_min = 3389
    port_max = 3389
  }
}

# This will allow users to ssh to the custom image instance from anywhere
# It won't exist unless custom image instance is ordered
resource "ibm_is_security_group_rule" "ingress_custom_image_ssh" {
  count     = var.deploy_custom_image_vsi ? 1 : 0
  group     = ibm_is_security_group.custom_image_sg[count.index].id
  direction = "inbound"
  remote    = "0.0.0.0/0"

  tcp {
    port_min = 22
    port_max = 22
  }
}

# This will allow all outbound traffic from custom image instance
# It won't exist unless custom image instance is ordered
resource "ibm_is_security_group_rule" "egress_custom_image_all" {
  count     = var.deploy_custom_image_vsi ? 1 : 0
  group     = ibm_is_security_group.custom_image_sg[count.index].id
  direction = "outbound"
  remote    = "0.0.0.0/0"
}

# Get Windows image for Virtual Server creates
data "ibm_is_image" "windows" {
  name = "ibm-windows-server-2022-full-standard-amd64-4"
}

# Get SSH Key for Virtual Server creates
data "ibm_is_ssh_key" "ssh_key_id" {
  name = var.ibmcloud_ssh_key_name
}

# Create Virtual Server for primary Active Directory Domain Controller
resource "ibm_is_instance" "active_directory" {
  depends_on = [
    ibm_is_dedicated_host.host
  ]

  name                 = "${var.basename}-${local.uuid}-${var.active_directory_vsi_name}"
  vpc                  = ibm_is_vpc.vpc.id
  zone                 = var.zones[0]
  keys                 = [data.ibm_is_ssh_key.ssh_key_id.id]
  image                = data.ibm_is_image.windows.id
  profile              = var.control_plane_profile
  resource_group       = data.ibm_resource_group.citrix_daas.id
  dedicated_host_group = (var.dedicated_host_per_zone > 0 && var.dedicated_control_plane) ? ibm_is_dedicated_host_group.dh_group[var.zones[0]].id : null

  user_data = var.active_directory_topology == "Extended" ? templatefile("${path.module}/scripts/ad-extended.ps1", {
    "common_ps"           = local.common_tpl,
    "ad_domain_name"      = var.active_directory_domain_name,
    "connector_name"      = local.connector_name,
    "connector_reg_num"   = local.connector_reg_num,
    "resource_identifier" = local.uuid,
    "topology"            = var.active_directory_topology,
    "zones"               = join(",", var.zones),
    "zone_index"          = 0,
    "sites"               = join(",", var.sites),
    }
  ) : local.standard_tpl

  primary_network_interface {
    name            = "primary-nic"
    subnet          = ibm_is_subnet.subnets[0].id
    security_groups = [ibm_is_security_group.active_directory_sg.id]
  }
}

# Create Virtual Server(s) for secondary Active Directory Domain Controller(s)
resource "ibm_is_instance" "secondary_active_directory" {
  depends_on = [
    ibm_is_dedicated_host.host
  ]

  count                = length(local.secondary_zones) > 0 ? length(local.secondary_zones) : 0
  name                 = "${var.basename}-${local.uuid}-${var.active_directory_vsi_name}-${count.index + 1}"
  vpc                  = ibm_is_vpc.vpc.id
  zone                 = local.secondary_zones[count.index]
  keys                 = [data.ibm_is_ssh_key.ssh_key_id.id]
  image                = data.ibm_is_image.windows.id
  profile              = var.control_plane_profile
  resource_group       = data.ibm_resource_group.citrix_daas.id
  dedicated_host_group = (var.dedicated_host_per_zone > 0 && var.dedicated_control_plane) ? ibm_is_dedicated_host_group.dh_group[local.secondary_zones[count.index]].id : null

  user_data = var.active_directory_topology == "Extended" ? templatefile("${path.module}/scripts/ad-extended.ps1", {
    "common_ps"           = local.common_tpl,
    "ad_domain_name"      = var.active_directory_domain_name,
    "connector_name"      = local.connector_name,
    "connector_reg_num"   = local.connector_reg_num,
    "resource_identifier" = local.uuid,
    "topology"            = var.active_directory_topology,
    "zones"               = join(",", local.secondary_zones),
    "zone_index"          = count.index,
    "sites"               = join(",", local.secondary_sites),
    }
    ) : templatefile("${path.module}/scripts/secondary-ad-userdata.ps1", {
      "common_ps"      = local.common_tpl,
      "root_ad_name"   = ibm_is_instance.active_directory.name,
      "ad_domain_name" = var.active_directory_domain_name,
      "zones"          = join(",", local.secondary_zones),
      "topology"       = var.active_directory_topology,
      "zone_index"     = count.index,
      "root_ad_ip"     = ibm_is_instance.active_directory.primary_network_interface[0].primary_ip[0].address,
      "ad_join_pwd"    = random_password.ad_join_pwd.result,
      "ad_safe_pwd"    = var.active_directory_safe_mode_password,
    }
  )

  primary_network_interface {
    name            = "primary-nic"
    subnet          = ibm_is_subnet.subnets[count.index + 1].id
    security_groups = [ibm_is_security_group.active_directory_sg.id]
  }
}

# Create x number of Virtual Servers in y number of zones for Cloud Connector(s)
resource "ibm_is_instance" "connector" {
  depends_on = [
    ibm_is_dedicated_host.host
  ]

  count                = var.connector_per_zone * length(var.zones)
  name                 = "${local.connector_name}-${local.uuid}-${count.index + 1}"
  vpc                  = ibm_is_vpc.vpc.id
  zone                 = var.zones[floor(count.index / var.connector_per_zone)]
  keys                 = [data.ibm_is_ssh_key.ssh_key_id.id]
  image                = data.ibm_is_image.windows.id
  profile              = var.control_plane_profile
  resource_group       = data.ibm_resource_group.citrix_daas.id
  dedicated_host_group = (var.dedicated_host_per_zone > 0 && var.dedicated_control_plane) ? ibm_is_dedicated_host_group.dh_group[var.zones[floor(count.index / var.connector_per_zone)]].id : null

  user_data = templatefile("${path.module}/scripts/connector-userdata.ps1", {
    "common_ps"                      = local.common_tpl,
    "customer_id"                    = var.citrix_customer_id,
    "api_id"                         = var.citrix_api_key_client_id,
    "api_secret"                     = var.citrix_api_key_client_secret,
    "resource_location_name"         = var.resource_location_names[floor(count.index / var.connector_per_zone)],
    "ad_domain_name"                 = var.active_directory_domain_name,
    "ad_ip"                          = floor(count.index / var.connector_per_zone) == 0 ? ibm_is_instance.active_directory.primary_network_interface[0].primary_ip[0].address : ibm_is_instance.secondary_active_directory[floor(count.index / var.connector_per_zone) - 1].primary_network_interface[0].primary_ip[0].address,
    "ghe_token"                      = var.personal_access_token,
    "ibmcloud_account_id"            = var.ibmcloud_account_id,
    "vpc_id"                         = ibm_is_vpc.vpc.id,
    "resource_group_id"              = data.ibm_resource_group.citrix_daas.id,
    "region"                         = var.region,
    "zone"                           = var.zones[floor(count.index / var.connector_per_zone)],
    "master_prep_sg"                 = ibm_is_security_group.master_prep_sg.name,
    "master_prep_rhel_sg"            = ibm_is_security_group.master_prep_rhel_sg.name,
    "topology"                       = var.active_directory_topology,
    "ad_join_pwd"                    = random_password.ad_join_pwd.result,
    "repository_download_url"        = local.repository_download_url,
    "tag"                            = var.repository_reference,
    "vda_sg"                         = var.vda_security_group_name,
    "dedicated_host_group_id"        = var.dedicated_host_per_zone > 0 ? ibm_is_dedicated_host_group.dh_group[var.zones[floor(count.index / var.connector_per_zone)]].id : "",
    "cos_bucket_name"                = local.fortio_bucket_name,
    "cos_region_name"                = local.fortio_manager_region,
    "identity_volume_encryption_crn" = var.identity_volume_encryption_crn,
    "use_volume_worker"              = var.deploy_volume_worker ? 1 : 0
    }
  )

  primary_network_interface {
    name            = "primary-nic"
    subnet          = ibm_is_subnet.subnets[floor(count.index / var.connector_per_zone)].id
    security_groups = [ibm_is_security_group.connector_sg.id]
  }
}

# Get image for Custom Image Instance creation
data "ibm_is_image" "custom_image" {
  count = length(var.custom_image_instances)
  name  = var.custom_image_vsi_image_name != null ? var.custom_image_vsi_image_name : var.custom_image_instances[count.index].custom_image_vsi_image_name
}

locals {
  ad_ip = ibm_is_instance.active_directory.primary_network_interface[0].primary_ip[0].address
  ps_script = "${path.module}/scripts/custom-image-userdata.ps1"
  rhel_script = "${path.module}/scripts/custom-image-userdata.sh"
}

# Create Virtual Server for custom VDA image creation
resource "ibm_is_instance" "custom_image_instance" {
  depends_on = [
    ibm_is_dedicated_host.host
  ]

  count                = var.deploy_custom_image_vsi ? length(var.custom_image_instances) : 0
  name                 = length(var.custom_image_instances) > 1 ? "cstm-img${local.uuid}${count.index + 1}" : "cstm-img-${local.uuid}"
  vpc                  = ibm_is_vpc.vpc.id
  zone                 = var.zones[0]
  keys                 = [data.ibm_is_ssh_key.ssh_key_id.id]
  image                = data.ibm_is_image.custom_image[count.index].id
  profile              = var.custom_image_vsi_profile != null ? var.custom_image_vsi_profile : var.custom_image_instances[count.index].custom_image_vsi_profile
  resource_group       = data.ibm_resource_group.citrix_daas.id
  dedicated_host_group = (var.dedicated_host_per_zone > 0 && var.dedicated_control_plane) ? ibm_is_dedicated_host_group.dh_group[var.zones[0]].id : null
  user_data            = coalesce(
      length(regexall("windows", data.ibm_is_image.custom_image[count.index].os)) > 0 ? templatefile(local.ps_script, {
        "common_ps" = local.common_tpl,
        "ad_ip"     = local.ad_ip
        }
      ) : null,
      length(regexall("red", data.ibm_is_image.custom_image[count.index].os)) > 0 ? templatefile(local.rhel_script, {
        "ad_ip"     = local.ad_ip
        }
      ) : null,
      length(regexall("rocky-linux", data.ibm_is_image.custom_image[count.index].os)) > 0 ? templatefile(local.rhel_script, {
        "ad_ip"     = local.ad_ip
        }
      ) : null
  )
  boot_volume {
    size = var.boot_volume_capacity != null ? var.boot_volume_capacity : var.custom_image_instances[count.index].boot_volume_capacity
  }
  primary_network_interface {
    name            = "primary-nic"
    subnet          = ibm_is_subnet.subnets[0].id
    security_groups = [ibm_is_security_group.custom_image_sg[0].id]
  }
}

# Create Floating IP for custom VDA image VSI
resource "ibm_is_floating_ip" "custom_image_fip" {
  count          = var.deploy_custom_image_vsi ? (var.deploy_custom_image_fip ? length(var.custom_image_instances) : 0) : 0
  name           = length(var.custom_image_instances) > 1 ? "cstm-img-${local.uuid}-fip-${count.index + 1}" : "cstm-img-${local.uuid}-fip"
  resource_group = data.ibm_resource_group.citrix_daas.id
  target         = ibm_is_instance.custom_image_instance[count.index].primary_network_interface[0].id
}

# Create one public gateway per zone
resource "ibm_is_public_gateway" "gateway" {
  count          = length(var.zones)
  name           = "gw-${local.uuid}-${count.index}"
  vpc            = ibm_is_vpc.vpc.id
  zone           = var.zones[count.index]
  resource_group = data.ibm_resource_group.citrix_daas.id
}

locals {
  fortio_prefix         = format("vw-%s", local.uuid)
  fortio_manager_region = replace(replace(var.region, "/(br-sao|ca-tor)/", "us-east"), "jp-osa", "jp-tok")
  fortio_bucket_name    = format("%s-bucket-%s", local.fortio_prefix, var.region)
}

provider "ibm" {
  ibmcloud_api_key = var.ibmcloud_api_key
  region           = local.fortio_manager_region
  ibmcloud_timeout = 60
  alias            = "manager"
}

module "volume_worker" {
  count                   = var.deploy_volume_worker ? 1 : 0
  source                  = "./modules/fortio"
  github_pat              = var.personal_access_token
  resource_prefix         = local.fortio_prefix
  region                  = var.region
  manager_region          = local.fortio_manager_region
  resource_group          = var.resource_group
  bucket_name             = local.fortio_bucket_name
  repository_download_url = local.repository_download_url
  repository_reference    = var.repository_reference
  logdna_ingestion_key    = local.ingestion_key
  providers = {
    ibm         = ibm
    ibm.manager = ibm.manager
  }
}
