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
  number  = false
  lower   = true
  special = false
}

# Generate random Active Directory join password
resource "random_password" "ad_join_pwd" {
  length           = 16
  special          = true
  override_special = "_%@"
}

# Define local variables for Virtual Server creation and Active Directory Cloudbase-Init scripts
locals {
  uuid                = random_string.resource_identifier.result
  connector_name      = "cc"
  connector_reg_num   = 5
  vpc_id              = var.vpc_name != "" ? data.ibm_is_vpc.vpc[0].id : ""
  standard_tpl        = templatefile("${path.module}/scripts/ad-userdata.ps1", {
      "ad_name"             = "${var.basename}-${local.uuid}-${var.active_directory_vsi_name}"
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
  extended_tpl        = templatefile("${path.module}/scripts/ad-extended.ps1", {
      "ad_domain_name"      = var.active_directory_domain_name,
      "connector_name"      = local.connector_name,
      "connector_reg_num"   = local.connector_reg_num,
      "resource_identifier" = local.uuid,
      "topology"            = var.active_directory_topology,
      "zones"               = join(",", var.zones),
    }
  )
  secondary_zones     = [
    for i, zone in var.zones :
      zone if i != 0
  ]
}

# Get resource group
data "ibm_resource_group" "cvad" {
  name = var.resource_group
}

# Get VPC if Terraform variable supplied
data "ibm_is_vpc" "vpc" {
  count = var.vpc_name != "" ? 1: 0
  name = var.vpc_name
}

# Create VPC if not supplied
resource "ibm_is_vpc" "vpc" {
  count          = local.vpc_id == "" ? 1 : 0
  name           = "${var.basename}-${local.uuid}-vpc"
  resource_group = data.ibm_resource_group.cvad.id
}

# Create one subnet per zone
resource "ibm_is_subnet" "subnets" {
  count                    = length(var.zones)
  name                     = "${var.basename}-${local.uuid}-subnet-${count.index +1}"
  vpc                      = local.vpc_id != "" ? local.vpc_id : ibm_is_vpc.vpc[0].id
  zone                     = var.zones[count.index]
  total_ipv4_address_count = 256
  resource_group           = data.ibm_resource_group.cvad.id
  public_gateway           = ibm_is_public_gateway.gateway[count.index].id
}

# Create security groups
resource "ibm_is_security_group" "master_prep_sg" {
  name           = "master-prep-sg"
  vpc            = local.vpc_id != "" ? local.vpc_id : ibm_is_vpc.vpc[0].id
  resource_group = data.ibm_resource_group.cvad.id
}

resource "ibm_is_security_group" "active_directory_sg" {
  name           = "active-directory-sg"
  vpc            = local.vpc_id != "" ? local.vpc_id : ibm_is_vpc.vpc[0].id
  resource_group = data.ibm_resource_group.cvad.id
}

resource "ibm_is_security_group" "connector_sg" {
  name           = "connector-sg"
  vpc            = local.vpc_id != "" ? local.vpc_id : ibm_is_vpc.vpc[0].id
  resource_group = data.ibm_resource_group.cvad.id
}

resource "ibm_is_security_group" "vda_sg" {
  name           = "vda-sg"
  vpc            = local.vpc_id != "" ? local.vpc_id : ibm_is_vpc.vpc[0].id
  resource_group = data.ibm_resource_group.cvad.id
}

resource "ibm_is_security_group" "custom_image_sg" {
  count          = var.deploy_custom_image_vsi ? 1 : 0
  name           = "custom-image-sg"
  vpc            = local.vpc_id != "" ? local.vpc_id : ibm_is_vpc.vpc[0].id
  resource_group = data.ibm_resource_group.cvad.id
}

# Create security group rules
resource "ibm_is_security_group_rule" "ingress_active_directory_from_connector_all" {
  group     = ibm_is_security_group.active_directory_sg.id
  direction = "inbound"
  remote    = ibm_is_security_group.connector_sg.id
}

resource "ibm_is_security_group_rule" "ingress_active_directory_from_vda_all" {
  group     = ibm_is_security_group.active_directory_sg.id
  direction = "inbound"
  remote    = ibm_is_security_group.vda_sg.id
}

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

resource "ibm_is_security_group_rule" "ingress_active_directory_from_active_directory_all" {
  count     = length(local.secondary_zones) > 0 ? 1 : 0
  group     = ibm_is_security_group.active_directory_sg.id
  direction = "inbound"
  remote    = ibm_is_security_group.active_directory_sg.id
}

resource "ibm_is_security_group_rule" "egress_active_directory_all" {
  group     = ibm_is_security_group.active_directory_sg.id
  direction = "outbound"
  remote    = "0.0.0.0/0"
}

resource "ibm_is_security_group_rule" "ingress_connector_from_vda_all" {
  group     = ibm_is_security_group.connector_sg.id
  direction = "inbound"
  remote    = ibm_is_security_group.vda_sg.id
}

resource "ibm_is_security_group_rule" "ingress_connector_from_active_directory_all" {
  group     = ibm_is_security_group.connector_sg.id
  direction = "inbound"
  remote    = ibm_is_security_group.active_directory_sg.id
}

resource "ibm_is_security_group_rule" "egress_connector_all" {
  group     = ibm_is_security_group.connector_sg.id
  direction = "outbound"
  remote    = "0.0.0.0/0"
}

resource "ibm_is_security_group_rule" "ingress_vda_from_connector_all" {
  group     = ibm_is_security_group.vda_sg.id
  direction = "inbound"
  remote    = ibm_is_security_group.connector_sg.id
}


resource "ibm_is_security_group_rule" "ingress_vda_from_active_directory_all" {
  group     = ibm_is_security_group.vda_sg.id
  direction = "inbound"
  remote    = ibm_is_security_group.active_directory_sg.id
}

resource "ibm_is_security_group_rule" "egress_vda_all" {
  group     = ibm_is_security_group.vda_sg.id
  direction = "outbound"
  remote    = "0.0.0.0/0"
}

resource "ibm_is_security_group_rule" "ingress_custom_image_tcp" {
  count     = var.deploy_custom_image_vsi ? 1 : 0
  group     = ibm_is_security_group.custom_image_sg[count.index].id
  direction = "inbound"
  remote    = "0.0.0.0/0"

  tcp {
    port_min = 3389
    port_max = 3389
  }
}

resource "ibm_is_security_group_rule" "egress_custom_image_all" {
  count     = var.deploy_custom_image_vsi ? 1 : 0
  group     = ibm_is_security_group.custom_image_sg[count.index].id
  direction = "outbound"
  remote    = "0.0.0.0/0"
}

# Get Windows image for Virtual Server creates
data "ibm_is_image" "windows" {
  name = "ibm-windows-server-2019-full-standard-amd64-5"
}

# Get SSH Key for Virtual Server creates
data "ibm_is_ssh_key" "ssh_key_id" {
  name       = var.ibmcloud_ssh_key_name
}

# Create Virtual Server for primary Active Directory Domain Controller
resource "ibm_is_instance" "active_directory" {
  name           = "${var.basename}-${local.uuid}-${var.active_directory_vsi_name}"
  vpc            = local.vpc_id != "" ? local.vpc_id : ibm_is_vpc.vpc[0].id
  zone           = var.zones[0]
  keys           = [data.ibm_is_ssh_key.ssh_key_id.id]
  image          = data.ibm_is_image.windows.id
  profile        = var.control_plane_profile
  resource_group = data.ibm_resource_group.cvad.id
  user_data      = var.active_directory_topology == "Extended" ? local.extended_tpl : local.standard_tpl

  primary_network_interface {
    name            = "primary-nic"
    subnet          = ibm_is_subnet.subnets[0].id
    security_groups = [ibm_is_security_group.active_directory_sg.id]
  }
}

# Create Virtual Server(s) for secondary Active Directory Domain Controller(s)
resource "ibm_is_instance" "secondary_active_directory" {
  count          = length(local.secondary_zones) > 0 ? length(local.secondary_zones) : 0
  name           = "${var.basename}-${local.uuid}-${var.active_directory_vsi_name}-${count.index+1}"
  vpc            = local.vpc_id != "" ? local.vpc_id : ibm_is_vpc.vpc[0].id
  zone           = local.secondary_zones[count.index]
  keys           = [data.ibm_is_ssh_key.ssh_key_id.id]
  image          = data.ibm_is_image.windows.id
  profile        = var.control_plane_profile
  resource_group = data.ibm_resource_group.cvad.id
  user_data      = var.active_directory_topology == "Extended" ? local.extended_tpl : templatefile("${path.module}/scripts/secondary-ad-userdata.ps1", {
      "root_ad_name"    = ibm_is_instance.active_directory.name,
      "ad_domain_name"  = var.active_directory_domain_name,
      "zones"           = join(",", local.secondary_zones),
      "topology"        = var.active_directory_topology,
      "zone_index"      = "${count.index}",
      "root_ad_ip"      = ibm_is_instance.active_directory.primary_network_interface[0].primary_ipv4_address,
      "ad_join_pwd"     = random_password.ad_join_pwd.result,
      "ad_safe_pwd"     = var.active_directory_safe_mode_password,
    }
  )

  primary_network_interface {
    name            = "primary-nic"
    subnet          = ibm_is_subnet.subnets[count.index+1].id
    security_groups = [ibm_is_security_group.active_directory_sg.id]
  }
}

# Create x number of Virtual Servers in y number of zones for Cloud Connector(s)
resource "ibm_is_instance" "connector" {
  count          = var.connector_per_zone * length(var.zones)
  name           = "${local.connector_name}-${local.uuid}-${count.index + 1}"
  vpc            = local.vpc_id != "" ? local.vpc_id : ibm_is_vpc.vpc[0].id
  zone           = var.zones[floor(count.index / var.connector_per_zone)]
  keys           = [data.ibm_is_ssh_key.ssh_key_id.id]
  image          = data.ibm_is_image.windows.id
  profile        = var.control_plane_profile
  resource_group = data.ibm_resource_group.cvad.id
  user_data = templatefile("${path.module}/scripts/connector-userdata.ps1", {
      "customer_id"            = var.citrix_customer_id,
      "api_id"                 = var.citrix_api_key_client_id,
      "api_secret"             = var.citrix_api_key_client_secret,
      "resource_location_name" = var.resource_location_names[floor(count.index / var.connector_per_zone)],
      "ad_domain_name"         = var.active_directory_domain_name,
      "ad_ip"                  = floor(count.index / var.connector_per_zone) == 0 ? ibm_is_instance.active_directory.primary_network_interface[0].primary_ipv4_address : ibm_is_instance.secondary_active_directory[floor(count.index / var.connector_per_zone)-1].primary_network_interface[0].primary_ipv4_address,
      "ghe_token"              = var.personal_access_token,
      "ibmcloud_account_id"    = var.ibmcloud_account_id,
      "vpc_id"                 = local.vpc_id != "" ? local.vpc_id : ibm_is_vpc.vpc[0].id,
      "resource_group_id"      = data.ibm_resource_group.cvad.id,
      "region"                 = var.region,
      "zone"                   = var.zones[floor(count.index / var.connector_per_zone)],
      "master_prep_sg"         = ibm_is_security_group.master_prep_sg.name,
      "topology"               = var.active_directory_topology,
      "ad_join_pwd"            = random_password.ad_join_pwd.result,
      "plugin_download_url"    = var.plugin_download_url
      "vda_sg"                 = ibm_is_security_group.vda_sg.name
    }
  )

  primary_network_interface {
    name            = "primary-nic"
    subnet          = ibm_is_subnet.subnets[floor(count.index / var.connector_per_zone)].id
    security_groups = [ibm_is_security_group.connector_sg.id]
  }
}

# Create Virtual Server for custom VDA image creation
resource "ibm_is_instance" "custom_image_instance" {
  count           = var.deploy_custom_image_vsi ? 1 : 0
  name            = "cstm-img-${local.uuid}"
  vpc             = local.vpc_id != "" ? local.vpc_id : ibm_is_vpc.vpc[0].id
  zone            = var.zones[0]
  keys            = [data.ibm_is_ssh_key.ssh_key_id.id]
  image           = data.ibm_is_image.windows.id
  profile         = var.custom_image_vsi_profile
  resource_group  = data.ibm_resource_group.cvad.id
  user_data       = templatefile("${path.module}/scripts/custom-image-userdata.ps1", {
      "ad_ip" = ibm_is_instance.active_directory.primary_network_interface[0].primary_ipv4_address
    }
  )

  primary_network_interface {
    name            = "primary-nic"
    subnet          = ibm_is_subnet.subnets[0].id
    security_groups = [ibm_is_security_group.custom_image_sg[count.index].id]
  }
}

# Create one public gateway per zone
resource "ibm_is_public_gateway" "gateway" {
  count           = length(var.zones)
  name            = "gw-${local.uuid}-${count.index}"
  vpc             = local.vpc_id != "" ? local.vpc_id : ibm_is_vpc.vpc[0].id
  zone            = var.zones[count.index]
  resource_group  = data.ibm_resource_group.cvad.id
}