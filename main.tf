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

# Generate a random identifier
resource "random_string" "resource_identifier" {
  length  = 5
  upper   = false
  number  = false
  lower   = true
  special = false
}

resource "random_password" "ad_join_pwd" {
  length           = 16
  special          = true
  override_special = "_%@"
}

locals {
  uuid            = random_string.resource_identifier.result
  connector_name  = "cc"
  connector_depth = 5

  vpc_id = var.vpc_name != "" ? data.ibm_is_vpc.vpc[0].id : ""
}

data "ibm_resource_group" "cvad" {
  name = var.resource_group
}

data "ibm_is_vpc" "vpc" {
  count = var.vpc_name != "" ? 1: 0
  name = var.vpc_name
}

resource "ibm_is_vpc" "vpc" {
  count          = local.vpc_id == "" ? 1 : 0
  name           = "${var.basename}-${local.uuid}-vpc"
  resource_group = data.ibm_resource_group.cvad.id
}

resource "ibm_is_subnet" "subnet1" {
  name                     = "${var.basename}-${local.uuid}-subnet1"
  vpc                      = local.vpc_id != "" ? local.vpc_id : ibm_is_vpc.vpc[0].id
  zone                     = var.zone
  total_ipv4_address_count = 256
  resource_group           = data.ibm_resource_group.cvad.id
  public_gateway           = ibm_is_public_gateway.gateway.id
}

resource "ibm_is_security_group" "control_plane_sg" {
  name           = "${var.basename}-${local.uuid}-control-plane-sg"
  vpc            = local.vpc_id != "" ? local.vpc_id : ibm_is_vpc.vpc[0].id
  resource_group = data.ibm_resource_group.cvad.id
}

resource "ibm_is_security_group_rule" "ingress_tcp_control_plane_all" {
  group     = ibm_is_security_group.control_plane_sg.id
  direction = "inbound"
  remote    = "0.0.0.0/0"

  tcp {
    port_min = 1
    port_max = 65535
  }
}

resource "ibm_is_security_group_rule" "ingress_udp_control_plane_all" {
  group     = ibm_is_security_group.control_plane_sg.id
  direction = "inbound"
  remote    = "0.0.0.0/0"

  udp {
    port_min = 1
    port_max = 65535
  }
}

# allow ping
resource "ibm_is_security_group_rule" "ingress_icmp_control_plane_all" {
  group     = ibm_is_security_group.control_plane_sg.id
  direction = "inbound"
  remote    = "0.0.0.0/0"

  icmp {}
}

resource "ibm_is_security_group_rule" "egress_control_plane_all" {
  group     = ibm_is_security_group.control_plane_sg.id
  direction = "outbound"
  remote    = "0.0.0.0/0"
}

resource "ibm_is_security_group" "vda_sg" {
  name           = "vda-sg"
  vpc            = local.vpc_id != "" ? local.vpc_id : ibm_is_vpc.vpc[0].id
  resource_group = data.ibm_resource_group.cvad.id
}

resource "ibm_is_security_group_rule" "ingress_tcp_vda_all" {
  group     = ibm_is_security_group.vda_sg.id
  direction = "inbound"
  remote    = "0.0.0.0/0"

  tcp {
    port_min = 1
    port_max = 65535
  }
}

resource "ibm_is_security_group_rule" "ingress_udp_vda_all" {
  group     = ibm_is_security_group.vda_sg.id
  direction = "inbound"
  remote    = "0.0.0.0/0"

  udp {
    port_min = 1
    port_max = 65535
  }
}

# allow ping
resource "ibm_is_security_group_rule" "ingress_icmp_vda_all" {
  group     = ibm_is_security_group.vda_sg.id
  direction = "inbound"
  remote    = "0.0.0.0/0"

  icmp {}
}

resource "ibm_is_security_group_rule" "egress_vda_all" {
  group     = ibm_is_security_group.vda_sg.id
  direction = "outbound"
  remote    = "0.0.0.0/0"
}

resource "ibm_is_security_group" "master_prep_sg" {
  name           = "master-prep-sg"
  vpc            = local.vpc_id != "" ? local.vpc_id : ibm_is_vpc.vpc[0].id
  resource_group = data.ibm_resource_group.cvad.id
}

// Security Group for Custom Image Instance
resource "ibm_is_security_group" "custom_image_sg" {
  name           = "custom-image-sg"
  vpc            = local.vpc_id != "" ? local.vpc_id : ibm_is_vpc.vpc[0].id
  resource_group = data.ibm_resource_group.cvad.id
}

resource "ibm_is_security_group_rule" "custom_image_sg_ingress_tcp" {
  group     = ibm_is_security_group.custom_image_sg.id
  direction = "inbound"
  remote    = "0.0.0.0/0"

  tcp {
    port_min = 3389
    port_max = 3389
  }
}

resource "ibm_is_security_group_rule" "custom_image_sg_egress_all" {
  group     = ibm_is_security_group.custom_image_sg.id
  direction = "outbound"
  remote    = "0.0.0.0/0"
}

data "ibm_is_image" "windows" {
  name = "ibm-windows-server-2019-full-standard-amd64-6"
}

data "ibm_is_ssh_key" "ssh_key_id" {
  name       = var.ibmcloud_ssh_key_name
}

resource "ibm_is_instance" "active_directory" {
  name           = "${var.basename}-${local.uuid}-${var.active_directory_vsi_name}"
  vpc            = local.vpc_id != "" ? local.vpc_id : ibm_is_vpc.vpc[0].id
  zone           = var.zone
  keys           = [data.ibm_is_ssh_key.ssh_key_id.id]
  image          = data.ibm_is_image.windows.id
  profile        = var.control_plane_profile
  resource_group = data.ibm_resource_group.cvad.id
  user_data      = templatefile("${path.module}/scripts/ad-userdata.ps1", {
      "ad_domain_name"      = var.active_directory_domain_name,
      "netbios_name"        = var.netbios_name
      "connector_name"      = local.connector_name
      "connector_depth"     = local.connector_depth
      "resource_identifier" = local.uuid,
      "topology"            = var.active_directory_topology,
      "ad_join_pwd"         = random_password.ad_join_pwd.result,
      "ad_safe_pwd"         = var.active_directory_safe_mode_password
    }
  )

  primary_network_interface {
    name            = "primary-nic"
    subnet          = ibm_is_subnet.subnet1.id
    security_groups = [ibm_is_security_group.control_plane_sg.id]
  }
}

resource "ibm_is_instance" "connector" {
  count          = var.connector_depth
  name           = "${local.connector_name}-${local.uuid}-${count.index + 1}"
  vpc            = local.vpc_id != "" ? local.vpc_id : ibm_is_vpc.vpc[0].id
  zone           = var.zone
  keys           = [data.ibm_is_ssh_key.ssh_key_id.id]
  image          = data.ibm_is_image.windows.id
  profile        = var.control_plane_profile
  resource_group = data.ibm_resource_group.cvad.id
  user_data = templatefile("${path.module}/scripts/connector-userdata.ps1", {
      "customer_id"            = var.citrix_customer_id,
      "api_id"                 = var.citrix_api_key_client_id,
      "api_secret"             = var.citrix_api_key_client_secret,
      "resource_location_name" = var.resource_location_name,
      "ad_domain_name"         = var.active_directory_domain_name,
      "ad_ip"                  = ibm_is_instance.active_directory.primary_network_interface[0].primary_ipv4_address,
      "ghe_token"              = var.personal_access_token,
      "ibmcloud_account_id"    = var.ibmcloud_account_id,
      "vpc_id"                 = local.vpc_id != "" ? local.vpc_id : ibm_is_vpc.vpc[0].id,
      "resource_group_id"      = data.ibm_resource_group.cvad.id,
      "region"                 = var.region,
      "zone"                   = var.zone,
      "master_prep_sg"         = ibm_is_security_group.master_prep_sg.name,
      "topology"               = var.active_directory_topology,
      "ad_join_pwd"            = random_password.ad_join_pwd.result,
      "dev_mode"               = var.dev_mode
    }
  )

  primary_network_interface {
    name            = "primary-nic"
    subnet          = ibm_is_subnet.subnet1.id
    security_groups = [ibm_is_security_group.control_plane_sg.id]
  }
}

// Custom Image Instance
resource "ibm_is_instance" "custom_image_instance" {
  count          = var.deploy_custom_image_vsi ? 1 : 0
  name           = "cstm-img-${local.uuid}"
  vpc            = local.vpc_id != "" ? local.vpc_id : ibm_is_vpc.vpc[0].id
  zone           = var.zone
  keys           = [data.ibm_is_ssh_key.ssh_key_id.id]
  image          = data.ibm_is_image.windows.id
  profile        = var.custom_image_vsi_profile
  resource_group = data.ibm_resource_group.cvad.id
  user_data = templatefile("${path.module}/scripts/custom-image-userdata.ps1", {
      "ad_ip" = ibm_is_instance.active_directory.primary_network_interface[0].primary_ipv4_address
    }
  )

  primary_network_interface {
    name            = "primary-nic"
    subnet          = ibm_is_subnet.subnet1.id
    security_groups = [ibm_is_security_group.custom_image_sg.id]
  }
}

resource "ibm_is_public_gateway" "gateway" {
  name = "gw-${local.uuid}"
  vpc  = local.vpc_id != "" ? local.vpc_id : ibm_is_vpc.vpc[0].id
  zone = var.zone
  resource_group = data.ibm_resource_group.cvad.id
}