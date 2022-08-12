##############################################################################
# Terraform Main IaC
##############################################################################

data "ibm_resource_group" "cvad" {
    name = var.resource_group
}

resource "ibm_is_vpc" "vpc" {
    name            = "${var.resource_prefix}-vpc"
    resource_group  = data.ibm_resource_group.cvad.id
}

resource "ibm_is_public_gateway" "gateway" {
    count            = 3
    name            = format("%s-%s-%s", "${var.resource_prefix}-pg", var.region, count.index)
    vpc             = ibm_is_vpc.vpc.id
    zone            = format("%s-%s", var.region, count.index+1)
    resource_group  = data.ibm_resource_group.cvad.id
}

resource "ibm_is_vpc_address_prefix" "add_prefix" {
    count           = 3
    cidr            = "10.0.${count.index+1}.0/27"
    name            = format("%s-%s-%s", "${var.resource_prefix}-pre", var.region, count.index)
    vpc             = ibm_is_vpc.vpc.id
    zone            = format("%s-%s", var.region, count.index+1)
}

resource "ibm_is_subnet" "subnet" {
    depends_on = [
        ibm_is_vpc_address_prefix.add_prefix,
    ]

    count           = 3
    name            = format("%s-%s-%s", "${var.resource_prefix}-sub", var.region, count.index+1)
    vpc             = ibm_is_vpc.vpc.id
    zone            = format("%s-%s", var.region, count.index+1)
    ipv4_cidr_block = "10.0.${count.index+1}.0/27"
    public_gateway  = ibm_is_public_gateway.gateway[count.index].id
    resource_group  = data.ibm_resource_group.cvad.id
}

resource "random_password" "database" {
    length      = 32
    numeric     = true
    lower       = true
    upper       = true
    special     = false
    min_lower   = 1
    min_upper   = 1
    min_numeric = 1
}

resource "ibm_database" "fortio_db" {
    name              = "${var.resource_prefix}-db-${var.region}"
    plan              = "standard"
    location          = var.region
    service           = "databases-for-redis"
    resource_group_id = data.ibm_resource_group.cvad.id

    adminpassword                = random_password.database.result
    members_memory_allocation_mb = 2048
    members_disk_allocation_mb   = 4096
}

##############################################################################
# Sub Module Manager
# This is needed because IBM Functions is not available in all regions
##############################################################################

locals {
    subnet_ids = [for subnet in ibm_is_subnet.subnet :
        {
            "zone" = subnet.zone,
            "id" = subnet.id
        }
    ]
}

module "manager" {
    source                  = "./modules/manager"
    ibmcloud_api_key        = var.ibmcloud_api_key
    worker_region           = var.region
    region                  = var.manager_region
    max_worker_count        = var.max_worker_count
    iam_auth_endpoint       = var.iam_auth_endpoint
    github_pat              = var.github_pat
    resource_prefix         = var.resource_prefix
    resource_group_id       = data.ibm_resource_group.cvad.id
    redis_url               = replace(replace(ibm_database.fortio_db.connectionstrings[0].composed, "$PASSWORD", random_password.database.result), "/0", "")
    redis_certbase64        = ibm_database.fortio_db.connectionstrings[0].certbase64
    subnet_ids              = local.subnet_ids
    bucket_name             = var.bucket_name
    repository_download_url = var.repository_download_url
    repository_reference    = var.repository_reference
    agent_repository_path   = var.agent_repository_path
    logdna_ingestion_key    = var.logdna_ingestion_key
    providers = {
        ibm = ibm.manager
    }
}
