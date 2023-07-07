##############################################################################
# Terraform Main IaC
##############################################################################

resource "ibm_iam_trusted_profile" "iam_trusted_profile" {
  name = "${var.resource_prefix}-trusted-profile"
}

resource "ibm_iam_trusted_profile_claim_rule" "iam_trusted_profile_claim_rule" {
  profile_id = ibm_iam_trusted_profile.iam_trusted_profile.id
  type       = "Profile-CR"
  conditions {
    claim    = "vpc_id"
    operator = "EQUALS"
    value    = "\"${var.vpc_id}\""
  }
  name    = "vw-trusted-profile-rule"
  cr_type = "VSI"
}

resource "ibm_iam_trusted_profile_policy" "vpc" {
  profile_id = ibm_iam_trusted_profile.iam_trusted_profile.id
  roles      = ["Writer", "Viewer", "Reader", "Editor"]

  resources {
    service           = "is"
    resource_group_id = var.resource_group_id
  }
}

resource "ibm_iam_trusted_profile_policy" "rg" {
  profile_id = ibm_iam_trusted_profile.iam_trusted_profile.id
  roles      = ["Writer", "Viewer", "Reader", "Editor"]

  resources {
    resource_type = "resource-group"
    resource      = var.resource_group_id
  }
}

resource "ibm_iam_trusted_profile_policy" "cos" {
  profile_id = ibm_iam_trusted_profile.iam_trusted_profile.id
  roles      = ["Writer", "Viewer", "Reader", "Editor"]
  resources {
    service              = "cloud-object-storage"
    resource_group_id    = var.resource_group_id
    resource_instance_id = split(":", split("/", ibm_resource_instance.cos_instance.id)[1])[1]
  }
}

resource "ibm_iam_trusted_profile_policy" "redis" {
  profile_id = ibm_iam_trusted_profile.iam_trusted_profile.id
  roles      = ["Operator", "Viewer", "Administrator", "Editor"]
  resources {
    service              = "databases-for-redis"
    resource_group_id    = var.resource_group_id
    resource_instance_id = split(".", split("@", var.redis_url)[1])[0]
  }
}

resource "ibm_iam_service_id" "service_id" {
  name        = "${var.resource_prefix}-${var.region}"
  description = "service id to be used with vw cloud function"
}

resource "ibm_iam_service_api_key" "service_id_api" {
  name           = "${var.resource_prefix}-${var.region}"
  iam_service_id = ibm_iam_service_id.service_id.iam_id
}

resource "ibm_iam_service_policy" "policy_rg" {
  iam_service_id = ibm_iam_service_id.service_id.id
  roles          = ["Writer", "Editor"]
  resources {
    resource_type = "resource-group"
    resource      = var.resource_group_id
  }
}

resource "ibm_iam_service_policy" "policy_trusted_profile" {
  iam_service_id = ibm_iam_service_id.service_id.id
  roles          = ["Editor", "User API key creator"]
  resources {
    service = "iam-identity"
    attributes = {
      "resource" = ibm_iam_trusted_profile.iam_trusted_profile.id
    }
  }
}

resource "ibm_iam_service_policy" "policy_function" {
  iam_service_id = ibm_iam_service_id.service_id.id
  roles          = ["Editor"]
  resources {
    service              = "functions"
    resource_group_id    = var.resource_group_id
    resource_instance_id = ibm_function_namespace.namespace.id
    region               = var.region
  }
}

resource "ibm_iam_service_policy" "policy_cos" {
  iam_service_id = ibm_iam_service_id.service_id.id
  roles          = ["Writer", "Editor"]
  resources {
    service              = "cloud-object-storage"
    resource_group_id    = var.resource_group_id
    resource_instance_id = split(":", split("/", ibm_resource_instance.cos_instance.id)[1])[1]
  }
}

resource "ibm_iam_service_policy" "policy_vpc" {
  iam_service_id = ibm_iam_service_id.service_id.id
  roles          = ["Editor"]
  resources {
    service           = "is"
    resource_group_id = var.resource_group_id
    attributes = {
      "vpcId" = var.vpc_id
    }
  }
}

resource "ibm_iam_service_policy" "policy_subnet" {
  count          = 3
  iam_service_id = ibm_iam_service_id.service_id.id
  roles          = ["Editor"]
  resources {
    service           = "is"
    resource_group_id = var.resource_group_id
    attributes = {
      "subnetId" = element([for subnet in var.subnet_ids : subnet.id], count.index)
    }
  }
}

resource "ibm_iam_service_policy" "policy_instance" {
  iam_service_id = ibm_iam_service_id.service_id.id
  roles          = ["Editor"]
  resources {
    service           = "is"
    resource_group_id = var.resource_group_id
    attributes = {
      "instanceId" = "*"
    }
  }
}

resource "ibm_iam_service_policy" "policy_volume" {
  iam_service_id = ibm_iam_service_id.service_id.id
  roles          = ["Editor"]
  resources {
    service           = "is"
    resource_group_id = var.resource_group_id
    attributes = {
      "volumeId" = "*"
    }
  }
}

resource "ibm_iam_service_policy" "policy_image" {
  iam_service_id = ibm_iam_service_id.service_id.id
  roles          = ["Editor"]
  resources {
    service           = "is"
    resource_group_id = var.resource_group_id
    attributes = {
      "imageId" = "*"
    }
  }
}

resource "ibm_iam_service_policy" "policy_security_group" {
  iam_service_id = ibm_iam_service_id.service_id.id
  roles          = ["Editor"]
  resources {
    service           = "is"
    resource_group_id = var.resource_group_id
    attributes = {
      "securityGroupId" = "*"
    }
  }
}

resource "ibm_resource_instance" "cos_instance" {
  name              = "${var.resource_prefix}-cos-${var.worker_region}"
  resource_group_id = var.resource_group_id
  service           = "cloud-object-storage"
  plan              = "standard"
  location          = "global"
}

resource "ibm_cos_bucket" "cos_bucket" {
  bucket_name          = var.bucket_name
  resource_instance_id = ibm_resource_instance.cos_instance.id
  region_location      = var.region
  storage_class        = "smart"
  expire_rule {
    rule_id = "${var.resource_prefix}-expiry"
    enable  = true
    days    = 1
  }
}

resource "ibm_function_namespace" "namespace" {
  name              = "${var.resource_prefix}-ns-${var.worker_region}"
  resource_group_id = var.resource_group_id
}

locals {
  action_dir = format("%s/%s", path.cwd, "modules/fortio/modules/manager/action")
}

resource "null_resource" "concat_manager_zip" {
  provisioner "local-exec" {
    command = "cat $ACTION_DIR/manager* > $ACTION_DIR/manager.zip"

    environment = {
      ACTION_DIR = local.action_dir
    }
  }
}

resource "ibm_function_action" "manager" {
  depends_on = [
    null_resource.concat_manager_zip
  ]

  name      = "${var.resource_prefix}-manager"
  namespace = ibm_function_namespace.namespace.name
  user_defined_parameters = jsonencode(concat([
    {
      "key"   = "workerNamePrefix",
      "value" = var.resource_prefix
    },
    {
      "key"   = "workerResourceGroupID",
      "value" = var.resource_group_id
    },
    {
      "key"   = "maxWorkerCount",
      "value" = var.max_worker_count
    },
    {
      "key"   = "cosServiceInstanceID"
      "value" = ibm_resource_instance.cos_instance.crn
    },
    {
      "key"   = "apiKey"
      "value" = ibm_iam_service_api_key.service_id_api.apikey
    },
    {
      "key"   = "trustedProfileID"
      "value" = ibm_iam_trusted_profile.iam_trusted_profile.id
    },
    {
      "key"   = "iamAuthEndpoint"
      "value" = var.iam_auth_endpoint
    },
    {
      "key"   = "redisURL"
      "value" = var.redis_url
    },
    {
      "key"   = "cacertB64",
      "value" = var.redis_certbase64
    },
    {
      "key"   = "agentRepositoryURL"
      "value" = format("%s/tarball/%s", var.repository_download_url, var.repository_reference)
    },
    {
      "key"   = "agentRepositoryPath"
      "value" = var.agent_repository_path
      }, {
      "key"   = "githubPAT"
      "value" = var.github_pat
    }
    ], [for subnet in var.subnet_ids :
    {
      "key"   = format("%s_%s", "workerSubnetID", subnet.zone)
      "value" = subnet.id
    }
    ], var.logdna_ingestion_key == "" ? [] : [
    {
      "key"   = "logdnaIngestionKey"
      "value" = var.logdna_ingestion_key
    }
  ]))

  exec {
    kind      = "go:1.19"
    code_path = format("%s/%s", local.action_dir, "manager.zip")
  }
}

resource "ibm_iam_authorization_policy" "policy" {
  source_service_name         = "functions"
  source_resource_instance_id = ibm_function_namespace.namespace.id
  target_service_name         = "cloud-object-storage"
  target_resource_instance_id = ibm_resource_instance.cos_instance.guid
  roles                       = ["Notifications Manager"]
}

resource "ibm_function_trigger" "cos_trigger" {
  depends_on = [
    ibm_iam_authorization_policy.policy
  ]

  name      = "${var.resource_prefix}-trigger"
  namespace = ibm_function_namespace.namespace.name
  feed {
    name = "/whisk.system/cos/changes"
    parameters = jsonencode([
      {
        "key"   = "bucket",
        "value" = ibm_cos_bucket.cos_bucket.bucket_name
      },
      {
        "key"   = "event_types"
        "value" = "write"
      },
      {
        "key"   = "suffix"
        "value" = ".job.json"
      }
    ])
  }
}

resource "ibm_function_rule" "cos_rule" {
  name         = "${var.resource_prefix}-trigger-manager"
  namespace    = ibm_function_namespace.namespace.name
  trigger_name = ibm_function_trigger.cos_trigger.name
  action_name  = ibm_function_action.manager.name
}
