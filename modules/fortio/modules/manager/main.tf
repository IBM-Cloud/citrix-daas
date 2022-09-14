##############################################################################
# Terraform Main IaC
##############################################################################

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
      "value" = var.ibmcloud_api_key
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
    kind      = "go:1.17"
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
