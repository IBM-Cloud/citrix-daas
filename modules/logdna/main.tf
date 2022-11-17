##############################################################################
# Terraform Main IaC
##############################################################################
data "ibm_resource_group" "group" {
  name = var.resource_group_name
}

# Create a logging instance
resource "ibm_resource_instance" "instance" {
  name              = var.name
  service           = "logdna"
  plan              = var.plan
  location          = var.location
  resource_group_id = data.ibm_resource_group.group.id
  tags              = var.tags
  parameters = {
    default_receiver = var.default_receiver
  }
}

# Create the resource key that is associated with the {{site.data.keyword.la_short}} instance
resource "ibm_resource_key" "resource_key" {
  name                 = format("%s-logdna-key", var.name)
  role                 = "Manager"
  resource_instance_id = ibm_resource_instance.instance.id
}
