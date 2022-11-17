##############################################################################
# Terraform Outputs
##############################################################################

output "ingestion_key" {
  value       = ibm_resource_key.resource_key.credentials.ingestion_key
  sensitive   = true
  description = "Ingestion Key for LogDNA"
}
