output "account_id" {
  description = "AWS Account ID"
  value       = data.aws_caller_identity.current.account_id
}

output "logging_bucket" {
  description = "Centralized logging S3 bucket"
  value       = local.logging_bucket_name
}

output "logging_bucket_arn" {
  description = "Centralized logging S3 bucket ARN"
  value       = local.need_logging_bucket ? (var.logging_bucket_exists ? "arn:aws:s3:::${local.logging_bucket_name}" : module.s3_logging[0].bucket_arn) : ""
}

output "access_logging_bucket" {
  description = "S3 access logging bucket"
  value       = local.access_logging_bucket_name
}

output "cloudtrail_name" {
  description = "CloudTrail trail name"
  value       = local.deploy_cloudtrail ? module.cloudtrail[0].trail_name : var.cloudtrail_trail_name
}

output "control_tower_detected" {
  description = "Whether Control Tower was detected (CloudTrail and Config skipped)"
  value       = var.control_tower_exists
}

output "security_hub_aggregator_region" {
  description = "Security Hub aggregator region"
  value       = var.aggregator_region
}

output "target_regions" {
  description = "Target regions for baseline"
  value       = var.target_regions
}

output "security_hub_org_managed" {
  description = "Whether Security Hub is org-managed (skipped by account baseline)"
  value       = var.security_hub_is_org_managed
}

output "inspector_org_managed" {
  description = "Whether Inspector is org-managed (skipped by account baseline)"
  value       = var.inspector_is_org_managed
}

output "baseline_summary" {
  description = "Summary of baseline deployment"
  value = {
    account_id               = data.aws_caller_identity.current.account_id
    target_regions           = var.target_regions
    control_tower_detected   = var.control_tower_exists
    logging_bucket           = local.logging_bucket_name
    config_enabled           = var.enable_config && !var.control_tower_exists
    cloudtrail_enabled       = var.enable_cloudtrail && !var.control_tower_exists
    security_hub_enabled     = var.enable_security_hub && !var.security_hub_is_org_managed
    security_hub_org_managed = var.security_hub_is_org_managed
    inspector_enabled        = var.enable_inspector && !var.inspector_is_org_managed
    inspector_org_managed    = var.inspector_is_org_managed
    aggregator_region        = var.aggregator_region
  }
}
