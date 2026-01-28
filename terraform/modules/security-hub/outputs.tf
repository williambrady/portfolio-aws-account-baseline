output "hub_arn" {
  description = "ARN of the Security Hub"
  value       = var.already_enabled ? null : (length(aws_securityhub_account.main) > 0 ? aws_securityhub_account.main[0].id : null)
}

output "is_aggregator" {
  description = "Whether this is the aggregator region"
  value       = var.is_aggregator
}

output "enabled_standards" {
  description = "Standards that were enabled"
  value       = local.standards_to_enable
}
