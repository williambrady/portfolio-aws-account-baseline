# Outputs for SSM Settings Module

output "public_sharing_setting" {
  description = "The SSM public sharing setting value"
  value       = aws_ssm_service_setting.public_sharing.setting_value
}

output "region" {
  description = "The region where this setting is applied"
  value       = data.aws_region.current.name
}

output "account_id" {
  description = "The account ID where this setting is applied"
  value       = data.aws_caller_identity.current.account_id
}

output "log_group_name" {
  description = "The CloudWatch Log Group name for SSM Automation"
  value       = aws_cloudwatch_log_group.ssm_automation.name
}

output "log_group_arn" {
  description = "The CloudWatch Log Group ARN for SSM Automation"
  value       = aws_cloudwatch_log_group.ssm_automation.arn
}

output "kms_key_arn" {
  description = "The KMS key ARN for SSM logs encryption"
  value       = aws_kms_key.ssm_logs.arn
}

output "automation_log_destination" {
  description = "The SSM Automation log destination setting"
  value       = aws_ssm_service_setting.automation_log_destination.setting_value
}
