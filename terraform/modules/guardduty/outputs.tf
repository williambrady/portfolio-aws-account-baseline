# Outputs for GuardDuty Module

output "detector_id" {
  description = "The ID of the GuardDuty detector"
  value       = aws_guardduty_detector.main.id
}

output "account_id" {
  description = "The AWS account ID"
  value       = aws_guardduty_detector.main.account_id
}

output "region" {
  description = "The region where GuardDuty is enabled"
  value       = data.aws_region.current.name
}
