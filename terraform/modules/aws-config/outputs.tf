output "recorder_id" {
  description = "ID of the Config recorder"
  value       = aws_config_configuration_recorder.main.id
}

output "recorder_name" {
  description = "Name of the Config recorder"
  value       = aws_config_configuration_recorder.main.name
}

output "role_arn" {
  description = "ARN of the Config service-linked role"
  value       = local.config_service_linked_role_arn
}
