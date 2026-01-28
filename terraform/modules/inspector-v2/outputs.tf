output "enabled" {
  description = "Whether Inspector was enabled"
  value       = length(aws_inspector2_enabler.main) > 0
}

output "resource_types" {
  description = "Resource types that are enabled"
  value       = local.all_resource_types
}
