output "internet_gateway_block_mode" {
  description = "VPC internet gateway block mode setting (null if disabled)"
  value       = length(aws_vpc_block_public_access_options.block_public_access) > 0 ? aws_vpc_block_public_access_options.block_public_access[0].internet_gateway_block_mode : null
}

output "vpc_block_public_access_id" {
  description = "ID of the VPC block public access configuration (null if disabled)"
  value       = length(aws_vpc_block_public_access_options.block_public_access) > 0 ? aws_vpc_block_public_access_options.block_public_access[0].id : null
}

output "vpc_block_public_access_enabled" {
  description = "Whether VPC block public access is enabled"
  value       = var.vpc_block_public_access_mode != "disabled"
}
