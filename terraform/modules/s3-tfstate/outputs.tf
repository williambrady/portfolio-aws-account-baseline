output "bucket_name" {
  description = "Name of the Terraform state bucket"
  value       = aws_s3_bucket.tfstate.id
}

output "bucket_arn" {
  description = "ARN of the Terraform state bucket"
  value       = aws_s3_bucket.tfstate.arn
}

output "bucket_domain_name" {
  description = "Domain name of the Terraform state bucket"
  value       = aws_s3_bucket.tfstate.bucket_domain_name
}

output "kms_key_arn" {
  description = "ARN of the KMS key for bucket encryption"
  value       = aws_kms_key.tfstate.arn
}

output "kms_key_id" {
  description = "ID of the KMS key for bucket encryption"
  value       = aws_kms_key.tfstate.key_id
}
