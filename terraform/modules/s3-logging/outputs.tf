output "bucket_name" {
  description = "Name of the logging bucket"
  value       = aws_s3_bucket.logging.id
}

output "bucket_arn" {
  description = "ARN of the logging bucket"
  value       = aws_s3_bucket.logging.arn
}

output "bucket_domain_name" {
  description = "Domain name of the logging bucket"
  value       = aws_s3_bucket.logging.bucket_domain_name
}

output "kms_key_arn" {
  description = "ARN of the KMS key for bucket encryption"
  value       = aws_kms_key.logging.arn
}

output "kms_key_id" {
  description = "ID of the KMS key for bucket encryption"
  value       = aws_kms_key.logging.key_id
}
