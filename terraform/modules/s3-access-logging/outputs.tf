output "bucket_name" {
  description = "Name of the access logging bucket"
  value       = aws_s3_bucket.access_logging.id
}

output "bucket_arn" {
  description = "ARN of the access logging bucket"
  value       = aws_s3_bucket.access_logging.arn
}

output "bucket_domain_name" {
  description = "Domain name of the access logging bucket"
  value       = aws_s3_bucket.access_logging.bucket_domain_name
}

output "kms_key_arn" {
  description = "ARN of the KMS key for bucket encryption"
  value       = aws_kms_key.access_logging.arn
}

output "kms_key_id" {
  description = "ID of the KMS key for bucket encryption"
  value       = aws_kms_key.access_logging.key_id
}
