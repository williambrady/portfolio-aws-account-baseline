output "block_public_acls" {
  description = "Whether Amazon S3 blocks public ACLs for this account"
  value       = aws_s3_account_public_access_block.block_all.block_public_acls
}

output "block_public_policy" {
  description = "Whether Amazon S3 blocks public bucket policies for this account"
  value       = aws_s3_account_public_access_block.block_all.block_public_policy
}

output "ignore_public_acls" {
  description = "Whether Amazon S3 ignores public ACLs for this account"
  value       = aws_s3_account_public_access_block.block_all.ignore_public_acls
}

output "restrict_public_buckets" {
  description = "Whether Amazon S3 restricts public bucket policies for this account"
  value       = aws_s3_account_public_access_block.block_all.restrict_public_buckets
}

output "id" {
  description = "AWS account ID"
  value       = aws_s3_account_public_access_block.block_all.id
}
