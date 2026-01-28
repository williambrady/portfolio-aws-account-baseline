terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# Block public access to S3 at the account level
# This applies to all S3 buckets in the account across all regions
resource "aws_s3_account_public_access_block" "block_all" {
  block_public_acls       = true # Block new public ACLs and uploading objects with public ACLs
  block_public_policy     = true # Block new public bucket policies
  ignore_public_acls      = true # Ignore all public ACLs on buckets and objects
  restrict_public_buckets = true # Restrict access to buckets with public policies
}
