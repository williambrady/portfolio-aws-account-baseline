terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# Enable EBS encryption by default for all new volumes
resource "aws_ebs_encryption_by_default" "enabled" {
  enabled = true
}

# Block public access to EBS snapshots
resource "aws_ebs_snapshot_block_public_access" "enabled" {
  state = "block-all-sharing"
}

# Configure Instance Metadata Service (IMDS) defaults
resource "aws_ec2_instance_metadata_defaults" "secure" {
  http_tokens                 = "required" # IMDSv2 only (no IMDSv1)
  http_put_response_hop_limit = 2          # Allow 2 hops for containers
  instance_metadata_tags      = "enabled"  # Enable access to instance tags

  depends_on = [
    aws_ebs_encryption_by_default.enabled,
    aws_ebs_snapshot_block_public_access.enabled
  ]
}
