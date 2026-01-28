terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# Get current account ID and region
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

locals {
  # LAMBDA_CODE scanning is only supported in these regions
  # https://docs.aws.amazon.com/inspector/latest/user/inspector_regions.html
  lambda_code_supported_regions = [
    "us-east-1",
    "us-east-2",
    "us-west-2",
    "ap-southeast-1",
    "ap-southeast-2",
    "ap-northeast-1",
    "eu-central-1",
    "eu-west-1",
    "eu-west-2",
    "eu-north-1",
  ]

  base_resource_types = ["EC2", "ECR", "LAMBDA"]

  # Add LAMBDA_CODE only for supported regions
  all_resource_types = contains(local.lambda_code_supported_regions, data.aws_region.current.name) ? concat(local.base_resource_types, ["LAMBDA_CODE"]) : local.base_resource_types
}

# Enable Inspector v2
resource "aws_inspector2_enabler" "main" {
  account_ids    = [data.aws_caller_identity.current.account_id]
  resource_types = local.all_resource_types
}
