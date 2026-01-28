terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# Use AWS Config service-linked role (satisfies Security Hub Config.1)
# Note: This role either already exists or will be automatically created by AWS Config
locals {
  config_service_linked_role_arn = "arn:aws:iam::${var.account_id}:role/aws-service-role/config.amazonaws.com/AWSServiceRoleForConfig"
}

# Configuration Recorder
resource "aws_config_configuration_recorder" "main" {
  # checkov:skip=CKV2_AWS_48:Global resource types must only be recorded in a single region
  name     = "${var.resource_prefix}-recorder"
  role_arn = local.config_service_linked_role_arn

  recording_group {
    all_supported                 = true
    include_global_resource_types = var.region == "us-east-1" # Only record globals in one region
  }

  recording_mode {
    recording_frequency = "CONTINUOUS"
  }
}

# Delivery Channel
resource "aws_config_delivery_channel" "main" {
  name           = "${var.resource_prefix}-delivery"
  s3_bucket_name = var.delivery_s3_bucket
  s3_key_prefix  = "${var.delivery_s3_key_prefix}/AWSLogs"

  snapshot_delivery_properties {
    delivery_frequency = var.delivery_frequency
  }

  depends_on = [aws_config_configuration_recorder.main]
}

# Start the recorder
resource "aws_config_configuration_recorder_status" "main" {
  name       = aws_config_configuration_recorder.main.name
  is_enabled = true

  depends_on = [aws_config_delivery_channel.main]
}
