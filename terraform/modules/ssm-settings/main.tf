# AWS SSM Settings Module
# Configures SSM account settings for a single region
# - Blocks public sharing of SSM documents
# - Enables CloudWatch logging for SSM Automation with KMS encryption

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# -----------------------------------------------------------------------------
# Data Sources
# -----------------------------------------------------------------------------

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# -----------------------------------------------------------------------------
# SSM Service Settings - Public Sharing
# -----------------------------------------------------------------------------

resource "aws_ssm_service_setting" "public_sharing" {
  setting_id    = "arn:aws:ssm:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:servicesetting/ssm/documents/console/public-sharing-permission"
  setting_value = "Disable"
}

# -----------------------------------------------------------------------------
# KMS Key for SSM Automation CloudWatch Logs
# -----------------------------------------------------------------------------

resource "aws_kms_key" "ssm_logs" {
  description             = "KMS key for SSM Automation CloudWatch Logs - ${data.aws_region.current.name}"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "EnableIAMPolicies"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "AllowCloudWatchLogs"
        Effect = "Allow"
        Principal = {
          Service = "logs.${data.aws_region.current.name}.amazonaws.com"
        }
        Action = [
          "kms:Encrypt*",
          "kms:Decrypt*",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:Describe*"
        ]
        Resource = "*"
        Condition = {
          ArnLike = {
            "kms:EncryptionContext:aws:logs:arn" = "arn:aws:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:log-group:*"
          }
        }
      }
    ]
  })

  tags = {
    Name = "${var.resource_prefix}-ssm-logs-${data.aws_region.current.name}"
  }
}

resource "aws_kms_alias" "ssm_logs" {
  name          = "alias/${var.resource_prefix}-ssm-logs-${data.aws_region.current.name}"
  target_key_id = aws_kms_key.ssm_logs.key_id
}

# -----------------------------------------------------------------------------
# CloudWatch Log Group for SSM Automation
# -----------------------------------------------------------------------------

resource "aws_cloudwatch_log_group" "ssm_automation" {
  name              = "/${var.resource_prefix}/ssm/automation"
  retention_in_days = 365
  kms_key_id        = aws_kms_key.ssm_logs.arn

  tags = {
    Name = "${var.resource_prefix}-ssm-automation-logs"
  }
}

# -----------------------------------------------------------------------------
# SSM Service Settings - Automation CloudWatch Logging
# -----------------------------------------------------------------------------

resource "aws_ssm_service_setting" "automation_log_destination" {
  setting_id    = "arn:aws:ssm:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:servicesetting/ssm/automation/customer-script-log-destination"
  setting_value = "CloudWatch"

  depends_on = [aws_cloudwatch_log_group.ssm_automation]
}

resource "aws_ssm_service_setting" "automation_log_group" {
  setting_id    = "arn:aws:ssm:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:servicesetting/ssm/automation/customer-script-log-group-name"
  setting_value = aws_cloudwatch_log_group.ssm_automation.name

  depends_on = [aws_ssm_service_setting.automation_log_destination]
}
