terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# KMS key for CloudTrail encryption
resource "aws_kms_key" "cloudtrail" {
  description             = "KMS key for CloudTrail encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Enable IAM User Permissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${var.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "Allow CloudTrail to encrypt logs"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action = [
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = var.account_id
          }
          StringLike = {
            "kms:EncryptionContext:aws:cloudtrail:arn" = "arn:aws:cloudtrail:*:${var.account_id}:trail/*"
          }
        }
      },
      {
        Sid    = "Allow CloudTrail to describe key"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "kms:DescribeKey"
        Resource = "*"
      }
    ]
  })

  tags = {
    Name    = "${var.resource_prefix}-cloudtrail-key"
    Purpose = "CloudTrail log encryption"
  }
}

resource "aws_kms_alias" "cloudtrail" {
  name          = "alias/${var.resource_prefix}-cloudtrail"
  target_key_id = aws_kms_key.cloudtrail.key_id
}

# KMS key for CloudWatch Logs encryption
resource "aws_kms_key" "cloudwatch_logs" {
  description             = "KMS key for CloudTrail CloudWatch Logs encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Enable IAM User Permissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${var.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "Allow CloudWatch Logs to use key"
        Effect = "Allow"
        Principal = {
          Service = "logs.amazonaws.com"
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
          ArnEquals = {
            "kms:EncryptionContext:aws:logs:arn" = "arn:aws:logs:us-east-1:${var.account_id}:log-group:${var.resource_prefix}-cloudtrail-logs"
          }
        }
      }
    ]
  })

  tags = {
    Name             = "${var.resource_prefix}-cloudwatch-logs-key"
    Purpose          = "CloudWatch Logs encryption"
    ProtectsLogGroup = "${var.resource_prefix}-cloudtrail-logs"
  }
}

resource "aws_kms_alias" "cloudwatch_logs" {
  name          = "alias/${var.resource_prefix}-cloudwatch-logs"
  target_key_id = aws_kms_key.cloudwatch_logs.key_id
}

# CloudWatch Log Group for CloudTrail
resource "aws_cloudwatch_log_group" "cloudtrail" {
  name              = "${var.resource_prefix}-cloudtrail-logs"
  retention_in_days = var.cloudwatch_logs_retention_days
  kms_key_id        = aws_kms_key.cloudwatch_logs.arn

  tags = {
    Name    = "${var.resource_prefix}-cloudtrail-logs"
    Purpose = "CloudTrail log delivery"
  }
}

# IAM role for CloudTrail to write to CloudWatch Logs
resource "aws_iam_role" "cloudtrail_cloudwatch" {
  name = "${var.resource_prefix}-cloudtrail-cloudwatch-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = {
    Name    = "${var.resource_prefix}-cloudtrail-cloudwatch-role"
    Purpose = "Allow CloudTrail to deliver logs to CloudWatch"
  }
}

#tfsec:ignore:AVD-AWS-0057 IAM policy should avoid use of wildcards and instead apply the principle of least privilege.
#trivy:skip=AVD-AWS-0057: IAM policy should avoid use of wildcards and instead apply the principle of least privilege. This is the least privilege for this resource
resource "aws_iam_role_policy" "cloudtrail_cloudwatch" {
  name = "${var.resource_prefix}-cloudtrail-cloudwatch-policy"
  role = aws_iam_role.cloudtrail_cloudwatch.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "${aws_cloudwatch_log_group.cloudtrail.arn}:*"
      }
    ]
  })
}

# CloudTrail
resource "aws_cloudtrail" "main" {
  #checkov:skip=CKV_AWS_252: Ensure CloudTrail defines an SNS Topic. We do not currently leverage SNS in this manner
  name                          = var.trail_name
  s3_bucket_name                = var.s3_bucket_name
  s3_key_prefix                 = var.s3_key_prefix
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  kms_key_id                    = aws_kms_key.cloudtrail.arn

  # CloudWatch Logs integration
  cloud_watch_logs_group_arn = "${aws_cloudwatch_log_group.cloudtrail.arn}:*"
  cloud_watch_logs_role_arn  = aws_iam_role.cloudtrail_cloudwatch.arn

  event_selector {
    read_write_type           = "All"
    include_management_events = true
  }

  tags = {
    Name    = var.trail_name
    Purpose = "Account-wide audit trail"
  }

  depends_on = [aws_iam_role_policy.cloudtrail_cloudwatch]
}
