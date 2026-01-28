terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# KMS key for access logging bucket encryption
resource "aws_kms_key" "access_logging" {
  description             = "KMS key for S3 access logging bucket encryption"
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
        Sid    = "Allow S3 to use key for access logs"
        Effect = "Allow"
        Principal = {
          Service = "logging.s3.amazonaws.com"
        }
        Action = [
          "kms:GenerateDataKey*",
          "kms:Decrypt"
        ]
        Resource = "*"
      }
    ]
  })

  tags = {
    Name           = "${var.resource_prefix}-access-logging-key"
    Purpose        = "S3 bucket encryption"
    ProtectsBucket = var.bucket_name
  }
}

resource "aws_kms_alias" "access_logging" {
  name          = "alias/${var.resource_prefix}-access-logging"
  target_key_id = aws_kms_key.access_logging.key_id
}

#tfsec:ignore:AVD-AWS-0089: Access logging bucket cannot log to itself - would cause circular logging
resource "aws_s3_bucket" "access_logging" {
  #checkov:skip=CKV_AWS_18: Access logging bucket cannot log to itself - would cause circular logging
  #checkov:skip=CKV2_AWS_62: No downstream consumer at this time
  #checkov:skip=CKV_AWS_144: Cross-region replication not required for access logs
  bucket = var.bucket_name

  tags = {
    Name    = var.bucket_name
    Purpose = "S3 access logging for baseline buckets"
  }
}

resource "aws_s3_bucket_versioning" "access_logging" {
  bucket = aws_s3_bucket.access_logging.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "access_logging" {
  bucket = aws_s3_bucket.access_logging.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.access_logging.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "access_logging" {
  bucket = aws_s3_bucket.access_logging.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "access_logging" {
  bucket = aws_s3_bucket.access_logging.id

  rule {
    id     = "access-log-retention"
    status = "Enabled"

    filter {
      prefix = ""
    }

    transition {
      days          = var.lifecycle_config.transition_to_ia_days
      storage_class = "STANDARD_IA"
    }

    expiration {
      days = var.lifecycle_config.expiration_days
    }

    noncurrent_version_expiration {
      noncurrent_days = var.lifecycle_config.noncurrent_version_expiration_days
    }
  }

  rule {
    id     = "abort-incomplete-multipart-uploads"
    status = "Enabled"

    filter {
      prefix = ""
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

# Bucket policy to allow S3 log delivery
resource "aws_s3_bucket_policy" "access_logging" {
  bucket = aws_s3_bucket.access_logging.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "S3ServerAccessLogsPolicy"
        Effect = "Allow"
        Principal = {
          Service = "logging.s3.amazonaws.com"
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.access_logging.arn}/*"
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = var.account_id
          }
        }
      },
      {
        Sid       = "DenyNonSSL"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.access_logging.arn,
          "${aws_s3_bucket.access_logging.arn}/*"
        ]
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      }
    ]
  })

  depends_on = [aws_s3_bucket_public_access_block.access_logging]
}
