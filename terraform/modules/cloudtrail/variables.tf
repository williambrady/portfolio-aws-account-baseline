variable "trail_name" {
  description = "Name of the CloudTrail trail"
  type        = string
}

variable "s3_bucket_name" {
  description = "S3 bucket for CloudTrail logs"
  type        = string
}

variable "s3_key_prefix" {
  description = "S3 key prefix for CloudTrail logs"
  type        = string
  default     = "cloudtrail"
}

variable "account_id" {
  description = "AWS Account ID"
  type        = string
}

variable "resource_prefix" {
  description = "Prefix for resource names"
  type        = string
}

variable "cloudwatch_logs_retention_days" {
  description = "CloudWatch Logs retention in days"
  type        = number
  default     = 365
}
