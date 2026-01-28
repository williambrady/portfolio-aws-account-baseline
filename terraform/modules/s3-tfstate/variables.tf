variable "bucket_name" {
  description = "Name of the S3 bucket for Terraform state"
  type        = string
}

variable "account_id" {
  description = "AWS Account ID"
  type        = string
}

variable "resource_prefix" {
  description = "Prefix for resource names"
  type        = string
}

variable "access_logging_bucket" {
  description = "Name of the S3 bucket for access logging"
  type        = string
}

variable "lifecycle_config" {
  description = "Lifecycle settings for state bucket (transition only, no expiration)"
  type = object({
    transition_to_ia_days = number
  })
  default = {
    transition_to_ia_days = 90
  }
}
