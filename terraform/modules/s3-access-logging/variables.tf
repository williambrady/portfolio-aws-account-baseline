variable "bucket_name" {
  description = "Name of the S3 bucket for access logging"
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

variable "lifecycle_config" {
  description = "S3 lifecycle configuration"
  type = object({
    transition_to_ia_days              = number
    expiration_days                    = number
    noncurrent_version_expiration_days = number
  })
}
