variable "region" {
  description = "AWS region for this Config deployment"
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

variable "delivery_s3_bucket" {
  description = "S3 bucket for Config delivery"
  type        = string
}

variable "delivery_s3_key_prefix" {
  description = "S3 key prefix for Config delivery"
  type        = string
  default     = "config"
}

variable "delivery_frequency" {
  description = "Frequency for Config snapshot delivery"
  type        = string
  default     = "TwentyFour_Hours"
}
