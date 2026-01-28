# Account information
variable "account_id" {
  description = "AWS Account ID"
  type        = string
}

variable "target_regions" {
  description = "List of target regions for deployment"
  type        = list(string)
  default = [
    "us-east-1", "us-east-2", "us-west-1", "us-west-2",
    "eu-west-1", "eu-west-2", "eu-west-3", "eu-central-1", "eu-north-1",
    "ap-southeast-1", "ap-southeast-2", "ap-northeast-1", "ap-northeast-2", "ap-northeast-3", "ap-south-1",
    "ca-central-1", "sa-east-1"
  ]
}

variable "aggregator_region" {
  description = "Region for Security Hub finding aggregator"
  type        = string
  default     = "us-east-1"
}

# Naming
variable "resource_prefix" {
  description = "Prefix for resource names"
  type        = string
  default     = "secops"
}

# VPC Block Public Access
variable "vpc_block_public_access_mode" {
  description = "VPC block public access mode: ingress (blocks inbound), bidirectional (blocks both), or disabled (no restrictions)"
  type        = string
  default     = "ingress"

  validation {
    condition     = contains(["ingress", "bidirectional", "disabled"], var.vpc_block_public_access_mode)
    error_message = "VPC block public access mode must be one of: ingress, bidirectional, or disabled."
  }
}

# Discovery state - Config
variable "config_exists" {
  description = "Map of region to boolean indicating if Config exists"
  type        = map(bool)
  default     = {}
}

variable "config_is_control_tower_managed" {
  description = "Whether Config is managed by Control Tower"
  type        = bool
  default     = false
}

variable "config_is_org_managed" {
  description = "Whether Config is managed by an organization (delivery to external account bucket). When true, Config module is skipped."
  type        = bool
  default     = false
}

# Discovery state - CloudTrail
variable "cloudtrail_multi_region_exists" {
  description = "Whether a multi-region CloudTrail already exists"
  type        = bool
  default     = false
}

variable "cloudtrail_is_control_tower_managed" {
  description = "Whether CloudTrail is managed by Control Tower"
  type        = bool
  default     = false
}

variable "cloudtrail_is_org_trail" {
  description = "Whether CloudTrail is an organization trail (managed by org-baseline). When true, CloudTrail module is skipped."
  type        = bool
  default     = false
}

variable "cloudtrail_trail_name" {
  description = "Name of existing CloudTrail trail"
  type        = string
  default     = ""
}

# Control Tower detection
variable "control_tower_exists" {
  description = "Whether Control Tower is detected (from discovery). When true, CloudTrail and Config modules are skipped as Control Tower manages these services."
  type        = bool
  default     = false
}

# Discovery state - Security Hub
variable "security_hub_enabled" {
  description = "Map of region to boolean indicating if Security Hub is enabled"
  type        = map(bool)
  default     = {}
}

variable "security_hub_standards" {
  description = "Map of region to list of enabled standards"
  type        = map(list(string))
  default     = {}
}

variable "security_hub_has_aggregator" {
  description = "Whether a Security Hub finding aggregator already exists"
  type        = bool
  default     = false
}

variable "security_hub_is_org_managed" {
  description = "Whether Security Hub is managed by an organization administrator (delegated admin). When true, Security Hub module is skipped."
  type        = bool
  default     = false
}

variable "security_hub_disabled_controls" {
  description = "List of Security Hub control IDs to disable (e.g., S3.15, CloudFormation.4). Aligns with org-baseline disabled_controls configuration."
  type        = list(string)
  default     = []
}

# Discovery state - S3 logging bucket
variable "logging_bucket_exists" {
  description = "Whether the logging S3 bucket already exists"
  type        = bool
  default     = false
}

# Discovery state - Inspector
variable "inspector_enabled" {
  description = "Map of region to boolean indicating if Inspector is enabled"
  type        = map(bool)
  default     = {}
}

variable "inspector_resource_types" {
  description = "Map of region to list of enabled resource types"
  type        = map(list(string))
  default     = {}
}

variable "inspector_is_org_managed" {
  description = "Whether Inspector is managed by an organization delegated administrator. When true, Inspector module is skipped."
  type        = bool
  default     = false
}

# Discovery state - GuardDuty
variable "guardduty_enabled" {
  description = "Map of region to boolean indicating if GuardDuty is enabled"
  type        = map(bool)
  default     = {}
}

variable "guardduty_is_org_managed" {
  description = "Whether GuardDuty is managed by an organization delegated administrator. When true, GuardDuty module is skipped."
  type        = bool
  default     = false
}

# S3 Lifecycle settings
variable "s3_lifecycle_config_logging" {
  description = "Lifecycle settings for config/cloudtrail logging bucket"
  type = object({
    transition_to_ia_days              = number
    expiration_days                    = number
    noncurrent_version_expiration_days = number
  })
  default = {
    transition_to_ia_days              = 90
    expiration_days                    = 2555
    noncurrent_version_expiration_days = 90
  }
}

variable "s3_lifecycle_access_logging" {
  description = "Lifecycle settings for access logging bucket"
  type = object({
    transition_to_ia_days              = number
    expiration_days                    = number
    noncurrent_version_expiration_days = number
  })
  default = {
    transition_to_ia_days              = 30
    expiration_days                    = 365
    noncurrent_version_expiration_days = 30
  }
}

variable "s3_lifecycle_tfstate" {
  description = "Lifecycle settings for Terraform state bucket (transition only, no expiration)"
  type = object({
    transition_to_ia_days = number
  })
  default = {
    transition_to_ia_days = 90
  }
}

# CloudWatch Logs settings
variable "cloudwatch_logs_retention_days" {
  description = "CloudWatch Logs retention in days"
  type        = number
  default     = 365
}

# Feature flags
variable "enable_config" {
  description = "Enable AWS Config baseline"
  type        = bool
  default     = true
}

variable "enable_cloudtrail" {
  description = "Enable CloudTrail baseline"
  type        = bool
  default     = true
}

variable "enable_security_hub" {
  description = "Enable Security Hub baseline"
  type        = bool
  default     = true
}

variable "enable_inspector" {
  description = "Enable Inspector v2 baseline"
  type        = bool
  default     = true
}

variable "enable_guardduty" {
  description = "Enable GuardDuty baseline"
  type        = bool
  default     = true
}

# Alternate Contacts
variable "enable_alternate_contacts" {
  description = "Enable alternate contacts for the account"
  type        = bool
  default     = false
}

variable "billing_contact" {
  description = "Billing alternate contact details"
  type = object({
    name  = string
    title = string
    email = string
    phone = string
  })
  default = {
    name  = ""
    title = ""
    email = ""
    phone = ""
  }
}

variable "operations_contact" {
  description = "Operations alternate contact details"
  type = object({
    name  = string
    title = string
    email = string
    phone = string
  })
  default = {
    name  = ""
    title = ""
    email = ""
    phone = ""
  }
}

variable "security_contact" {
  description = "Security alternate contact details"
  type = object({
    name  = string
    title = string
    email = string
    phone = string
  })
  default = {
    name  = ""
    title = ""
    email = ""
    phone = ""
  }
}

# Tags
variable "tags" {
  description = "Tags to apply to all resources"
  type        = map(string)
  default = {
    ManagedBy = "portfolio-aws-account-baseline"
  }
}
