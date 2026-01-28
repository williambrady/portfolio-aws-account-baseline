variable "region" {
  description = "AWS region for this Security Hub deployment"
  type        = string
}

variable "is_aggregator" {
  description = "Whether this region is the finding aggregator"
  type        = bool
  default     = false
}

variable "linked_regions" {
  description = "Regions to link to this aggregator"
  type        = list(string)
  default     = []
}

variable "already_enabled" {
  description = "Whether Security Hub is already enabled in this region"
  type        = bool
  default     = false
}

variable "enabled_standards" {
  description = "List of standards already enabled"
  type        = list(string)
  default     = []
}

variable "has_aggregator" {
  description = "Whether a finding aggregator already exists"
  type        = bool
  default     = false
}

variable "disabled_controls" {
  description = "List of Security Hub control IDs to disable (e.g., S3.15, CloudFormation.4)"
  type        = list(string)
  default     = []
}
