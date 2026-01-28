variable "vpc_block_public_access_mode" {
  description = "VPC block public access mode: ingress, bidirectional, or disabled"
  type        = string
  default     = "ingress"
}
