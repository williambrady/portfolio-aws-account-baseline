terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# Block public access for VPCs in this region
# Mode options:
#   - ingress: Blocks inbound internet access, allows outbound (recommended)
#   - bidirectional: Blocks both inbound and outbound internet access (most restrictive)
#   - disabled: No VPC block public access restrictions (least secure)
resource "aws_vpc_block_public_access_options" "block_public_access" {
  count = var.vpc_block_public_access_mode != "disabled" ? 1 : 0

  internet_gateway_block_mode = var.vpc_block_public_access_mode == "ingress" ? "block-ingress" : "block-bidirectional"
}
