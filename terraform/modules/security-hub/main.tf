terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# Enable Security Hub
resource "aws_securityhub_account" "main" {
  count = var.already_enabled ? 0 : 1

  enable_default_standards  = false
  auto_enable_controls      = true
  control_finding_generator = "SECURITY_CONTROL"
}

# Finding aggregator (only in aggregator region, and only if not already existing)
resource "aws_securityhub_finding_aggregator" "main" {
  count = var.is_aggregator && !var.has_aggregator ? 1 : 0

  linking_mode      = "SPECIFIED_REGIONS"
  specified_regions = var.linked_regions

  depends_on = [aws_securityhub_account.main]
}

# Standard ARNs
locals {
  region = var.region

  standard_arns = {
    "NIST-800-53" = "arn:aws:securityhub:${local.region}::standards/nist-800-53/v/5.0.0"
    "CIS"         = "arn:aws:securityhub:${local.region}::standards/cis-aws-foundations-benchmark/v/1.4.0"
    "AFSBP"       = "arn:aws:securityhub:${local.region}::standards/aws-foundational-security-best-practices/v/1.0.0"
  }

  # Determine which standards to enable
  standards_to_enable = toset([
    for std in ["NIST-800-53", "CIS", "AFSBP"] : std
    if !contains(var.enabled_standards, std)
  ])
}

# Enable NIST 800-53
resource "aws_securityhub_standards_subscription" "nist" {
  count = contains(local.standards_to_enable, "NIST-800-53") ? 1 : 0

  standards_arn = local.standard_arns["NIST-800-53"]

  depends_on = [aws_securityhub_account.main]

  timeouts {
    create = "10m"
  }
}

# Enable CIS AWS Foundations Benchmark
resource "aws_securityhub_standards_subscription" "cis" {
  count = contains(local.standards_to_enable, "CIS") ? 1 : 0

  standards_arn = local.standard_arns["CIS"]

  depends_on = [aws_securityhub_account.main]

  timeouts {
    create = "10m"
  }
}

# Enable AWS Foundational Security Best Practices
resource "aws_securityhub_standards_subscription" "afsbp" {
  count = contains(local.standards_to_enable, "AFSBP") ? 1 : 0

  standards_arn = local.standard_arns["AFSBP"]

  depends_on = [aws_securityhub_account.main]

  timeouts {
    create = "10m"
  }
}

# Disable specific controls (if any)
# With SECURITY_CONTROL mode, disabling a control in AFSBP affects all standards
locals {
  # Get the AFSBP subscription ARN - we need this to construct control ARNs
  # If AFSBP is being subscribed, use that. Otherwise, check if already enabled.
  afsbp_subscription_base = length(aws_securityhub_standards_subscription.afsbp) > 0 ? (
    replace(aws_securityhub_standards_subscription.afsbp[0].standards_arn, "standards", "control")
    ) : (
    contains(var.enabled_standards, "AFSBP") ? "arn:aws:securityhub:${var.region}::control/aws-foundational-security-best-practices/v/1.0.0" : ""
  )

  # Only create disabled controls if we have AFSBP enabled (either new or existing)
  controls_to_disable = local.afsbp_subscription_base != "" ? var.disabled_controls : []
}

resource "aws_securityhub_standards_control" "disabled" {
  for_each = toset(local.controls_to_disable)

  standards_control_arn = "${local.afsbp_subscription_base}/${each.value}"
  control_status        = "DISABLED"
  disabled_reason       = "Disabled by portfolio-aws-account-baseline configuration"

  depends_on = [
    aws_securityhub_standards_subscription.afsbp,
    aws_securityhub_standards_subscription.nist,
    aws_securityhub_standards_subscription.cis
  ]
}
