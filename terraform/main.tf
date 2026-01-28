# Data sources
data "aws_caller_identity" "current" {}

# =============================================================================
# Global Resources (account-wide, not region-specific)
# =============================================================================

# IAM Password Policy (global - only needs to be set once)
module "iam_password_policy" {
  source = "./modules/iam-password-policy"
}

# S3 Account Block Public Access (global - only needs to be set once)
module "s3_account_block_public_access" {
  source = "./modules/s3-account-block-public-access"

  providers = {
    aws = aws.us-east-1
  }
}

# Alternate Contacts (global - only needs to be set once)
module "alternate_contacts" {
  source = "./modules/alternate-contacts"

  enable_alternate_contacts = var.enable_alternate_contacts
  billing_contact           = var.billing_contact
  operations_contact        = var.operations_contact
  security_contact          = var.security_contact
}

# =============================================================================
# S3 Buckets (created in us-east-1, used by all regions)
# =============================================================================

# S3 Access Logging bucket (must be created first)
module "s3_access_logging" {
  source = "./modules/s3-access-logging"

  bucket_name      = "${var.resource_prefix}-access-logging-${var.account_id}-us-east-1"
  account_id       = var.account_id
  resource_prefix  = var.resource_prefix
  lifecycle_config = var.s3_lifecycle_access_logging
}

locals {
  access_logging_bucket_name = module.s3_access_logging.bucket_name

  # Skip CloudTrail and Config entirely if:
  # - Control Tower is detected (manages both services)
  # - Organization trail exists (org-baseline manages CloudTrail)
  # - Config is org-managed (delivers to external account bucket)
  skip_cloudtrail_and_config = (
    var.control_tower_exists ||
    var.cloudtrail_is_org_trail ||
    var.config_is_org_managed
  )

  # Determine if we need to deploy CloudTrail (not managed by org/CT)
  deploy_cloudtrail = var.enable_cloudtrail && !local.skip_cloudtrail_and_config && !var.cloudtrail_multi_region_exists

  # Determine if we need to deploy Config in any region (not managed by org/CT)
  # If Control Tower or org-managed, skip all regions
  # Otherwise, check if any region needs Config deployed
  deploy_config = var.enable_config && !local.skip_cloudtrail_and_config && anytrue([
    for region in var.target_regions : !lookup(var.config_exists, region, false)
  ])

  # Logging bucket is only needed if we're deploying CloudTrail or Config
  # Skip entirely if org manages these services
  need_logging_bucket = !local.skip_cloudtrail_and_config && (local.deploy_cloudtrail || local.deploy_config)
}

# S3 Terraform State bucket
module "s3_tfstate" {
  source = "./modules/s3-tfstate"

  bucket_name           = "${var.resource_prefix}-tfstate-${var.account_id}"
  account_id            = var.account_id
  resource_prefix       = var.resource_prefix
  access_logging_bucket = module.s3_access_logging.bucket_name
  lifecycle_config      = var.s3_lifecycle_tfstate

  depends_on = [module.s3_access_logging]
}

# Centralized logging bucket (only if deploying CloudTrail or Config)
module "s3_logging" {
  source = "./modules/s3-logging"
  count  = local.need_logging_bucket && !var.logging_bucket_exists ? 1 : 0

  bucket_name           = "${var.resource_prefix}-security-logging-${var.account_id}-us-east-1"
  account_id            = var.account_id
  resource_prefix       = var.resource_prefix
  access_logging_bucket = local.access_logging_bucket_name
  lifecycle_config      = var.s3_lifecycle_config_logging

  depends_on = [module.s3_access_logging]
}

locals {
  # Only reference logging bucket if we're creating it or it exists
  logging_bucket_name = local.need_logging_bucket ? (
    var.logging_bucket_exists ? "${var.resource_prefix}-security-logging-${var.account_id}-us-east-1" : module.s3_logging[0].bucket_name
  ) : ""
}

# =============================================================================
# CloudTrail (global, multi-region trail)
# =============================================================================

module "cloudtrail" {
  source = "./modules/cloudtrail"
  count  = var.enable_cloudtrail && !local.skip_cloudtrail_and_config && !var.cloudtrail_multi_region_exists ? 1 : 0

  trail_name                     = "${var.resource_prefix}-trail"
  s3_bucket_name                 = local.logging_bucket_name
  s3_key_prefix                  = "cloudtrail"
  account_id                     = var.account_id
  resource_prefix                = var.resource_prefix
  cloudwatch_logs_retention_days = var.cloudwatch_logs_retention_days
}

# =============================================================================
# AWS Config - per region
# Skip if Config recorder already exists (e.g., managed by Control Tower/Org)
# =============================================================================

module "aws_config_us_east_1" {
  source                 = "./modules/aws-config"
  count                  = var.enable_config && !local.skip_cloudtrail_and_config && !lookup(var.config_exists, "us-east-1", false) ? 1 : 0
  providers              = { aws = aws.us-east-1 }
  region                 = "us-east-1"
  account_id             = var.account_id
  resource_prefix        = var.resource_prefix
  delivery_s3_bucket     = local.logging_bucket_name
  delivery_s3_key_prefix = "config"
}

module "aws_config_us_east_2" {
  source                 = "./modules/aws-config"
  count                  = var.enable_config && !local.skip_cloudtrail_and_config && !lookup(var.config_exists, "us-east-2", false) ? 1 : 0
  providers              = { aws = aws.us-east-2 }
  region                 = "us-east-2"
  account_id             = var.account_id
  resource_prefix        = var.resource_prefix
  delivery_s3_bucket     = local.logging_bucket_name
  delivery_s3_key_prefix = "config"
}

module "aws_config_us_west_1" {
  source                 = "./modules/aws-config"
  count                  = var.enable_config && !local.skip_cloudtrail_and_config && !lookup(var.config_exists, "us-west-1", false) ? 1 : 0
  providers              = { aws = aws.us-west-1 }
  region                 = "us-west-1"
  account_id             = var.account_id
  resource_prefix        = var.resource_prefix
  delivery_s3_bucket     = local.logging_bucket_name
  delivery_s3_key_prefix = "config"
}

module "aws_config_us_west_2" {
  source                 = "./modules/aws-config"
  count                  = var.enable_config && !local.skip_cloudtrail_and_config && !lookup(var.config_exists, "us-west-2", false) ? 1 : 0
  providers              = { aws = aws.us-west-2 }
  region                 = "us-west-2"
  account_id             = var.account_id
  resource_prefix        = var.resource_prefix
  delivery_s3_bucket     = local.logging_bucket_name
  delivery_s3_key_prefix = "config"
}

module "aws_config_eu_west_1" {
  source                 = "./modules/aws-config"
  count                  = var.enable_config && !local.skip_cloudtrail_and_config && !lookup(var.config_exists, "eu-west-1", false) ? 1 : 0
  providers              = { aws = aws.eu-west-1 }
  region                 = "eu-west-1"
  account_id             = var.account_id
  resource_prefix        = var.resource_prefix
  delivery_s3_bucket     = local.logging_bucket_name
  delivery_s3_key_prefix = "config"
}

module "aws_config_eu_west_2" {
  source                 = "./modules/aws-config"
  count                  = var.enable_config && !local.skip_cloudtrail_and_config && !lookup(var.config_exists, "eu-west-2", false) ? 1 : 0
  providers              = { aws = aws.eu-west-2 }
  region                 = "eu-west-2"
  account_id             = var.account_id
  resource_prefix        = var.resource_prefix
  delivery_s3_bucket     = local.logging_bucket_name
  delivery_s3_key_prefix = "config"
}

module "aws_config_eu_west_3" {
  source                 = "./modules/aws-config"
  count                  = var.enable_config && !local.skip_cloudtrail_and_config && !lookup(var.config_exists, "eu-west-3", false) ? 1 : 0
  providers              = { aws = aws.eu-west-3 }
  region                 = "eu-west-3"
  account_id             = var.account_id
  resource_prefix        = var.resource_prefix
  delivery_s3_bucket     = local.logging_bucket_name
  delivery_s3_key_prefix = "config"
}

module "aws_config_eu_central_1" {
  source                 = "./modules/aws-config"
  count                  = var.enable_config && !local.skip_cloudtrail_and_config && !lookup(var.config_exists, "eu-central-1", false) ? 1 : 0
  providers              = { aws = aws.eu-central-1 }
  region                 = "eu-central-1"
  account_id             = var.account_id
  resource_prefix        = var.resource_prefix
  delivery_s3_bucket     = local.logging_bucket_name
  delivery_s3_key_prefix = "config"
}

module "aws_config_eu_north_1" {
  source                 = "./modules/aws-config"
  count                  = var.enable_config && !local.skip_cloudtrail_and_config && !lookup(var.config_exists, "eu-north-1", false) ? 1 : 0
  providers              = { aws = aws.eu-north-1 }
  region                 = "eu-north-1"
  account_id             = var.account_id
  resource_prefix        = var.resource_prefix
  delivery_s3_bucket     = local.logging_bucket_name
  delivery_s3_key_prefix = "config"
}

module "aws_config_ap_southeast_1" {
  source                 = "./modules/aws-config"
  count                  = var.enable_config && !local.skip_cloudtrail_and_config && !lookup(var.config_exists, "ap-southeast-1", false) ? 1 : 0
  providers              = { aws = aws.ap-southeast-1 }
  region                 = "ap-southeast-1"
  account_id             = var.account_id
  resource_prefix        = var.resource_prefix
  delivery_s3_bucket     = local.logging_bucket_name
  delivery_s3_key_prefix = "config"
}

module "aws_config_ap_southeast_2" {
  source                 = "./modules/aws-config"
  count                  = var.enable_config && !local.skip_cloudtrail_and_config && !lookup(var.config_exists, "ap-southeast-2", false) ? 1 : 0
  providers              = { aws = aws.ap-southeast-2 }
  region                 = "ap-southeast-2"
  account_id             = var.account_id
  resource_prefix        = var.resource_prefix
  delivery_s3_bucket     = local.logging_bucket_name
  delivery_s3_key_prefix = "config"
}

module "aws_config_ap_northeast_1" {
  source                 = "./modules/aws-config"
  count                  = var.enable_config && !local.skip_cloudtrail_and_config && !lookup(var.config_exists, "ap-northeast-1", false) ? 1 : 0
  providers              = { aws = aws.ap-northeast-1 }
  region                 = "ap-northeast-1"
  account_id             = var.account_id
  resource_prefix        = var.resource_prefix
  delivery_s3_bucket     = local.logging_bucket_name
  delivery_s3_key_prefix = "config"
}

module "aws_config_ap_northeast_2" {
  source                 = "./modules/aws-config"
  count                  = var.enable_config && !local.skip_cloudtrail_and_config && !lookup(var.config_exists, "ap-northeast-2", false) ? 1 : 0
  providers              = { aws = aws.ap-northeast-2 }
  region                 = "ap-northeast-2"
  account_id             = var.account_id
  resource_prefix        = var.resource_prefix
  delivery_s3_bucket     = local.logging_bucket_name
  delivery_s3_key_prefix = "config"
}

module "aws_config_ap_northeast_3" {
  source                 = "./modules/aws-config"
  count                  = var.enable_config && !local.skip_cloudtrail_and_config && !lookup(var.config_exists, "ap-northeast-3", false) ? 1 : 0
  providers              = { aws = aws.ap-northeast-3 }
  region                 = "ap-northeast-3"
  account_id             = var.account_id
  resource_prefix        = var.resource_prefix
  delivery_s3_bucket     = local.logging_bucket_name
  delivery_s3_key_prefix = "config"
}

module "aws_config_ap_south_1" {
  source                 = "./modules/aws-config"
  count                  = var.enable_config && !local.skip_cloudtrail_and_config && !lookup(var.config_exists, "ap-south-1", false) ? 1 : 0
  providers              = { aws = aws.ap-south-1 }
  region                 = "ap-south-1"
  account_id             = var.account_id
  resource_prefix        = var.resource_prefix
  delivery_s3_bucket     = local.logging_bucket_name
  delivery_s3_key_prefix = "config"
}

module "aws_config_ca_central_1" {
  source                 = "./modules/aws-config"
  count                  = var.enable_config && !local.skip_cloudtrail_and_config && !lookup(var.config_exists, "ca-central-1", false) ? 1 : 0
  providers              = { aws = aws.ca-central-1 }
  region                 = "ca-central-1"
  account_id             = var.account_id
  resource_prefix        = var.resource_prefix
  delivery_s3_bucket     = local.logging_bucket_name
  delivery_s3_key_prefix = "config"
}

module "aws_config_sa_east_1" {
  source                 = "./modules/aws-config"
  count                  = var.enable_config && !local.skip_cloudtrail_and_config && !lookup(var.config_exists, "sa-east-1", false) ? 1 : 0
  providers              = { aws = aws.sa-east-1 }
  region                 = "sa-east-1"
  account_id             = var.account_id
  resource_prefix        = var.resource_prefix
  delivery_s3_bucket     = local.logging_bucket_name
  delivery_s3_key_prefix = "config"
}

# =============================================================================
# Security Hub - per region
# us-east-1 is the aggregator, linked to all other regions
# Skip entirely if org-managed (delegated administrator handles configuration)
# =============================================================================

module "security_hub_us_east_1" {
  source            = "./modules/security-hub"
  count             = var.enable_security_hub && !var.security_hub_is_org_managed ? 1 : 0
  providers         = { aws = aws.us-east-1 }
  region            = "us-east-1"
  is_aggregator     = true
  linked_regions    = ["us-east-2", "us-west-1", "us-west-2", "eu-west-1", "eu-west-2", "eu-west-3", "eu-central-1", "eu-north-1", "ap-southeast-1", "ap-southeast-2", "ap-northeast-1", "ap-northeast-2", "ap-northeast-3", "ap-south-1", "ca-central-1", "sa-east-1"]
  already_enabled   = lookup(var.security_hub_enabled, "us-east-1", false)
  enabled_standards = lookup(var.security_hub_standards, "us-east-1", [])
  has_aggregator    = var.security_hub_has_aggregator
  disabled_controls = var.security_hub_disabled_controls
}

module "security_hub_us_east_2" {
  source            = "./modules/security-hub"
  count             = var.enable_security_hub && !var.security_hub_is_org_managed ? 1 : 0
  providers         = { aws = aws.us-east-2 }
  region            = "us-east-2"
  is_aggregator     = false
  linked_regions    = []
  already_enabled   = lookup(var.security_hub_enabled, "us-east-2", false)
  enabled_standards = lookup(var.security_hub_standards, "us-east-2", [])
  disabled_controls = var.security_hub_disabled_controls
  depends_on        = [module.security_hub_us_east_1]
}

module "security_hub_us_west_1" {
  source            = "./modules/security-hub"
  count             = var.enable_security_hub && !var.security_hub_is_org_managed ? 1 : 0
  providers         = { aws = aws.us-west-1 }
  region            = "us-west-1"
  is_aggregator     = false
  linked_regions    = []
  already_enabled   = lookup(var.security_hub_enabled, "us-west-1", false)
  enabled_standards = lookup(var.security_hub_standards, "us-west-1", [])
  disabled_controls = var.security_hub_disabled_controls
  depends_on        = [module.security_hub_us_east_1]
}

module "security_hub_us_west_2" {
  source            = "./modules/security-hub"
  count             = var.enable_security_hub && !var.security_hub_is_org_managed ? 1 : 0
  providers         = { aws = aws.us-west-2 }
  region            = "us-west-2"
  is_aggregator     = false
  linked_regions    = []
  already_enabled   = lookup(var.security_hub_enabled, "us-west-2", false)
  enabled_standards = lookup(var.security_hub_standards, "us-west-2", [])
  disabled_controls = var.security_hub_disabled_controls
  depends_on        = [module.security_hub_us_east_1]
}

module "security_hub_eu_west_1" {
  source            = "./modules/security-hub"
  count             = var.enable_security_hub && !var.security_hub_is_org_managed ? 1 : 0
  providers         = { aws = aws.eu-west-1 }
  region            = "eu-west-1"
  is_aggregator     = false
  linked_regions    = []
  already_enabled   = lookup(var.security_hub_enabled, "eu-west-1", false)
  enabled_standards = lookup(var.security_hub_standards, "eu-west-1", [])
  disabled_controls = var.security_hub_disabled_controls
  depends_on        = [module.security_hub_us_east_1]
}

module "security_hub_eu_west_2" {
  source            = "./modules/security-hub"
  count             = var.enable_security_hub && !var.security_hub_is_org_managed ? 1 : 0
  providers         = { aws = aws.eu-west-2 }
  region            = "eu-west-2"
  is_aggregator     = false
  linked_regions    = []
  already_enabled   = lookup(var.security_hub_enabled, "eu-west-2", false)
  enabled_standards = lookup(var.security_hub_standards, "eu-west-2", [])
  disabled_controls = var.security_hub_disabled_controls
  depends_on        = [module.security_hub_us_east_1]
}

module "security_hub_eu_west_3" {
  source            = "./modules/security-hub"
  count             = var.enable_security_hub && !var.security_hub_is_org_managed ? 1 : 0
  providers         = { aws = aws.eu-west-3 }
  region            = "eu-west-3"
  is_aggregator     = false
  linked_regions    = []
  already_enabled   = lookup(var.security_hub_enabled, "eu-west-3", false)
  enabled_standards = lookup(var.security_hub_standards, "eu-west-3", [])
  disabled_controls = var.security_hub_disabled_controls
  depends_on        = [module.security_hub_us_east_1]
}

module "security_hub_eu_central_1" {
  source            = "./modules/security-hub"
  count             = var.enable_security_hub && !var.security_hub_is_org_managed ? 1 : 0
  providers         = { aws = aws.eu-central-1 }
  region            = "eu-central-1"
  is_aggregator     = false
  linked_regions    = []
  already_enabled   = lookup(var.security_hub_enabled, "eu-central-1", false)
  enabled_standards = lookup(var.security_hub_standards, "eu-central-1", [])
  disabled_controls = var.security_hub_disabled_controls
  depends_on        = [module.security_hub_us_east_1]
}

module "security_hub_eu_north_1" {
  source            = "./modules/security-hub"
  count             = var.enable_security_hub && !var.security_hub_is_org_managed ? 1 : 0
  providers         = { aws = aws.eu-north-1 }
  region            = "eu-north-1"
  is_aggregator     = false
  linked_regions    = []
  already_enabled   = lookup(var.security_hub_enabled, "eu-north-1", false)
  enabled_standards = lookup(var.security_hub_standards, "eu-north-1", [])
  disabled_controls = var.security_hub_disabled_controls
  depends_on        = [module.security_hub_us_east_1]
}

module "security_hub_ap_southeast_1" {
  source            = "./modules/security-hub"
  count             = var.enable_security_hub && !var.security_hub_is_org_managed ? 1 : 0
  providers         = { aws = aws.ap-southeast-1 }
  region            = "ap-southeast-1"
  is_aggregator     = false
  linked_regions    = []
  already_enabled   = lookup(var.security_hub_enabled, "ap-southeast-1", false)
  enabled_standards = lookup(var.security_hub_standards, "ap-southeast-1", [])
  disabled_controls = var.security_hub_disabled_controls
  depends_on        = [module.security_hub_us_east_1]
}

module "security_hub_ap_southeast_2" {
  source            = "./modules/security-hub"
  count             = var.enable_security_hub && !var.security_hub_is_org_managed ? 1 : 0
  providers         = { aws = aws.ap-southeast-2 }
  region            = "ap-southeast-2"
  is_aggregator     = false
  linked_regions    = []
  already_enabled   = lookup(var.security_hub_enabled, "ap-southeast-2", false)
  enabled_standards = lookup(var.security_hub_standards, "ap-southeast-2", [])
  disabled_controls = var.security_hub_disabled_controls
  depends_on        = [module.security_hub_us_east_1]
}

module "security_hub_ap_northeast_1" {
  source            = "./modules/security-hub"
  count             = var.enable_security_hub && !var.security_hub_is_org_managed ? 1 : 0
  providers         = { aws = aws.ap-northeast-1 }
  region            = "ap-northeast-1"
  is_aggregator     = false
  linked_regions    = []
  already_enabled   = lookup(var.security_hub_enabled, "ap-northeast-1", false)
  enabled_standards = lookup(var.security_hub_standards, "ap-northeast-1", [])
  disabled_controls = var.security_hub_disabled_controls
  depends_on        = [module.security_hub_us_east_1]
}

module "security_hub_ap_northeast_2" {
  source            = "./modules/security-hub"
  count             = var.enable_security_hub && !var.security_hub_is_org_managed ? 1 : 0
  providers         = { aws = aws.ap-northeast-2 }
  region            = "ap-northeast-2"
  is_aggregator     = false
  linked_regions    = []
  already_enabled   = lookup(var.security_hub_enabled, "ap-northeast-2", false)
  enabled_standards = lookup(var.security_hub_standards, "ap-northeast-2", [])
  disabled_controls = var.security_hub_disabled_controls
  depends_on        = [module.security_hub_us_east_1]
}

module "security_hub_ap_northeast_3" {
  source            = "./modules/security-hub"
  count             = var.enable_security_hub && !var.security_hub_is_org_managed ? 1 : 0
  providers         = { aws = aws.ap-northeast-3 }
  region            = "ap-northeast-3"
  is_aggregator     = false
  linked_regions    = []
  already_enabled   = lookup(var.security_hub_enabled, "ap-northeast-3", false)
  enabled_standards = lookup(var.security_hub_standards, "ap-northeast-3", [])
  disabled_controls = var.security_hub_disabled_controls
  depends_on        = [module.security_hub_us_east_1]
}

module "security_hub_ap_south_1" {
  source            = "./modules/security-hub"
  count             = var.enable_security_hub && !var.security_hub_is_org_managed ? 1 : 0
  providers         = { aws = aws.ap-south-1 }
  region            = "ap-south-1"
  is_aggregator     = false
  linked_regions    = []
  already_enabled   = lookup(var.security_hub_enabled, "ap-south-1", false)
  enabled_standards = lookup(var.security_hub_standards, "ap-south-1", [])
  disabled_controls = var.security_hub_disabled_controls
  depends_on        = [module.security_hub_us_east_1]
}

module "security_hub_ca_central_1" {
  source            = "./modules/security-hub"
  count             = var.enable_security_hub && !var.security_hub_is_org_managed ? 1 : 0
  providers         = { aws = aws.ca-central-1 }
  region            = "ca-central-1"
  is_aggregator     = false
  linked_regions    = []
  already_enabled   = lookup(var.security_hub_enabled, "ca-central-1", false)
  enabled_standards = lookup(var.security_hub_standards, "ca-central-1", [])
  disabled_controls = var.security_hub_disabled_controls
  depends_on        = [module.security_hub_us_east_1]
}

module "security_hub_sa_east_1" {
  source            = "./modules/security-hub"
  count             = var.enable_security_hub && !var.security_hub_is_org_managed ? 1 : 0
  providers         = { aws = aws.sa-east-1 }
  region            = "sa-east-1"
  is_aggregator     = false
  linked_regions    = []
  already_enabled   = lookup(var.security_hub_enabled, "sa-east-1", false)
  enabled_standards = lookup(var.security_hub_standards, "sa-east-1", [])
  disabled_controls = var.security_hub_disabled_controls
  depends_on        = [module.security_hub_us_east_1]
}

# =============================================================================
# Inspector v2 - per region
# Skip entirely if org-managed (delegated administrator handles configuration)
# =============================================================================

module "inspector_us_east_1" {
  source = "./modules/inspector-v2"
  count  = var.enable_inspector && !var.inspector_is_org_managed ? 1 : 0
  # Note: We don't check inspector_enabled because Terraform needs to continue managing
  # resources it created. The org-managed check is sufficient to skip external management.
  # Original pattern preserved for reference: !lookup(var.inspector_enabled, "us-east-1", false) ? 1 : 0
  providers  = { aws = aws.us-east-1 }
  depends_on = [module.security_hub_us_east_1]
}

module "inspector_us_east_2" {
  source = "./modules/inspector-v2"
  count  = var.enable_inspector && !var.inspector_is_org_managed ? 1 : 0
  # Note: We don't check inspector_enabled because Terraform needs to continue managing
  # resources it created. The org-managed check is sufficient to skip external management.
  # Original pattern preserved for reference: !lookup(var.inspector_enabled, "us-east-2", false) ? 1 : 0
  providers  = { aws = aws.us-east-2 }
  depends_on = [module.security_hub_us_east_2]
}

module "inspector_us_west_1" {
  source = "./modules/inspector-v2"
  count  = var.enable_inspector && !var.inspector_is_org_managed ? 1 : 0
  # Note: We don't check inspector_enabled because Terraform needs to continue managing
  # resources it created. The org-managed check is sufficient to skip external management.
  # Original pattern preserved for reference: !lookup(var.inspector_enabled, "us-west-1", false) ? 1 : 0
  providers  = { aws = aws.us-west-1 }
  depends_on = [module.security_hub_us_west_1]
}

module "inspector_us_west_2" {
  source = "./modules/inspector-v2"
  count  = var.enable_inspector && !var.inspector_is_org_managed ? 1 : 0
  # Note: We don't check inspector_enabled because Terraform needs to continue managing
  # resources it created. The org-managed check is sufficient to skip external management.
  # Original pattern preserved for reference: !lookup(var.inspector_enabled, "us-west-2", false) ? 1 : 0
  providers  = { aws = aws.us-west-2 }
  depends_on = [module.security_hub_us_west_2]
}

module "inspector_eu_west_1" {
  source = "./modules/inspector-v2"
  count  = var.enable_inspector && !var.inspector_is_org_managed ? 1 : 0
  # Note: We don't check inspector_enabled because Terraform needs to continue managing
  # resources it created. The org-managed check is sufficient to skip external management.
  # Original pattern preserved for reference: !lookup(var.inspector_enabled, "eu-west-1", false) ? 1 : 0
  providers  = { aws = aws.eu-west-1 }
  depends_on = [module.security_hub_eu_west_1]
}

module "inspector_eu_west_2" {
  source = "./modules/inspector-v2"
  count  = var.enable_inspector && !var.inspector_is_org_managed ? 1 : 0
  # Note: We don't check inspector_enabled because Terraform needs to continue managing
  # resources it created. The org-managed check is sufficient to skip external management.
  # Original pattern preserved for reference: !lookup(var.inspector_enabled, "eu-west-2", false) ? 1 : 0
  providers  = { aws = aws.eu-west-2 }
  depends_on = [module.security_hub_eu_west_2]
}

module "inspector_eu_west_3" {
  source = "./modules/inspector-v2"
  count  = var.enable_inspector && !var.inspector_is_org_managed ? 1 : 0
  # Note: We don't check inspector_enabled because Terraform needs to continue managing
  # resources it created. The org-managed check is sufficient to skip external management.
  # Original pattern preserved for reference: !lookup(var.inspector_enabled, "eu-west-3", false) ? 1 : 0
  providers  = { aws = aws.eu-west-3 }
  depends_on = [module.security_hub_eu_west_3]
}

module "inspector_eu_central_1" {
  source = "./modules/inspector-v2"
  count  = var.enable_inspector && !var.inspector_is_org_managed ? 1 : 0
  # Note: We don't check inspector_enabled because Terraform needs to continue managing
  # resources it created. The org-managed check is sufficient to skip external management.
  # Original pattern preserved for reference: !lookup(var.inspector_enabled, "eu-central-1", false) ? 1 : 0
  providers  = { aws = aws.eu-central-1 }
  depends_on = [module.security_hub_eu_central_1]
}

module "inspector_eu_north_1" {
  source = "./modules/inspector-v2"
  count  = var.enable_inspector && !var.inspector_is_org_managed ? 1 : 0
  # Note: We don't check inspector_enabled because Terraform needs to continue managing
  # resources it created. The org-managed check is sufficient to skip external management.
  # Original pattern preserved for reference: !lookup(var.inspector_enabled, "eu-north-1", false) ? 1 : 0
  providers  = { aws = aws.eu-north-1 }
  depends_on = [module.security_hub_eu_north_1]
}

module "inspector_ap_southeast_1" {
  source = "./modules/inspector-v2"
  count  = var.enable_inspector && !var.inspector_is_org_managed ? 1 : 0
  # Note: We don't check inspector_enabled because Terraform needs to continue managing
  # resources it created. The org-managed check is sufficient to skip external management.
  # Original pattern preserved for reference: !lookup(var.inspector_enabled, "ap-southeast-1", false) ? 1 : 0
  providers  = { aws = aws.ap-southeast-1 }
  depends_on = [module.security_hub_ap_southeast_1]
}

module "inspector_ap_southeast_2" {
  source = "./modules/inspector-v2"
  count  = var.enable_inspector && !var.inspector_is_org_managed ? 1 : 0
  # Note: We don't check inspector_enabled because Terraform needs to continue managing
  # resources it created. The org-managed check is sufficient to skip external management.
  # Original pattern preserved for reference: !lookup(var.inspector_enabled, "ap-southeast-2", false) ? 1 : 0
  providers  = { aws = aws.ap-southeast-2 }
  depends_on = [module.security_hub_ap_southeast_2]
}

module "inspector_ap_northeast_1" {
  source = "./modules/inspector-v2"
  count  = var.enable_inspector && !var.inspector_is_org_managed ? 1 : 0
  # Note: We don't check inspector_enabled because Terraform needs to continue managing
  # resources it created. The org-managed check is sufficient to skip external management.
  # Original pattern preserved for reference: !lookup(var.inspector_enabled, "ap-northeast-1", false) ? 1 : 0
  providers  = { aws = aws.ap-northeast-1 }
  depends_on = [module.security_hub_ap_northeast_1]
}

module "inspector_ap_northeast_2" {
  source = "./modules/inspector-v2"
  count  = var.enable_inspector && !var.inspector_is_org_managed ? 1 : 0
  # Note: We don't check inspector_enabled because Terraform needs to continue managing
  # resources it created. The org-managed check is sufficient to skip external management.
  # Original pattern preserved for reference: !lookup(var.inspector_enabled, "ap-northeast-2", false) ? 1 : 0
  providers  = { aws = aws.ap-northeast-2 }
  depends_on = [module.security_hub_ap_northeast_2]
}

module "inspector_ap_northeast_3" {
  source = "./modules/inspector-v2"
  count  = var.enable_inspector && !var.inspector_is_org_managed ? 1 : 0
  # Note: We don't check inspector_enabled because Terraform needs to continue managing
  # resources it created. The org-managed check is sufficient to skip external management.
  # Original pattern preserved for reference: !lookup(var.inspector_enabled, "ap-northeast-3", false) ? 1 : 0
  providers  = { aws = aws.ap-northeast-3 }
  depends_on = [module.security_hub_ap_northeast_3]
}

module "inspector_ap_south_1" {
  source = "./modules/inspector-v2"
  count  = var.enable_inspector && !var.inspector_is_org_managed ? 1 : 0
  # Note: We don't check inspector_enabled because Terraform needs to continue managing
  # resources it created. The org-managed check is sufficient to skip external management.
  # Original pattern preserved for reference: !lookup(var.inspector_enabled, "ap-south-1", false) ? 1 : 0
  providers  = { aws = aws.ap-south-1 }
  depends_on = [module.security_hub_ap_south_1]
}

module "inspector_ca_central_1" {
  source = "./modules/inspector-v2"
  count  = var.enable_inspector && !var.inspector_is_org_managed ? 1 : 0
  # Note: We don't check inspector_enabled because Terraform needs to continue managing
  # resources it created. The org-managed check is sufficient to skip external management.
  # Original pattern preserved for reference: !lookup(var.inspector_enabled, "ca-central-1", false) ? 1 : 0
  providers  = { aws = aws.ca-central-1 }
  depends_on = [module.security_hub_ca_central_1]
}

module "inspector_sa_east_1" {
  source = "./modules/inspector-v2"
  count  = var.enable_inspector && !var.inspector_is_org_managed ? 1 : 0
  # Note: We don't check inspector_enabled because Terraform needs to continue managing
  # resources it created. The org-managed check is sufficient to skip external management.
  # Original pattern preserved for reference: !lookup(var.inspector_enabled, "sa-east-1", false) ? 1 : 0
  providers  = { aws = aws.sa-east-1 }
  depends_on = [module.security_hub_sa_east_1]
}

# =============================================================================
# SSM Settings - per region
# - Blocks public sharing of SSM documents
# - Enables CloudWatch logging for SSM Automation (SSM.6 compliance)
# - Creates KMS key for CloudWatch log encryption
# - CloudWatch Log Group with 365-day retention
# =============================================================================

module "ssm_us_east_1" {
  source          = "./modules/ssm-settings"
  providers       = { aws = aws.us-east-1 }
  resource_prefix = var.resource_prefix
}

module "ssm_us_east_2" {
  source          = "./modules/ssm-settings"
  providers       = { aws = aws.us-east-2 }
  resource_prefix = var.resource_prefix
}

module "ssm_us_west_1" {
  source          = "./modules/ssm-settings"
  providers       = { aws = aws.us-west-1 }
  resource_prefix = var.resource_prefix
}

module "ssm_us_west_2" {
  source          = "./modules/ssm-settings"
  providers       = { aws = aws.us-west-2 }
  resource_prefix = var.resource_prefix
}

module "ssm_eu_west_1" {
  source          = "./modules/ssm-settings"
  providers       = { aws = aws.eu-west-1 }
  resource_prefix = var.resource_prefix
}

module "ssm_eu_west_2" {
  source          = "./modules/ssm-settings"
  providers       = { aws = aws.eu-west-2 }
  resource_prefix = var.resource_prefix
}

module "ssm_eu_west_3" {
  source          = "./modules/ssm-settings"
  providers       = { aws = aws.eu-west-3 }
  resource_prefix = var.resource_prefix
}

module "ssm_eu_central_1" {
  source          = "./modules/ssm-settings"
  providers       = { aws = aws.eu-central-1 }
  resource_prefix = var.resource_prefix
}

module "ssm_eu_north_1" {
  source          = "./modules/ssm-settings"
  providers       = { aws = aws.eu-north-1 }
  resource_prefix = var.resource_prefix
}

module "ssm_ap_southeast_1" {
  source          = "./modules/ssm-settings"
  providers       = { aws = aws.ap-southeast-1 }
  resource_prefix = var.resource_prefix
}

module "ssm_ap_southeast_2" {
  source          = "./modules/ssm-settings"
  providers       = { aws = aws.ap-southeast-2 }
  resource_prefix = var.resource_prefix
}

module "ssm_ap_northeast_1" {
  source          = "./modules/ssm-settings"
  providers       = { aws = aws.ap-northeast-1 }
  resource_prefix = var.resource_prefix
}

module "ssm_ap_northeast_2" {
  source          = "./modules/ssm-settings"
  providers       = { aws = aws.ap-northeast-2 }
  resource_prefix = var.resource_prefix
}

module "ssm_ap_northeast_3" {
  source          = "./modules/ssm-settings"
  providers       = { aws = aws.ap-northeast-3 }
  resource_prefix = var.resource_prefix
}

module "ssm_ap_south_1" {
  source          = "./modules/ssm-settings"
  providers       = { aws = aws.ap-south-1 }
  resource_prefix = var.resource_prefix
}

module "ssm_ca_central_1" {
  source          = "./modules/ssm-settings"
  providers       = { aws = aws.ca-central-1 }
  resource_prefix = var.resource_prefix
}

module "ssm_sa_east_1" {
  source          = "./modules/ssm-settings"
  providers       = { aws = aws.sa-east-1 }
  resource_prefix = var.resource_prefix
}

# =============================================================================
# EC2 Defaults (EBS encryption, snapshot blocking, IMDS) - per region
# =============================================================================

module "ec2_defaults_us_east_1" {
  source    = "./modules/ec2-defaults"
  providers = { aws = aws.us-east-1 }
}

module "ec2_defaults_us_east_2" {
  source    = "./modules/ec2-defaults"
  providers = { aws = aws.us-east-2 }
}

module "ec2_defaults_us_west_1" {
  source    = "./modules/ec2-defaults"
  providers = { aws = aws.us-west-1 }
}

module "ec2_defaults_us_west_2" {
  source    = "./modules/ec2-defaults"
  providers = { aws = aws.us-west-2 }
}

module "ec2_defaults_eu_west_1" {
  source    = "./modules/ec2-defaults"
  providers = { aws = aws.eu-west-1 }
}

module "ec2_defaults_eu_west_2" {
  source    = "./modules/ec2-defaults"
  providers = { aws = aws.eu-west-2 }
}

module "ec2_defaults_eu_west_3" {
  source    = "./modules/ec2-defaults"
  providers = { aws = aws.eu-west-3 }
}

module "ec2_defaults_eu_central_1" {
  source    = "./modules/ec2-defaults"
  providers = { aws = aws.eu-central-1 }
}

module "ec2_defaults_eu_north_1" {
  source    = "./modules/ec2-defaults"
  providers = { aws = aws.eu-north-1 }
}

module "ec2_defaults_ap_southeast_1" {
  source    = "./modules/ec2-defaults"
  providers = { aws = aws.ap-southeast-1 }
}

module "ec2_defaults_ap_southeast_2" {
  source    = "./modules/ec2-defaults"
  providers = { aws = aws.ap-southeast-2 }
}

module "ec2_defaults_ap_northeast_1" {
  source    = "./modules/ec2-defaults"
  providers = { aws = aws.ap-northeast-1 }
}

module "ec2_defaults_ap_northeast_2" {
  source    = "./modules/ec2-defaults"
  providers = { aws = aws.ap-northeast-2 }
}

module "ec2_defaults_ap_northeast_3" {
  source    = "./modules/ec2-defaults"
  providers = { aws = aws.ap-northeast-3 }
}

module "ec2_defaults_ap_south_1" {
  source    = "./modules/ec2-defaults"
  providers = { aws = aws.ap-south-1 }
}

module "ec2_defaults_ca_central_1" {
  source    = "./modules/ec2-defaults"
  providers = { aws = aws.ca-central-1 }
}

module "ec2_defaults_sa_east_1" {
  source    = "./modules/ec2-defaults"
  providers = { aws = aws.sa-east-1 }
}

# =============================================================================
# VPC Defaults (Block Public Access) - per region
# =============================================================================

module "vpc_defaults_us_east_1" {
  source                       = "./modules/vpc-defaults"
  providers                    = { aws = aws.us-east-1 }
  vpc_block_public_access_mode = var.vpc_block_public_access_mode
}

module "vpc_defaults_us_east_2" {
  source                       = "./modules/vpc-defaults"
  providers                    = { aws = aws.us-east-2 }
  vpc_block_public_access_mode = var.vpc_block_public_access_mode
}

module "vpc_defaults_us_west_1" {
  source                       = "./modules/vpc-defaults"
  providers                    = { aws = aws.us-west-1 }
  vpc_block_public_access_mode = var.vpc_block_public_access_mode
}

module "vpc_defaults_us_west_2" {
  source                       = "./modules/vpc-defaults"
  providers                    = { aws = aws.us-west-2 }
  vpc_block_public_access_mode = var.vpc_block_public_access_mode
}

module "vpc_defaults_eu_west_1" {
  source                       = "./modules/vpc-defaults"
  providers                    = { aws = aws.eu-west-1 }
  vpc_block_public_access_mode = var.vpc_block_public_access_mode
}

module "vpc_defaults_eu_west_2" {
  source                       = "./modules/vpc-defaults"
  providers                    = { aws = aws.eu-west-2 }
  vpc_block_public_access_mode = var.vpc_block_public_access_mode
}

module "vpc_defaults_eu_west_3" {
  source                       = "./modules/vpc-defaults"
  providers                    = { aws = aws.eu-west-3 }
  vpc_block_public_access_mode = var.vpc_block_public_access_mode
}

module "vpc_defaults_eu_central_1" {
  source                       = "./modules/vpc-defaults"
  providers                    = { aws = aws.eu-central-1 }
  vpc_block_public_access_mode = var.vpc_block_public_access_mode
}

module "vpc_defaults_eu_north_1" {
  source                       = "./modules/vpc-defaults"
  providers                    = { aws = aws.eu-north-1 }
  vpc_block_public_access_mode = var.vpc_block_public_access_mode
}

module "vpc_defaults_ap_southeast_1" {
  source                       = "./modules/vpc-defaults"
  providers                    = { aws = aws.ap-southeast-1 }
  vpc_block_public_access_mode = var.vpc_block_public_access_mode
}

module "vpc_defaults_ap_southeast_2" {
  source                       = "./modules/vpc-defaults"
  providers                    = { aws = aws.ap-southeast-2 }
  vpc_block_public_access_mode = var.vpc_block_public_access_mode
}

module "vpc_defaults_ap_northeast_1" {
  source                       = "./modules/vpc-defaults"
  providers                    = { aws = aws.ap-northeast-1 }
  vpc_block_public_access_mode = var.vpc_block_public_access_mode
}

module "vpc_defaults_ap_northeast_2" {
  source                       = "./modules/vpc-defaults"
  providers                    = { aws = aws.ap-northeast-2 }
  vpc_block_public_access_mode = var.vpc_block_public_access_mode
}

module "vpc_defaults_ap_northeast_3" {
  source                       = "./modules/vpc-defaults"
  providers                    = { aws = aws.ap-northeast-3 }
  vpc_block_public_access_mode = var.vpc_block_public_access_mode
}

module "vpc_defaults_ap_south_1" {
  source                       = "./modules/vpc-defaults"
  providers                    = { aws = aws.ap-south-1 }
  vpc_block_public_access_mode = var.vpc_block_public_access_mode
}

module "vpc_defaults_ca_central_1" {
  source                       = "./modules/vpc-defaults"
  providers                    = { aws = aws.ca-central-1 }
  vpc_block_public_access_mode = var.vpc_block_public_access_mode
}

module "vpc_defaults_sa_east_1" {
  source                       = "./modules/vpc-defaults"
  providers                    = { aws = aws.sa-east-1 }
  vpc_block_public_access_mode = var.vpc_block_public_access_mode
}

# =============================================================================
# GuardDuty - per region
# Skip entirely if org-managed (delegated administrator handles configuration)
# =============================================================================

module "guardduty_us_east_1" {
  source    = "./modules/guardduty"
  count     = var.enable_guardduty && !var.guardduty_is_org_managed ? 1 : 0
  providers = { aws = aws.us-east-1 }
}

module "guardduty_us_east_2" {
  source    = "./modules/guardduty"
  count     = var.enable_guardduty && !var.guardduty_is_org_managed ? 1 : 0
  providers = { aws = aws.us-east-2 }
}

module "guardduty_us_west_1" {
  source    = "./modules/guardduty"
  count     = var.enable_guardduty && !var.guardduty_is_org_managed ? 1 : 0
  providers = { aws = aws.us-west-1 }
}

module "guardduty_us_west_2" {
  source    = "./modules/guardduty"
  count     = var.enable_guardduty && !var.guardduty_is_org_managed ? 1 : 0
  providers = { aws = aws.us-west-2 }
}

module "guardduty_eu_west_1" {
  source    = "./modules/guardduty"
  count     = var.enable_guardduty && !var.guardduty_is_org_managed ? 1 : 0
  providers = { aws = aws.eu-west-1 }
}

module "guardduty_eu_west_2" {
  source    = "./modules/guardduty"
  count     = var.enable_guardduty && !var.guardduty_is_org_managed ? 1 : 0
  providers = { aws = aws.eu-west-2 }
}

module "guardduty_eu_west_3" {
  source    = "./modules/guardduty"
  count     = var.enable_guardduty && !var.guardduty_is_org_managed ? 1 : 0
  providers = { aws = aws.eu-west-3 }
}

module "guardduty_eu_central_1" {
  source    = "./modules/guardduty"
  count     = var.enable_guardduty && !var.guardduty_is_org_managed ? 1 : 0
  providers = { aws = aws.eu-central-1 }
}

module "guardduty_eu_north_1" {
  source    = "./modules/guardduty"
  count     = var.enable_guardduty && !var.guardduty_is_org_managed ? 1 : 0
  providers = { aws = aws.eu-north-1 }
}

module "guardduty_ap_southeast_1" {
  source    = "./modules/guardduty"
  count     = var.enable_guardduty && !var.guardduty_is_org_managed ? 1 : 0
  providers = { aws = aws.ap-southeast-1 }
}

module "guardduty_ap_southeast_2" {
  source    = "./modules/guardduty"
  count     = var.enable_guardduty && !var.guardduty_is_org_managed ? 1 : 0
  providers = { aws = aws.ap-southeast-2 }
}

module "guardduty_ap_northeast_1" {
  source    = "./modules/guardduty"
  count     = var.enable_guardduty && !var.guardduty_is_org_managed ? 1 : 0
  providers = { aws = aws.ap-northeast-1 }
}

module "guardduty_ap_northeast_2" {
  source    = "./modules/guardduty"
  count     = var.enable_guardduty && !var.guardduty_is_org_managed ? 1 : 0
  providers = { aws = aws.ap-northeast-2 }
}

module "guardduty_ap_northeast_3" {
  source    = "./modules/guardduty"
  count     = var.enable_guardduty && !var.guardduty_is_org_managed ? 1 : 0
  providers = { aws = aws.ap-northeast-3 }
}

module "guardduty_ap_south_1" {
  source    = "./modules/guardduty"
  count     = var.enable_guardduty && !var.guardduty_is_org_managed ? 1 : 0
  providers = { aws = aws.ap-south-1 }
}

module "guardduty_ca_central_1" {
  source    = "./modules/guardduty"
  count     = var.enable_guardduty && !var.guardduty_is_org_managed ? 1 : 0
  providers = { aws = aws.ca-central-1 }
}

module "guardduty_sa_east_1" {
  source    = "./modules/guardduty"
  count     = var.enable_guardduty && !var.guardduty_is_org_managed ? 1 : 0
  providers = { aws = aws.sa-east-1 }
}
