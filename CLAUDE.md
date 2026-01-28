# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

portfolio-aws-account-baseline is an AWS infrastructure automation tool that bootstraps secure baseline configurations for AWS accounts. It ensures consistent logging, monitoring, and security controls using a discovery-driven approach with Terraform and Python/Boto3.

**Target regions:** All 17 supported AWS regions (us-east-1, us-east-2, us-west-1, us-west-2, eu-west-1, eu-west-2, eu-west-3, eu-central-1, eu-north-1, ap-southeast-1, ap-southeast-2, ap-northeast-1, ap-northeast-2, ap-northeast-3, ap-south-1, ca-central-1, sa-east-1)

**Target baseline components:**
- IAM Password Policy (global - strict password requirements)
- S3 Account Block Public Access (global - blocks public access to all S3 buckets)
- Alternate Contacts (global - billing, operations, security contacts)
- AWS Config (all resources, S3 logging) - all regions (conditional: skipped if org-managed)
- CloudTrail (multi-region trail, S3 logging, KMS encryption, CloudWatch Logs integration) - conditional: skipped if org trail exists
- Security Hub (all regions, us-east-1 as aggregator, configurable standards and disabled_controls) - conditional: skipped if org-managed
- Inspector v2 (EC2, ECR, Lambda scanning) - all regions (conditional: skipped if org-managed)
- GuardDuty (S3 logs, K8s audit, malware protection) - all regions (conditional: skipped if org-managed)
- SSM Settings (block public sharing, CloudWatch logging for Automation) - all regions
- EC2 Defaults (EBS encryption, snapshot blocking, IMDSv2) - all regions
- VPC Block Public Access (configurable: ingress/bidirectional/disabled) - all regions
- Default VPC cleanup - all active regions (post-deployment)

## Git Commit Guidelines

**IMPORTANT**: When creating git commits, follow these rules:

- Write clear, concise commit messages describing the changes
- Use conventional commit format when appropriate (e.g., "feat:", "fix:", "docs:")
- **NEVER include AI attribution or credit in commit messages**
- **DO NOT add "Generated with Claude Code" or "Co-Authored-By: Claude" to commits**
- Commit messages should reflect the actual changes made, not the tools used to make them

## Build and Run

```bash
# Build Docker image
docker build -t portfolio-aws-account-baseline .

# Run with environment variables
docker run --rm \
  -e AWS_ACCESS_KEY_ID \
  -e AWS_SECRET_ACCESS_KEY \
  -e AWS_SESSION_TOKEN \
  portfolio-aws-account-baseline [discover|plan|apply|destroy]

# Run with mounted credentials
docker run --rm \
  -v ~/.aws:/home/baseline/.aws:ro \
  portfolio-aws-account-baseline apply

# Or with AWS_PROFILE
docker run --rm \
  -v ~/.aws:/home/baseline/.aws:ro \
  -e AWS_PROFILE=myprofile \
  portfolio-aws-account-baseline apply
```

## AWS Account Access

When using AWS profiles (especially with SSO or assumed roles), you must cache credentials before running make commands:

```bash
# Always verify and cache credentials first
aws sts get-caller-identity --profile <account_id>

# Then run the make command
AWS_PROFILE=<account_id> make plan
```

This ensures the AWS credentials are properly cached before the Docker container attempts to use them. Without this step, the container may fail to authenticate.

## Configuration

Edit `config.yaml` to customize settings:

```yaml
resource_prefix: "secops"  # Prefix for all resources (S3 buckets, KMS keys, etc.)

vpc_block_public_access:
  mode: "ingress"  # Options: ingress, bidirectional, disabled

s3_lifecycle:
  tfstate:           # Terraform state buckets
  access_logging:    # S3 access log buckets
  config_logging:    # CloudTrail/Config log buckets
  cloudwatch_logs:   # CloudWatch Logs retention
```

Resource naming:
- `resource_prefix` - Prefix used for all resources created by this tool (default: `secops`)

VPC Block Public Access:
- `mode` - Controls internet gateway traffic blocking (default: `ingress`)
  - `ingress` - Blocks inbound only, allows outbound (recommended)
  - `bidirectional` - Blocks both directions (most restrictive)
  - `disabled` - No restrictions (least secure)

S3 lifecycle options:
- `transition_to_ia_days` - Days before transition to Standard-IA
- `expiration_days` - Days before object expiration
- `noncurrent_version_expiration_days` - Days before noncurrent version expiration

CloudWatch Logs options:
- `retention_days` - Log retention period (default: 365)

## Control Tower Integration

The account baseline automatically detects if the account is enrolled in AWS Control Tower and adjusts its behavior accordingly.

**Detection Method:**
- Checks for Control Tower managed CloudTrail (`aws-controltower-BaselineCloudTrail`)
- Checks for Control Tower managed Config recorders (`aws-controltower-*` prefix)

**Behavior when Control Tower is detected:**
- **CloudTrail**: Skipped entirely (Control Tower manages organization-wide trail)
- **AWS Config**: Skipped entirely (Control Tower manages Config recorders in governed regions)
- **Logging Bucket**: Skipped (Control Tower has its own centralized logging)

**Services NOT affected by Control Tower detection:**
- Security Hub (see Organization-Managed Services below)
- Inspector (see Organization-Managed Services below)
- IAM Password Policy (applies to all accounts)
- S3 Account Block Public Access
- SSM Settings (block public sharing, CloudWatch logging)
- EC2 Defaults (EBS encryption, IMDSv2)
- VPC Block Public Access
- Alternate Contacts

## Organization-Managed Services

The account baseline detects when Security Hub, Inspector, GuardDuty, CloudTrail, and Config are managed by an organization delegated administrator or central management.

**CloudTrail Detection:**
- Checks for `IsOrganizationTrail=true` flag on existing trails
- If an organization trail exists, CloudTrail is org-managed and skipped

**Config Detection:**
- Checks if the delivery channel S3 bucket belongs to a different account
- If Config delivers to an external account's bucket, Config is org-managed and skipped

**Security Hub Detection:**
- Uses `get_administrator_account()` API to check if this account has an administrator
- If an administrator account is found, Security Hub is org-managed and skipped

**Inspector Detection:**
- Uses `get_delegated_admin_account()` API to check for a delegated administrator
- If Inspector is enabled and a delegated admin exists (different from current account), Inspector is org-managed and skipped
- If access is denied to the delegated admin API but Inspector is already enabled, assumes org-managed

**GuardDuty Detection:**
- Uses `get_administrator_account()` API to check if this account has an administrator
- Falls back to `list_organization_admin_accounts()` for admin accounts
- If a delegated admin exists (different from current account), GuardDuty is org-managed and skipped

**Behavior when org-managed:**
- **CloudTrail**: Skipped entirely (org trail covers all accounts)
- **Config**: Skipped entirely (org manages Config recorders and delivery)
- **Security Hub**: Skipped entirely (delegated admin manages configuration and standards)
- **Inspector**: Skipped entirely (delegated admin manages scanning configuration)
- **GuardDuty**: Skipped entirely (delegated admin manages detector configuration)
- **S3 Logging Bucket**: Skipped when CloudTrail/Config are org-managed

**Services NOT affected by org-management detection:**
- IAM Password Policy
- S3 Account Block Public Access
- S3 Access Logging Bucket
- S3 Terraform State Bucket
- SSM Settings (block public sharing, CloudWatch logging)
- EC2 Defaults (EBS encryption, IMDSv2)
- VPC Block Public Access
- Alternate Contacts

## State Management

Terraform state is stored in S3: `{resource_prefix}-tfstate-{ACCOUNT_ID}/baseline/terraform.tfstate`

Default: `secops-tfstate-{ACCOUNT_ID}/baseline/terraform.tfstate`

The state bucket is automatically created on first run with:
- Versioning enabled
- KMS encryption
- Public access blocked

## Architecture

```
discovery/          # Python/Boto3 scripts to inspect account state
post-deployment/    # Python scripts for post-deployment tasks
  verify-config.py              # Verify AWS Config setup and recording status
  cleanup-default-vpcs.py       # Remove default VPCs
terraform/          # Main Terraform configuration
  modules/          # Terraform modules:
    - iam-password-policy
    - s3-account-block-public-access
    - alternate-contacts
    - s3-logging, s3-tfstate, s3-access-logging
    - aws-config
    - cloudtrail
    - security-hub (with disabled_controls support)
    - inspector-v2
    - guardduty
    - ssm-settings
    - ec2-defaults
    - vpc-defaults
entrypoint.sh       # Orchestration script
```

**Workflow:**
1. Run discovery script → generates `bootstrap.auto.tfvars.json`
2. Run Terraform → creates/updates baseline components
3. Run post-deployment tasks → verifies Config recording, removes default VPCs
4. Review outputs → confirms compliance

## Key Design Principles

**Discovery-Driven Deployment:** Every account differs. Discovery inspects current state and generates Terraform variables for conditional resource creation.

**Idempotency:** Running bootstrap multiple times is safe. Use `count` or `for_each` in Terraform based on discovered state.

**Reconciliation Rules:**
- Config: Fail if misconfigured (require manual fix)
- CloudTrail: Fail if exists but misconfigured
- Security Hub: Normalize if exists (enforce home region + standards)
- Inspector: Always enforce baseline

## Post-Deployment Tasks

After Terraform successfully applies the baseline configuration, the system automatically runs post-deployment tasks:

### AWS Config Verification

**Purpose:** Ensures AWS Config is properly configured and actively recording in all target regions.

**Process:**
1. Verifies the AWS Config service-linked role (`AWSServiceRoleForConfig`) exists
2. Creates the service-linked role if it doesn't exist
3. Checks that Config recorders are enabled and recording in all US regions
4. Reports the status of each region's Config recorder

**Output:** Provides clear status for each region showing whether Config is recording successfully.

### Default VPC Removal

**Purpose:** Removes default VPCs across all active AWS regions as a security best practice.

**Process:**
1. Enumerates all active AWS regions
2. Identifies default VPCs in each region
3. Safely deletes VPC components in order:
   - Detaches and deletes Internet Gateways
   - Deletes Subnets
   - Deletes Security Groups (non-default)
   - Deletes Route Tables (non-main)
   - Deletes Network ACLs (non-default)
   - Deletes the VPC itself

**Dependency Handling:** VPCs with active dependencies (running instances, EFS mounts, etc.) are marked as "skipped" rather than "failed". The script returns exit code 0 when only skipped, allowing the baseline deployment to succeed. Skipped VPCs can be cleaned up in follow-up processes after dependencies are removed.

## Development Notes

**Multi-region Terraform strategy:** Use `for_each` with provider aliases for regional resources.

**Python discovery output format (multi-region):**
```json
{
  "regions": ["us-east-1", "us-east-2", "us-west-1", "us-west-2"],
  "config": {
    "us-east-1": { "exists": true, "recorder_name": "default", "s3_bucket": "..." },
    "us-east-2": { "exists": false }
  },
  "security_hub": {
    "us-east-1": { "enabled": true, "enabled_standards": ["AFSBP", "CIS"] }
  }
}
```

**Security Hub aggregator region:** us-east-1 collects findings from all other US regions.

**S3 bucket requirements:** Versioning, KMS encryption with dedicated keys (tagged with ProtectsBucket), Block Public Access, service policies for CloudTrail/Config, access logging to central bucket.

**CloudWatch Logs:** CloudTrail integrates with CloudWatch Logs for real-time monitoring. Log group uses dedicated KMS key (tagged with ProtectsLogGroup).

**EC2 Defaults (per-region):**
- EBS encryption by default: Enabled for all new volumes
- EBS snapshot block public access: Block all public sharing
- Instance Metadata Service (IMDS) defaults:
  - HTTP tokens: Required (IMDSv2 only, no IMDSv1)
  - HTTP PUT response hop limit: 2 (supports containerized workloads)
  - Instance metadata tags: Enabled (allows instance tag access via IMDS)

**VPC Defaults (per-region):**
- VPC Block Public Access: Configurable blocking of internet gateway traffic
- Modes (configured via `vpc_block_public_access.mode` in config.yaml):
  - `ingress` (default): Blocks inbound internet access, allows outbound
  - `bidirectional`: Blocks both inbound and outbound internet access
  - `disabled`: No VPC block public access restrictions
- This setting prevents accidental public exposure of VPC resources when enabled

**IAM Password Policy (global):**
- Minimum password length: 16 characters
- Require at least one uppercase letter
- Require at least one lowercase letter
- Require at least one number
- Require at least one symbol
- Password expiration: 90 days
- Password reuse prevention: 24 passwords
- Hard expiry: Password expiration requires administrator reset
- Allow users to change their own passwords: Enabled

**S3 Account Block Public Access (global):**
- Block public ACLs: Prevents new public ACLs and uploading objects with public ACLs
- Block public policy: Prevents new public bucket policies
- Ignore public ACLs: Ignores all public ACLs on buckets and objects
- Restrict public buckets: Restricts access to buckets with public policies to AWS services and authorized users only
- Applies to all S3 buckets in the account across all regions

**Alternate Contacts (global):**
- Configured via `config.yaml`
- Three contact types: Billing, Operations, Security
- Each contact includes: name, title, email address, phone number
- Contacts receive AWS notifications for their respective areas
- Enable/disable via `enable_alternate_contacts` flag in config.yaml

## Reference

See [STEPS.md](STEPS.md) for detailed deployment phases and [README.md](README.md) for complete documentation.
