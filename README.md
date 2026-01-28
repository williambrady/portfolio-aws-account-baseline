# portfolio-aws-account-baseline

Setup a secure standalone AWS account with baseline security controls using a discovery-driven approach.

## Overview

portfolio-aws-account-baseline is an AWS infrastructure automation tool that bootstraps secure baseline configurations for AWS accounts. It ensures consistent logging, monitoring, and security controls across all US commercial regions using Terraform and Python/Boto3.

## Features

### Global Controls
- **IAM Password Policy** - Strict password requirements (16 chars, all complexity, 90-day expiration, 24 password history)
- **S3 Account Block Public Access** - Blocks all public S3 access at account level
- **Alternate Contacts** - Configures billing, operations, and security contacts

### Regional Controls (All US Regions)
- **AWS Config** - Configuration recorder with service-linked role (AWSServiceRoleForConfig)
- **Security Hub** - Enabled with us-east-1 as aggregator, NIST 800-53 + CIS + AFSBP standards
- **Inspector v2** - EC2, ECR, Lambda, and Lambda Code scanning (LAMBDA_CODE not available in us-west-1)
- **SSM Settings** - Prevents public sharing of SSM documents, enables CloudWatch logging for SSM Automation (SSM.6 compliance) with KMS encryption and 365-day retention
- **EC2 Defaults** - EBS encryption by default, EBS snapshot public access blocking, secure IMDSv2 configuration
- **VPC Block Public Access** - Configurable blocking of internet gateway traffic (ingress, bidirectional, or disabled)

### Multi-Region Controls
- **CloudTrail** - Multi-region trail with KMS encryption, CloudWatch Logs integration
- **S3 Logging** - Centralized logging bucket with KMS encryption and access logging

### Post-Deployment Automation
- **AWS Config Verification** - Ensures Config service-linked role exists and recorders are actively recording
- **Default VPC Cleanup** - Removes default VPCs across all active regions

### Control Tower Integration
- **Automatic Detection** - Detects Control Tower managed CloudTrail and Config
- **CloudTrail Skip** - Automatically skips CloudTrail when Control Tower trail exists
- **Config Skip** - Automatically skips Config when Control Tower manages it

### Organization-Managed Services
- **Security Hub Detection** - Detects delegated administrator and skips if org-managed
- **Inspector Detection** - Detects delegated administrator and skips if org-managed

## Target Regions

All 17 commercial regions:
- us-east-1 (aggregator region)
- us-east-2
- us-west-1
- us-west-2
- eu-west-1
- eu-west-2
- eu-west-3
- eu-central-1
- eu-north-1
- ap-southeast-1
- ap-southeast-2
- ap-northeast-1
- ap-northeast-2
- ap-northeast-3
- ap-south-1
- ca-central-1
- sa-east-1

## Prerequisites

- Docker
- AWS credentials with administrative access to the target account
- AWS CLI (optional, for credential management)

For detailed information about each deployment phase, see [STEPS.md](STEPS.md).

## Installation

```bash
# Clone the repository
git clone <repository-url>
cd portfolio-aws-account-baseline

# Build Docker image
docker build -t portfolio-aws-account-baseline .
```

## Usage

### With Environment Variables

```bash
docker run --rm \
  -e AWS_ACCESS_KEY_ID \
  -e AWS_SECRET_ACCESS_KEY \
  -e AWS_SESSION_TOKEN \
  portfolio-aws-account-baseline [discover|plan|apply|destroy]
```

### With AWS Profile

```bash
docker run --rm \
  -v ~/.aws:/home/baseline/.aws:ro \
  -e AWS_PROFILE=myaccount \
  portfolio-aws-account-baseline apply
```

### Commands

- `discover` - Discover current account state and generate Terraform variables
- `plan` - Run discovery and show Terraform plan
- `apply` - Run discovery and apply baseline configuration
- `destroy` - Destroy baseline resources (use with caution)

## Configuration

Edit `config.yaml` to customize settings:

```yaml
# Resource Naming Prefix
resource_prefix: "secops"

# VPC Block Public Access Configuration
vpc_block_public_access:
  mode: "ingress"  # Options: ingress, bidirectional, disabled

s3_lifecycle:
  tfstate:
    transition_to_ia_days: 90  # No expiration - state files kept indefinitely
  access_logging:
    transition_to_ia_days: 30
    expiration_days: 365
    noncurrent_version_expiration_days: 30
  config_logging:
    transition_to_ia_days: 90
    expiration_days: 2555
    noncurrent_version_expiration_days: 90
  cloudwatch_logs:
    retention_days: 365

alternate_contacts:
  enable_alternate_contacts: true
  billing_contact:
    name: "Your Name"
    title: "FinOps Manager"
    email: "billing@example.com"
    phone: "+15551234567"
  operations_contact:
    name: "Your Name"
    title: "Operations Manager"
    email: "ops@example.com"
    phone: "+15551234567"
  security_contact:
    name: "Your Name"
    title: "Cloud Security"
    email: "security@example.com"
    phone: "+15551234567"
```

### Resource Naming

- `resource_prefix` - Prefix used for all resources created by this tool (S3 buckets, KMS keys, IAM roles, etc.). Default: `secops`

### VPC Block Public Access

Controls whether VPCs can have internet gateways and public IP addresses:

- `mode` - VPC block public access mode:
  - `ingress` (recommended) - Blocks inbound internet access, allows outbound. Prevents internet gateways from accepting inbound traffic while allowing VPCs to reach the internet.
  - `bidirectional` (most restrictive) - Blocks both inbound and outbound internet access. Completely prevents internet gateway attachment and public IP assignment.
  - `disabled` (least secure) - No VPC block public access restrictions. Allows unrestricted internet gateway usage.

**Default**: `ingress`

### S3 Lifecycle Options

- `transition_to_ia_days` - Days before transition to Standard-IA storage class
- `expiration_days` - Days before object expiration
- `noncurrent_version_expiration_days` - Days before noncurrent version expiration

### CloudWatch Logs Options

- `retention_days` - Log retention period in days

### Alternate Contacts Options

- `enable_alternate_contacts` - Enable/disable alternate contacts configuration
- `billing_contact`, `operations_contact`, `security_contact` - Contact details for each type
  - `name` - Contact person name
  - `title` - Job title
  - `email` - Email address
  - `phone` - Phone number (E.164 format recommended)

## Architecture

```
discovery/          # Python/Boto3 scripts to inspect account state
post-deployment/    # Python scripts for post-deployment tasks
  verify-config.py              # Verify AWS Config setup and recording status
  cleanup-default-vpcs.py       # Remove default VPCs
terraform/          # Main Terraform configuration
  modules/          # Terraform modules
    iam-password-policy/        # IAM password policy (global)
    s3-account-block-public-access/  # S3 account-level public access blocking (global)
    alternate-contacts/         # Account alternate contacts (global)
    aws-config/                 # AWS Config recorder and delivery channel (regional)
    cloudtrail/                 # CloudTrail with KMS and CloudWatch Logs (multi-region)
    security-hub/               # Security Hub with standards (regional)
    inspector-v2/               # Inspector v2 scanning (regional)
    ssm-settings/               # SSM settings with CloudWatch logging (regional)
    ec2-defaults/               # EC2/EBS defaults and IMDSv2 (regional)
    vpc-defaults/               # VPC block public access (regional)
    s3-logging/                 # Centralized logging bucket
    s3-access-logging/          # Access logging bucket
    s3-tfstate/                 # Terraform state bucket
entrypoint.sh       # Orchestration script
config.yaml         # User configuration
```

### Workflow

1. **Discovery** - Python script inspects current account state and generates `bootstrap.auto.tfvars.json`
2. **Terraform Init & Import** - Initializes Terraform and imports pre-created bootstrap buckets into state
3. **Terraform Apply** - Creates/updates baseline components based on discovered state
4. **Post-Deployment** - Verifies AWS Config recording, removes default VPCs
5. **Summary** - Outputs deployment status and baseline configuration

### State Management

Terraform state is stored in S3: `{resource_prefix}-tfstate-{ACCOUNT_ID}/baseline/terraform.tfstate`

Default: `secops-tfstate-{ACCOUNT_ID}/baseline/terraform.tfstate`

The state bucket and access logging bucket are automatically created on first run, then imported into Terraform state for ongoing management. Both buckets include:
- Versioning enabled
- KMS encryption with dedicated keys
- Public access blocked
- SSL/TLS enforcement via bucket policy
- Lifecycle policies (configurable via config.yaml)

## Design Principles

### Discovery-Driven Deployment

The tool discovers existing resources before deployment. Resources managed by this tool (prefixed with the configured `resource_prefix`, default `secops-`) are recognized and continue to be managed by Terraform. External resources are detected and reported.

### Idempotency

Running the bootstrap multiple times is safe. The tool will:
- Skip creating resources that already exist (external)
- Continue managing resources it created (baseline-managed)
- Report current state without making unnecessary changes

### Service-Linked Roles

AWS Config uses the AWS-managed service-linked role `AWSServiceRoleForConfig` to satisfy Security Hub Config.1 compliance requirement.

## Security Controls

### Encryption

- S3 buckets encrypted with dedicated KMS keys (tagged with `ProtectsBucket`)
- CloudTrail logs encrypted with KMS
- CloudWatch Logs encrypted with KMS (tagged with `ProtectsLogGroup`)

### Transport Security

- All S3 buckets enforce SSL/TLS via bucket policy (denies requests where `aws:SecureTransport` is false)
- Applies to state bucket, access logging bucket, and centralized logging bucket

### Logging

- CloudTrail delivers to S3 and CloudWatch Logs
- S3 access logging enabled on all buckets
- Config delivers snapshots to S3

### Standards

Security Hub enables these standards:
- AWS Foundational Security Best Practices (AFSBP)
- CIS AWS Foundations Benchmark
- NIST 800-53 Rev. 5

## Troubleshooting

### Common Issues

**Resources being destroyed on subsequent runs**

The discovery logic recognizes baseline-created resources by their naming prefix (configured via `resource_prefix` in config.yaml, default `secops-`). If resources are being destroyed, ensure they match the expected naming convention.

**Config.1 Security Hub finding**

AWS Config should use the service-linked role `AWSServiceRoleForConfig`. This is configured by default. If you see this finding, the Config recorder may have been created before this fix was applied and needs to be recreated.

**Expired AWS credentials**

Ensure your AWS credentials are valid. For named profiles, use the `-e AWS_PROFILE=<profile>` flag.

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

### Default VPC Cleanup

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

**Dependency Handling:** If default VPCs contain running instances or other active resources, they are marked as "skipped" (not failed). The baseline deployment succeeds, and skipped VPCs can be cleaned up in follow-up processes after dependencies are removed.

**Example output:**
```
us-east-1            ⏭️  SKIPPED (has dependencies)
us-west-2            ✅ SUCCESS

Total regions processed: 17
Successful cleanups: 16
Skipped (dependencies): 1
Failed: 0

✅ Completed! 1 VPC(s) skipped due to active dependencies (will be cleaned up in follow-up)
```

## Known Limitations

There are some things that cannot be programmatically configured but are part of our program:
1. Initial AWS Account Creation
2. Initial Access Key setup for new Org
3. IAM user and role access to Billing information

## Contributing

See CLAUDE.md for development guidelines and architecture details.

## License

Proprietary - Crofton Cloud
