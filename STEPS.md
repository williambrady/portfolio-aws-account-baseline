# Deployment Steps

This document describes the exact steps that occur when using `portfolio-aws-account-baseline` to deploy baseline security configurations to an AWS account.

## Prerequisites

Before running the tool, ensure:
- AWS credentials are configured (via environment variables or mounted `~/.aws` directory)
- Docker is installed and running
- `config.yaml` is customized for your environment (optional)

## Execution Flow

### Step 0: Credential Validation

1. Verify AWS credentials are valid using `aws sts get-caller-identity`
2. Retrieve and display the target AWS account ID
3. Load resource prefix from `config.yaml` (default: `secops`)

### Step 1: State Bucket Setup

Creates or validates the Terraform state bucket (`{prefix}-tfstate-{account_id}`):

1. **Check if state bucket exists**
2. **If bucket doesn't exist:**
   - Create KMS key for state bucket encryption
   - Create KMS key alias (`alias/{prefix}-tfstate`)
   - Enable KMS key rotation
   - Create S3 bucket in `us-east-1`
   - Enable versioning
   - Configure KMS encryption
   - Block all public access
3. **If bucket exists but lacks KMS encryption:**
   - Create or retrieve KMS key
   - Upgrade bucket to KMS encryption

### Step 2: Access Logging Bucket Setup

Creates or validates the access logging bucket (`{prefix}-access-logging-{account_id}-us-east-1`):

1. **Check if access logging bucket exists**
2. **If bucket doesn't exist:**
   - Create KMS key for access logging bucket encryption
   - Create KMS key alias (`alias/{prefix}-access-logging`)
   - Enable KMS key rotation
   - Configure KMS key policy for S3 logging service
   - Create S3 bucket in `us-east-1`
   - Enable versioning
   - Configure KMS encryption
   - Block all public access
   - Add bucket policy for S3 log delivery

### Step 3: Configure Access Logging

1. Configure access logging on the state bucket (logs to access logging bucket)
2. Check if the main logging bucket exists (`{prefix}-logs-{account_id}`)
3. **If logging bucket exists but lacks KMS encryption:**
   - Create or retrieve KMS key with policy for CloudTrail, Config, and S3
   - Upgrade bucket to KMS encryption
4. Configure access logging on the logging bucket

---

## Phase 1: Discovery

The discovery script (`discovery/discover.py`) inspects the current state of the AWS account:

### Account Information
- Retrieve AWS account ID and caller ARN

### S3 Bucket Discovery
- Check if logging bucket exists (`{prefix}-logs-{account_id}`)

### CloudTrail Discovery (Global)
- List all CloudTrail trails
- Identify multi-region trails
- Check if trails are managed by this tool
- Determine logging status

### Regional Service Discovery
For each target region (`us-east-1`, `us-east-2`, `us-west-1`, `us-west-2`):

**AWS Config:**
- Check if Config recorder exists
- Determine if recorder is managed by this tool
- Get recording status
- Retrieve delivery channel configuration

**Security Hub:**
- Check if Security Hub is enabled
- List enabled security standards (NIST 800-53, CIS, AFSBP, PCI-DSS)
- Check for finding aggregator (in us-east-1 only)

**Inspector v2:**
- Check if Inspector is enabled
- Identify enabled resource types (EC2, ECR, Lambda)

### Output
- Generate `bootstrap.auto.tfvars.json` with discovered state
- Variables inform Terraform about existing resources to avoid conflicts

---

## Phase 2: Terraform Init and Import

### Initialization
1. Initialize Terraform with S3 backend configuration
2. Download required provider plugins

### Import Pre-Created Resources

After initialization, the tool imports pre-created bootstrap resources into Terraform state:

**Access Logging Bucket** (if not already in state):
- `aws_kms_key.access_logging` - KMS encryption key
- `aws_kms_alias.access_logging` - Key alias
- `aws_s3_bucket.access_logging` - The bucket
- `aws_s3_bucket_versioning.access_logging` - Versioning config
- `aws_s3_bucket_server_side_encryption_configuration.access_logging` - Encryption
- `aws_s3_bucket_public_access_block.access_logging` - Public access block
- `aws_s3_bucket_policy.access_logging` - Bucket policy

**State Bucket** (if not already in state):
- `aws_kms_key.tfstate` - KMS encryption key
- `aws_kms_alias.tfstate` - Key alias
- `aws_s3_bucket.tfstate` - The bucket
- `aws_s3_bucket_versioning.tfstate` - Versioning config
- `aws_s3_bucket_server_side_encryption_configuration.tfstate` - Encryption
- `aws_s3_bucket_public_access_block.tfstate` - Public access block
- `aws_s3_bucket_logging.tfstate` - Access logging config
- `aws_s3_bucket_policy.tfstate` - SSL enforcement policy

This ensures resources created in Steps 1-3 become managed by Terraform for drift detection and future updates.

**Note:** Lifecycle configurations and bucket policies (SSL enforcement) are managed by Terraform and will be created/updated on first apply after import.

---

## Phase 3: Terraform Apply

### Resource Creation/Updates

Terraform creates or updates the following resources:

**Global Resources:**
- IAM Password Policy (strict password requirements)
- S3 Account Block Public Access
- Alternate Contacts (if enabled in config)

**Logging Infrastructure:**
- S3 state bucket with KMS encryption, SSL enforcement (imported from Step 1)
- S3 access logging bucket with KMS encryption, SSL enforcement (imported from Step 2)
- S3 logging bucket with KMS encryption, SSL enforcement
- Lifecycle policies per config settings:
  - **tfstate**: Transition to Standard-IA after 90 days, no expiration (state files kept indefinitely)
  - **access_logging**: Transition to Standard-IA after 30 days, expire after 365 days
  - **config_logging**: Transition to Standard-IA after 90 days, expire after 2555 days (~7 years)

**CloudTrail (Multi-Region):**
- CloudTrail trail with multi-region support
- CloudWatch Logs integration
- KMS encryption for logs
- S3 bucket policy for CloudTrail

**Regional Resources (per target region):**

| Service | Configuration |
|---------|--------------|
| AWS Config | Recorder, delivery channel, S3 logging |
| Security Hub | Enable with NIST 800-53, CIS, AFSBP standards |
| Security Hub Aggregator | Finding aggregator in us-east-1 |
| Inspector v2 | EC2, ECR, Lambda, Lambda Code scanning (LAMBDA_CODE not available in us-west-1) |
| SSM | Block public sharing |
| EC2 Defaults | EBS encryption, snapshot blocking, IMDSv2 |
| VPC Defaults | Block public access (mode from config) |

---

## Phase 4: Post-Deployment

Only runs when `apply` action is used.

### AWS Config Verification

1. **Service-Linked Role Check**
   - Verify `AWSServiceRoleForConfig` exists
   - Create the role if missing

2. **Recorder Verification**
   - Check Config recorder status in each target region
   - Verify recorders are actively recording
   - Report status for each region

### Default VPC Cleanup

1. **Enumerate all active AWS regions** (not just target regions)

2. **For each region with a default VPC:**
   - Detach and delete Internet Gateways
   - Delete all Subnets
   - Delete non-default Security Groups
   - Delete non-main Route Tables
   - Delete non-default Network ACLs
   - Delete the default VPC

3. **Handle failures gracefully**
   - If VPC has running instances or dependencies, cleanup fails with warning
   - Deployment continues; manual intervention may be needed

---

## Phase 5: Summary

1. Output Terraform `baseline_summary` as JSON
2. Display completion message

---

## Command Reference

| Command | Description |
|---------|-------------|
| `discover` | Run discovery only, output current state |
| `plan` | Run discovery + Terraform plan (no changes) |
| `apply` | Full deployment (discovery + apply + post-deployment) |
| `destroy` | Tear down all managed resources |

## State Management

- Terraform state stored in: `s3://{prefix}-tfstate-{account_id}/baseline/terraform.tfstate`
- State bucket is created automatically on first run, then imported into Terraform
- Access logging bucket is created for state bucket logging, then imported into Terraform
- Both bootstrap buckets are fully managed by Terraform after initial import
- State includes all managed resources across all regions

## Security Controls Summary

All S3 buckets created by this tool include the following security controls:

| Control | Description |
|---------|-------------|
| KMS Encryption | Dedicated KMS key per bucket with automatic rotation enabled |
| Public Access Block | All public access blocked at bucket level |
| SSL/TLS Enforcement | Bucket policy denies requests where `aws:SecureTransport` is false |
| Versioning | All buckets have versioning enabled for object recovery |
| Access Logging | State and logs buckets log to the access logging bucket |
| Lifecycle Management | Configurable transitions and expirations per bucket type |

### Bucket Lifecycle Defaults

| Bucket | Transition to Standard-IA | Expiration |
|--------|---------------------------|------------|
| tfstate | 90 days | Never (state files kept indefinitely) |
| access-logging | 30 days | 365 days |
| logs (CloudTrail/Config) | 90 days | 2555 days (~7 years) |
