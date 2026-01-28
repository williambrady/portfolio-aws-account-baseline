#!/bin/bash
set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "============================================"
echo "  AWS Account Baseline Bootstrap"
echo "============================================"
echo ""

# Check AWS credentials
echo -e "${YELLOW}Checking AWS credentials...${NC}"
if ! aws sts get-caller-identity > /dev/null 2>&1; then
    echo -e "${RED}Error: AWS credentials not configured${NC}"
    echo "Please provide AWS credentials via:"
    echo "  - Environment variables (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)"
    echo "  - Mounted ~/.aws directory"
    exit 1
fi

ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
echo -e "${GREEN}Authenticated to account: ${ACCOUNT_ID}${NC}"
echo ""

# Load resource prefix from config.yaml
echo -e "${YELLOW}Loading configuration...${NC}"
RESOURCE_PREFIX=$(python3 -c "import yaml; print(yaml.safe_load(open('/work/config.yaml'))['resource_prefix'])" 2>/dev/null || echo "secops")
echo -e "${GREEN}Resource prefix: ${RESOURCE_PREFIX}${NC}"
echo ""

# State bucket configuration
STATE_BUCKET="${RESOURCE_PREFIX}-tfstate-${ACCOUNT_ID}"
STATE_KEY="baseline/terraform.tfstate"
STATE_REGION="us-east-1"

# Create state bucket if it doesn't exist
echo -e "${YELLOW}Checking Terraform state bucket...${NC}"
if ! aws s3api head-bucket --bucket "${STATE_BUCKET}" 2>/dev/null; then
    echo -e "${YELLOW}Creating state bucket: ${STATE_BUCKET}${NC}"

    # Create KMS key for state bucket
    echo -e "${YELLOW}Creating KMS key for state bucket...${NC}"
    KMS_KEY_ID=$(aws kms create-key \
        --description "KMS key for Terraform state bucket encryption" \
        --tags TagKey=Name,TagValue=${RESOURCE_PREFIX}-tfstate-key \
               TagKey=Purpose,TagValue="S3 bucket encryption" \
               TagKey=ProtectsBucket,TagValue="${STATE_BUCKET}" \
               TagKey=ManagedBy,TagValue=portfolio-aws-account-baseline \
        --region "${STATE_REGION}" \
        --query 'KeyMetadata.KeyId' \
        --output text \
        --no-cli-pager)

    # Create alias for the key
    aws kms create-alias \
        --alias-name "alias/${RESOURCE_PREFIX}-tfstate" \
        --target-key-id "${KMS_KEY_ID}" \
        --region "${STATE_REGION}" \
        --no-cli-pager

    # Enable key rotation
    aws kms enable-key-rotation \
        --key-id "${KMS_KEY_ID}" \
        --region "${STATE_REGION}" \
        --no-cli-pager

    KMS_KEY_ARN="arn:aws:kms:${STATE_REGION}:${ACCOUNT_ID}:key/${KMS_KEY_ID}"

    # Create bucket
    aws s3api create-bucket \
        --bucket "${STATE_BUCKET}" \
        --region "${STATE_REGION}" \
        --no-cli-pager

    # Enable versioning
    aws s3api put-bucket-versioning \
        --bucket "${STATE_BUCKET}" \
        --versioning-configuration Status=Enabled \
        --no-cli-pager

    # Enable KMS encryption
    aws s3api put-bucket-encryption \
        --bucket "${STATE_BUCKET}" \
        --server-side-encryption-configuration "{
            \"Rules\": [{
                \"ApplyServerSideEncryptionByDefault\": {
                    \"SSEAlgorithm\": \"aws:kms\",
                    \"KMSMasterKeyID\": \"${KMS_KEY_ARN}\"
                },
                \"BucketKeyEnabled\": true
            }]
        }" \
        --no-cli-pager

    # Block public access
    aws s3api put-public-access-block \
        --bucket "${STATE_BUCKET}" \
        --public-access-block-configuration '{
            "BlockPublicAcls": true,
            "IgnorePublicAcls": true,
            "BlockPublicPolicy": true,
            "RestrictPublicBuckets": true
        }' \
        --no-cli-pager

    echo -e "${GREEN}State bucket created with KMS encryption${NC}"
else
    echo -e "${GREEN}State bucket exists${NC}"

    # Check if bucket already has KMS encryption
    CURRENT_ENCRYPTION=$(aws s3api get-bucket-encryption \
        --bucket "${STATE_BUCKET}" \
        --query 'ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault.SSEAlgorithm' \
        --output text 2>/dev/null || echo "NONE")

    if [ "${CURRENT_ENCRYPTION}" != "aws:kms" ]; then
        echo -e "${YELLOW}Upgrading state bucket to KMS encryption...${NC}"

        # Check if KMS key alias exists
        if ! aws kms describe-key --key-id "alias/${RESOURCE_PREFIX}-tfstate" --region "${STATE_REGION}" 2>/dev/null; then
            # Create KMS key for state bucket
            KMS_KEY_ID=$(aws kms create-key \
                --description "KMS key for Terraform state bucket encryption" \
                --tags TagKey=Name,TagValue=${RESOURCE_PREFIX}-tfstate-key \
                       TagKey=Purpose,TagValue="S3 bucket encryption" \
                       TagKey=ProtectsBucket,TagValue="${STATE_BUCKET}" \
                       TagKey=ManagedBy,TagValue=portfolio-aws-account-baseline \
                --region "${STATE_REGION}" \
                --query 'KeyMetadata.KeyId' \
                --output text \
                --no-cli-pager)

            # Create alias for the key
            aws kms create-alias \
                --alias-name "alias/${RESOURCE_PREFIX}-tfstate" \
                --target-key-id "${KMS_KEY_ID}" \
                --region "${STATE_REGION}" \
                --no-cli-pager

            # Enable key rotation
            aws kms enable-key-rotation \
                --key-id "${KMS_KEY_ID}" \
                --region "${STATE_REGION}" \
                --no-cli-pager
        else
            KMS_KEY_ID=$(aws kms describe-key \
                --key-id "alias/${RESOURCE_PREFIX}-tfstate" \
                --region "${STATE_REGION}" \
                --query 'KeyMetadata.KeyId' \
                --output text)
        fi

        KMS_KEY_ARN="arn:aws:kms:${STATE_REGION}:${ACCOUNT_ID}:key/${KMS_KEY_ID}"

        # Update bucket encryption
        aws s3api put-bucket-encryption \
            --bucket "${STATE_BUCKET}" \
            --server-side-encryption-configuration "{
                \"Rules\": [{
                    \"ApplyServerSideEncryptionByDefault\": {
                        \"SSEAlgorithm\": \"aws:kms\",
                        \"KMSMasterKeyID\": \"${KMS_KEY_ARN}\"
                    },
                    \"BucketKeyEnabled\": true
                }]
            }" \
            --no-cli-pager

        echo -e "${GREEN}State bucket upgraded to KMS encryption${NC}"
    fi
fi
echo ""

# Access logging bucket
ACCESS_LOGGING_BUCKET="${RESOURCE_PREFIX}-access-logging-${ACCOUNT_ID}-us-east-1"
echo -e "${YELLOW}Checking access logging bucket...${NC}"
if ! aws s3api head-bucket --bucket "${ACCESS_LOGGING_BUCKET}" 2>/dev/null; then
    echo -e "${YELLOW}Creating access logging bucket: ${ACCESS_LOGGING_BUCKET}${NC}"

    # Create KMS key for access logging bucket
    ACCESS_KMS_KEY_ID=$(aws kms create-key \
        --description "KMS key for S3 access logging bucket encryption" \
        --tags TagKey=Name,TagValue=${RESOURCE_PREFIX}-access-logging-key \
               TagKey=Purpose,TagValue="S3 bucket encryption" \
               TagKey=ProtectsBucket,TagValue="${ACCESS_LOGGING_BUCKET}" \
               TagKey=ManagedBy,TagValue=portfolio-aws-account-baseline \
        --region "${STATE_REGION}" \
        --query 'KeyMetadata.KeyId' \
        --output text \
        --no-cli-pager)

    # Create alias for the key
    aws kms create-alias \
        --alias-name "alias/${RESOURCE_PREFIX}-access-logging" \
        --target-key-id "${ACCESS_KMS_KEY_ID}" \
        --region "${STATE_REGION}" \
        --no-cli-pager

    # Enable key rotation
    aws kms enable-key-rotation \
        --key-id "${ACCESS_KMS_KEY_ID}" \
        --region "${STATE_REGION}" \
        --no-cli-pager

    # Add key policy for S3 logging service
    aws kms put-key-policy \
        --key-id "${ACCESS_KMS_KEY_ID}" \
        --policy-name default \
        --region "${STATE_REGION}" \
        --policy "{
            \"Version\": \"2012-10-17\",
            \"Statement\": [
                {
                    \"Sid\": \"Enable IAM User Permissions\",
                    \"Effect\": \"Allow\",
                    \"Principal\": {\"AWS\": \"arn:aws:iam::${ACCOUNT_ID}:root\"},
                    \"Action\": \"kms:*\",
                    \"Resource\": \"*\"
                },
                {
                    \"Sid\": \"Allow S3 to use key for access logs\",
                    \"Effect\": \"Allow\",
                    \"Principal\": {\"Service\": \"logging.s3.amazonaws.com\"},
                    \"Action\": [\"kms:GenerateDataKey*\", \"kms:Decrypt\"],
                    \"Resource\": \"*\"
                }
            ]
        }" \
        --no-cli-pager

    ACCESS_KMS_KEY_ARN="arn:aws:kms:${STATE_REGION}:${ACCOUNT_ID}:key/${ACCESS_KMS_KEY_ID}"

    # Create bucket
    aws s3api create-bucket \
        --bucket "${ACCESS_LOGGING_BUCKET}" \
        --region "${STATE_REGION}" \
        --no-cli-pager

    # Enable versioning
    aws s3api put-bucket-versioning \
        --bucket "${ACCESS_LOGGING_BUCKET}" \
        --versioning-configuration Status=Enabled \
        --no-cli-pager

    # Enable KMS encryption
    aws s3api put-bucket-encryption \
        --bucket "${ACCESS_LOGGING_BUCKET}" \
        --server-side-encryption-configuration "{
            \"Rules\": [{
                \"ApplyServerSideEncryptionByDefault\": {
                    \"SSEAlgorithm\": \"aws:kms\",
                    \"KMSMasterKeyID\": \"${ACCESS_KMS_KEY_ARN}\"
                },
                \"BucketKeyEnabled\": true
            }]
        }" \
        --no-cli-pager

    # Block public access
    aws s3api put-public-access-block \
        --bucket "${ACCESS_LOGGING_BUCKET}" \
        --public-access-block-configuration '{
            "BlockPublicAcls": true,
            "IgnorePublicAcls": true,
            "BlockPublicPolicy": true,
            "RestrictPublicBuckets": true
        }' \
        --no-cli-pager

    # Add bucket policy for S3 log delivery
    aws s3api put-bucket-policy \
        --bucket "${ACCESS_LOGGING_BUCKET}" \
        --policy "{
            \"Version\": \"2012-10-17\",
            \"Statement\": [
                {
                    \"Sid\": \"S3ServerAccessLogsPolicy\",
                    \"Effect\": \"Allow\",
                    \"Principal\": {\"Service\": \"logging.s3.amazonaws.com\"},
                    \"Action\": \"s3:PutObject\",
                    \"Resource\": \"arn:aws:s3:::${ACCESS_LOGGING_BUCKET}/*\",
                    \"Condition\": {\"StringEquals\": {\"aws:SourceAccount\": \"${ACCOUNT_ID}\"}}
                },
                {
                    \"Sid\": \"DenyNonSSL\",
                    \"Effect\": \"Deny\",
                    \"Principal\": \"*\",
                    \"Action\": \"s3:*\",
                    \"Resource\": [\"arn:aws:s3:::${ACCESS_LOGGING_BUCKET}\", \"arn:aws:s3:::${ACCESS_LOGGING_BUCKET}/*\"],
                    \"Condition\": {\"Bool\": {\"aws:SecureTransport\": \"false\"}}
                }
            ]
        }" \
        --no-cli-pager

    echo -e "${GREEN}Access logging bucket created${NC}"
else
    echo -e "${GREEN}Access logging bucket exists${NC}"
fi

# Configure access logging on state bucket
echo -e "${YELLOW}Configuring access logging on state bucket...${NC}"
aws s3api put-bucket-logging \
    --bucket "${STATE_BUCKET}" \
    --bucket-logging-status "{
        \"LoggingEnabled\": {
            \"TargetBucket\": \"${ACCESS_LOGGING_BUCKET}\",
            \"TargetPrefix\": \"${STATE_BUCKET}/\",
            \"TargetObjectKeyFormat\": {
                \"PartitionedPrefix\": {
                    \"PartitionDateSource\": \"EventTime\"
                }
            }
        }
    }" \
    --no-cli-pager 2>/dev/null || echo -e "${YELLOW}Access logging already configured${NC}"
echo ""

# Check if logging bucket is needed (only if deploying CloudTrail or Config)
# Check for Control Tower CloudTrail (org trail that's not baseline-managed)
CT_CLOUDTRAIL=$(aws cloudtrail describe-trails --include-shadow-trails --region us-east-1 \
    --query "trailList[?IsMultiRegionTrail==\`true\` && starts_with(Name, 'aws-controltower')] | length(@)" \
    --output text 2>/dev/null || echo "0")

# Check for Control Tower Config recorder (not baseline-managed)
CT_CONFIG=$(aws configservice describe-configuration-recorders --region us-east-1 \
    --query "ConfigurationRecorders[?starts_with(name, 'aws-controltower')] | length(@)" \
    --output text 2>/dev/null || echo "0")

# Logging bucket is only needed if we're deploying CloudTrail or Config
# Skip only if BOTH Control Tower CloudTrail AND Control Tower Config exist
if [ "${CT_CLOUDTRAIL}" -gt 0 ] && [ "${CT_CONFIG}" -gt 0 ]; then
    NEED_LOGGING_BUCKET="false"
    echo -e "${GREEN}Control Tower manages CloudTrail and Config, skipping logging bucket setup${NC}"
else
    NEED_LOGGING_BUCKET="true"
    echo -e "${YELLOW}Will create logging bucket for CloudTrail/Config logs${NC}"
fi
echo ""

# Check and upgrade logging bucket KMS encryption (only if needed)
LOGGING_BUCKET="${RESOURCE_PREFIX}-security-logging-${ACCOUNT_ID}-us-east-1"
if [ "${NEED_LOGGING_BUCKET}" = "true" ]; then
    echo -e "${YELLOW}Checking logging bucket encryption...${NC}"
    if aws s3api head-bucket --bucket "${LOGGING_BUCKET}" 2>/dev/null; then
    LOGGING_ENCRYPTION=$(aws s3api get-bucket-encryption \
        --bucket "${LOGGING_BUCKET}" \
        --query 'ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault.SSEAlgorithm' \
        --output text 2>/dev/null || echo "NONE")

    if [ "${LOGGING_ENCRYPTION}" != "aws:kms" ]; then
        echo -e "${YELLOW}Upgrading logging bucket to KMS encryption...${NC}"

        # Check if KMS key alias exists
        if ! aws kms describe-key --key-id "alias/${RESOURCE_PREFIX}-logging-bucket" --region "${STATE_REGION}" 2>/dev/null; then
            # Create KMS key for logging bucket
            LOGGING_KMS_KEY_ID=$(aws kms create-key \
                --description "KMS key for S3 logging bucket encryption" \
                --tags TagKey=Name,TagValue=${RESOURCE_PREFIX}-logging-bucket-key \
                       TagKey=Purpose,TagValue="S3 bucket encryption" \
                       TagKey=ProtectsBucket,TagValue="${LOGGING_BUCKET}" \
                       TagKey=ManagedBy,TagValue=portfolio-aws-account-baseline \
                --region "${STATE_REGION}" \
                --query 'KeyMetadata.KeyId' \
                --output text \
                --no-cli-pager)

            # Create alias for the key
            aws kms create-alias \
                --alias-name "alias/${RESOURCE_PREFIX}-logging-bucket" \
                --target-key-id "${LOGGING_KMS_KEY_ID}" \
                --region "${STATE_REGION}" \
                --no-cli-pager

            # Enable key rotation
            aws kms enable-key-rotation \
                --key-id "${LOGGING_KMS_KEY_ID}" \
                --region "${STATE_REGION}" \
                --no-cli-pager

            # Add key policy for CloudTrail and Config
            aws kms put-key-policy \
                --key-id "${LOGGING_KMS_KEY_ID}" \
                --policy-name default \
                --region "${STATE_REGION}" \
                --policy "{
                    \"Version\": \"2012-10-17\",
                    \"Statement\": [
                        {
                            \"Sid\": \"Enable IAM User Permissions\",
                            \"Effect\": \"Allow\",
                            \"Principal\": {\"AWS\": \"arn:aws:iam::${ACCOUNT_ID}:root\"},
                            \"Action\": \"kms:*\",
                            \"Resource\": \"*\"
                        },
                        {
                            \"Sid\": \"Allow CloudTrail to encrypt logs\",
                            \"Effect\": \"Allow\",
                            \"Principal\": {\"Service\": \"cloudtrail.amazonaws.com\"},
                            \"Action\": [\"kms:GenerateDataKey*\", \"kms:DescribeKey\"],
                            \"Resource\": \"*\",
                            \"Condition\": {\"StringEquals\": {\"aws:SourceAccount\": \"${ACCOUNT_ID}\"}}
                        },
                        {
                            \"Sid\": \"Allow Config to encrypt\",
                            \"Effect\": \"Allow\",
                            \"Principal\": {\"Service\": \"config.amazonaws.com\"},
                            \"Action\": [\"kms:GenerateDataKey*\", \"kms:Decrypt\"],
                            \"Resource\": \"*\",
                            \"Condition\": {\"StringEquals\": {\"aws:SourceAccount\": \"${ACCOUNT_ID}\"}}
                        },
                        {
                            \"Sid\": \"Allow S3 to use key\",
                            \"Effect\": \"Allow\",
                            \"Principal\": {\"Service\": \"s3.amazonaws.com\"},
                            \"Action\": [\"kms:GenerateDataKey*\", \"kms:Decrypt\"],
                            \"Resource\": \"*\"
                        }
                    ]
                }" \
                --no-cli-pager
        else
            LOGGING_KMS_KEY_ID=$(aws kms describe-key \
                --key-id "alias/${RESOURCE_PREFIX}-logging-bucket" \
                --region "${STATE_REGION}" \
                --query 'KeyMetadata.KeyId' \
                --output text)
        fi

        LOGGING_KMS_KEY_ARN="arn:aws:kms:${STATE_REGION}:${ACCOUNT_ID}:key/${LOGGING_KMS_KEY_ID}"

        # Update bucket encryption
        aws s3api put-bucket-encryption \
            --bucket "${LOGGING_BUCKET}" \
            --server-side-encryption-configuration "{
                \"Rules\": [{
                    \"ApplyServerSideEncryptionByDefault\": {
                        \"SSEAlgorithm\": \"aws:kms\",
                        \"KMSMasterKeyID\": \"${LOGGING_KMS_KEY_ARN}\"
                    },
                    \"BucketKeyEnabled\": true
                }]
            }" \
            --no-cli-pager

        echo -e "${GREEN}Logging bucket upgraded to KMS encryption${NC}"
    else
        echo -e "${GREEN}Logging bucket already has KMS encryption${NC}"
    fi

    # Configure access logging on logging bucket
    echo -e "${YELLOW}Configuring access logging on logging bucket...${NC}"
    aws s3api put-bucket-logging \
        --bucket "${LOGGING_BUCKET}" \
        --bucket-logging-status "{
            \"LoggingEnabled\": {
                \"TargetBucket\": \"${ACCESS_LOGGING_BUCKET}\",
                \"TargetPrefix\": \"${LOGGING_BUCKET}/\",
                \"TargetObjectKeyFormat\": {
                    \"PartitionedPrefix\": {
                        \"PartitionDateSource\": \"EventTime\"
                    }
                }
            }
        }" \
        --no-cli-pager 2>/dev/null || echo -e "${YELLOW}Access logging already configured${NC}"
    else
        echo -e "${YELLOW}Logging bucket not yet created (will be created by Terraform)${NC}"
    fi
fi
echo ""

# Parse command line arguments
ACTION="${1:-apply}"
TERRAFORM_ARGS="${@:2}"

case "$ACTION" in
    discover)
        echo -e "${YELLOW}Running discovery only...${NC}"
        python /work/discovery/discover.py
        exit 0
        ;;
    plan)
        TF_ACTION="plan"
        ;;
    apply)
        TF_ACTION="apply -auto-approve"
        ;;
    destroy)
        TF_ACTION="destroy -auto-approve"
        ;;
    *)
        echo "Usage: $0 [discover|plan|apply|destroy]"
        exit 1
        ;;
esac

# Phase 1: Discovery
echo ""
echo "============================================"
echo "  Phase 1: Discovery"
echo "============================================"
echo ""
python /work/discovery/discover.py
echo ""

# Phase 2: Terraform
echo ""
echo "============================================"
echo "  Phase 2: Terraform ${TF_ACTION}"
echo "============================================"
echo ""

cd /work/terraform

# Initialize Terraform with S3 backend
echo -e "${YELLOW}Initializing Terraform...${NC}"
terraform init -input=false \
    -backend-config="bucket=${STATE_BUCKET}" \
    -backend-config="key=${STATE_KEY}" \
    -backend-config="region=${STATE_REGION}"

# Import pre-created bootstrap resources if not already in state
# Note: terraform import may show "Resource already managed by Terraform" errors
# if the state check races with state loading - these are benign and suppressed
import_bootstrap_resources() {
    echo ""
    echo -e "${YELLOW}Checking for resources to import...${NC}"

    # Force state refresh from S3 backend before checking
    terraform state pull > /dev/null 2>&1 || true

    # Helper function to import silently (suppresses "already managed" errors)
    import_if_needed() {
        terraform import "$1" "$2" > /dev/null 2>&1 || true
    }

    # Check if s3_access_logging resources are in state
    if ! terraform state list 2>/dev/null | grep -q "module.s3_access_logging.aws_s3_bucket.access_logging"; then
        echo -e "${YELLOW}Importing access logging bucket resources...${NC}"

        # Get KMS key ID
        ACCESS_KMS_KEY_ID=$(aws kms describe-key \
            --key-id "alias/${RESOURCE_PREFIX}-access-logging" \
            --region "${STATE_REGION}" \
            --query 'KeyMetadata.KeyId' \
            --output text 2>/dev/null || echo "")

        if [ -n "${ACCESS_KMS_KEY_ID}" ]; then
            import_if_needed "module.s3_access_logging.aws_kms_key.access_logging" "${ACCESS_KMS_KEY_ID}"
            import_if_needed "module.s3_access_logging.aws_kms_alias.access_logging" "alias/${RESOURCE_PREFIX}-access-logging"
        fi

        import_if_needed "module.s3_access_logging.aws_s3_bucket.access_logging" "${ACCESS_LOGGING_BUCKET}"
        import_if_needed "module.s3_access_logging.aws_s3_bucket_versioning.access_logging" "${ACCESS_LOGGING_BUCKET}"
        import_if_needed "module.s3_access_logging.aws_s3_bucket_server_side_encryption_configuration.access_logging" "${ACCESS_LOGGING_BUCKET}"
        import_if_needed "module.s3_access_logging.aws_s3_bucket_public_access_block.access_logging" "${ACCESS_LOGGING_BUCKET}"
        import_if_needed "module.s3_access_logging.aws_s3_bucket_policy.access_logging" "${ACCESS_LOGGING_BUCKET}"
    else
        echo -e "${GREEN}Access logging bucket resources already in state${NC}"
        # Verify KMS alias is also in state (can be missing if previous import partially failed)
        if ! terraform state list 2>/dev/null | grep -q "module.s3_access_logging.aws_kms_alias.access_logging"; then
            echo -e "${YELLOW}Importing missing access logging KMS alias...${NC}"
            import_if_needed "module.s3_access_logging.aws_kms_alias.access_logging" "alias/${RESOURCE_PREFIX}-access-logging"
        fi
    fi

    # Check if s3_tfstate resources are in state
    if ! terraform state list 2>/dev/null | grep -q "module.s3_tfstate.aws_s3_bucket.tfstate"; then
        echo -e "${YELLOW}Importing state bucket resources...${NC}"

        # Get KMS key ID
        STATE_KMS_KEY_ID=$(aws kms describe-key \
            --key-id "alias/${RESOURCE_PREFIX}-tfstate" \
            --region "${STATE_REGION}" \
            --query 'KeyMetadata.KeyId' \
            --output text 2>/dev/null || echo "")

        if [ -n "${STATE_KMS_KEY_ID}" ]; then
            import_if_needed "module.s3_tfstate.aws_kms_key.tfstate" "${STATE_KMS_KEY_ID}"
            import_if_needed "module.s3_tfstate.aws_kms_alias.tfstate" "alias/${RESOURCE_PREFIX}-tfstate"
        fi

        import_if_needed "module.s3_tfstate.aws_s3_bucket.tfstate" "${STATE_BUCKET}"
        import_if_needed "module.s3_tfstate.aws_s3_bucket_versioning.tfstate" "${STATE_BUCKET}"
        import_if_needed "module.s3_tfstate.aws_s3_bucket_server_side_encryption_configuration.tfstate" "${STATE_BUCKET}"
        import_if_needed "module.s3_tfstate.aws_s3_bucket_public_access_block.tfstate" "${STATE_BUCKET}"
        import_if_needed "module.s3_tfstate.aws_s3_bucket_logging.tfstate" "${STATE_BUCKET}"
    else
        echo -e "${GREEN}State bucket resources already in state${NC}"
        # Verify KMS alias is also in state (can be missing if previous import partially failed)
        if ! terraform state list 2>/dev/null | grep -q "module.s3_tfstate.aws_kms_alias.tfstate"; then
            echo -e "${YELLOW}Importing missing tfstate KMS alias...${NC}"
            import_if_needed "module.s3_tfstate.aws_kms_alias.tfstate" "alias/${RESOURCE_PREFIX}-tfstate"
        fi
    fi

    echo -e "${GREEN}Import check complete${NC}"
}

# Import bootstrap resources before running Terraform action
import_bootstrap_resources

# Run Terraform action
echo ""
echo -e "${YELLOW}Running terraform ${TF_ACTION}...${NC}"
terraform ${TF_ACTION} ${TERRAFORM_ARGS}

# Phase 3: Post-Deployment
if [ "$TF_ACTION" = "apply -auto-approve" ]; then
    echo ""
    echo "============================================"
    echo "  Phase 3: Post-Deployment"
    echo "============================================"
    echo ""

    # Verify AWS Config Setup
    echo -e "${YELLOW}Verifying AWS Config setup...${NC}"
    python /work/post-deployment/verify-config.py
    CONFIG_VERIFY_EXIT_CODE=$?

    if [ $CONFIG_VERIFY_EXIT_CODE -eq 0 ]; then
        echo -e "${GREEN}AWS Config verification completed${NC}"
    else
        echo -e "${YELLOW}Warning: AWS Config verification encountered issues (exit code: $CONFIG_VERIFY_EXIT_CODE)${NC}"
    fi
    echo ""

    # Cleanup Default VPCs
    echo -e "${YELLOW}Cleaning up default VPCs across all regions...${NC}"
    python /work/post-deployment/cleanup-default-vpcs.py
    CLEANUP_EXIT_CODE=$?

    if [ $CLEANUP_EXIT_CODE -eq 0 ]; then
        echo -e "${GREEN}Default VPC cleanup completed successfully${NC}"
    else
        echo -e "${YELLOW}Warning: Default VPC cleanup encountered issues (exit code: $CLEANUP_EXIT_CODE)${NC}"
        echo -e "${YELLOW}This may indicate running instances or other dependencies in default VPCs${NC}"
    fi
    echo ""
fi

# Phase 4: Summary
if [ "$TF_ACTION" = "apply -auto-approve" ]; then
    echo ""
    echo "============================================"
    echo "  Phase 4: Summary"
    echo "============================================"
    echo ""
    terraform output -json baseline_summary | jq .
    echo ""
    echo -e "${GREEN}Baseline deployment complete!${NC}"
fi
