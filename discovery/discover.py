#!/usr/bin/env python3
"""
AWS Account Discovery Script

Discovers the current state of AWS Config, CloudTrail, Security Hub, Inspector,
and GuardDuty across all target regions. Detects organization-managed services
to conditionally skip deployment when org-baseline handles them.

Outputs JSON for Terraform consumption.
"""

import json
import sys

import boto3
import yaml
from botocore.exceptions import ClientError

TARGET_REGIONS = [
    "us-east-1",
    "us-east-2",
    "us-west-1",
    "us-west-2",
    "eu-west-1",
    "eu-west-2",
    "eu-west-3",
    "eu-central-1",
    "eu-north-1",
    "ap-southeast-1",
    "ap-southeast-2",
    "ap-northeast-1",
    "ap-northeast-2",
    "ap-northeast-3",
    "ap-south-1",
    "ca-central-1",
    "sa-east-1",
]
CONFIG_PATH = "/work/config.yaml"


def load_config() -> dict:
    """Load configuration from config.yaml."""
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            return yaml.safe_load(f)
    except FileNotFoundError:
        print(
            f"Warning: Config file not found at {CONFIG_PATH}, using defaults",
            file=sys.stderr,
        )
        return {
            "resource_prefix": "secops",
            "vpc_block_public_access": {"mode": "ingress"},
            "s3_lifecycle": {
                "tfstate": {
                    "transition_to_ia_days": 90,
                    "expiration_days": 2555,
                    "noncurrent_version_expiration_days": 90,
                },
                "access_logging": {
                    "transition_to_ia_days": 30,
                    "expiration_days": 365,
                    "noncurrent_version_expiration_days": 30,
                },
                "config_logging": {
                    "transition_to_ia_days": 90,
                    "expiration_days": 2555,
                    "noncurrent_version_expiration_days": 90,
                },
                "general": {
                    "transition_to_ia_days": 90,
                    "expiration_days": 2555,
                    "noncurrent_version_expiration_days": 90,
                },
                "cloudwatch_logs": {"retention_days": 365},
            },
        }


def discover_config(region: str, resource_prefix: str, current_account_id: str) -> dict:
    """Discover AWS Config state in a region.

    Detects:
    - Control Tower managed Config (aws-controltower-* prefix)
    - Organization-managed Config (delivery to external account's S3 bucket)
    - Baseline-managed Config (continues Terraform management)
    """
    client = boto3.client("config", region_name=region)
    result = {
        "exists": False,
        "is_control_tower_managed": False,
        "is_org_managed": False,
    }

    try:
        recorders = client.describe_configuration_recorders()
        if recorders.get("ConfigurationRecorders"):
            recorder = recorders["ConfigurationRecorders"][0]
            recorder_name = recorder.get("name", "")

            # Check if this is Control Tower managed
            is_control_tower = recorder_name.startswith("aws-controltower")

            # Check if this is a baseline-managed recorder
            # If so, mark as not existing so Terraform continues to manage it
            is_baseline_managed = recorder_name == f"{resource_prefix}-recorder"

            if is_control_tower:
                result["exists"] = True
                result["is_control_tower_managed"] = True
            elif is_baseline_managed:
                result["exists"] = False
                result["is_baseline_managed"] = True
            else:
                # External recorder (not CT, not baseline)
                result["exists"] = True

            result["recorder_name"] = recorder_name
            result["role_arn"] = recorder.get("roleARN", "")

            # Check recording status
            status = client.describe_configuration_recorder_status()
            if status.get("ConfigurationRecordersStatus"):
                result["recording"] = status["ConfigurationRecordersStatus"][0].get(
                    "recording", False
                )

            # Check delivery channel
            channels = client.describe_delivery_channels()
            if channels.get("DeliveryChannels"):
                channel = channels["DeliveryChannels"][0]
                s3_bucket = channel.get("s3BucketName", "")
                result["s3_bucket"] = s3_bucket
                result["s3_key_prefix"] = channel.get("s3KeyPrefix", "")

                # Check if delivery goes to a different account's bucket
                # Org-baseline delivers to centralized bucket in log-archive account
                # Pattern: {prefix}-config-{log_archive_account_id}
                if s3_bucket and current_account_id not in s3_bucket:
                    # Bucket name doesn't contain this account's ID
                    # Likely delivering to centralized org bucket
                    result["is_org_managed"] = True
                    result["external_bucket"] = s3_bucket

    except ClientError as e:
        if e.response["Error"]["Code"] not in ["NoSuchConfigurationRecorderException"]:
            print(f"Warning: Config discovery error in {region}: {e}", file=sys.stderr)

    return result


def discover_cloudtrail(resource_prefix: str) -> dict:
    """Discover CloudTrail state (trails are global, check from us-east-1).

    Detects:
    - Organization trails (IsOrganizationTrail=true) - managed by org-baseline
    - Control Tower managed trails (aws-controltower-* prefix)
    - Multi-region trails
    - Baseline-managed trails (continues Terraform management)
    """
    client = boto3.client("cloudtrail", region_name="us-east-1")
    result = {
        "multi_region_trail_exists": False,
        "is_control_tower_managed": False,
        "is_org_trail": False,
        "trails": [],
    }

    try:
        trails = client.describe_trails(includeShadowTrails=True)
        for trail in trails.get("trailList", []):
            trail_name = trail.get("Name", "")
            is_org_trail = trail.get("IsOrganizationTrail", False)

            trail_info = {
                "name": trail_name,
                "is_multi_region": trail.get("IsMultiRegionTrail", False),
                "is_organization_trail": is_org_trail,
                "s3_bucket": trail.get("S3BucketName", ""),
                "s3_key_prefix": trail.get("S3KeyPrefix", ""),
                "kms_key_id": trail.get("KMSKeyId", ""),
                "include_global_events": trail.get("IncludeGlobalServiceEvents", False),
                "is_logging": False,
            }

            # Check if trail is logging
            try:
                status = client.get_trail_status(Name=trail["TrailARN"])
                trail_info["is_logging"] = status.get("IsLogging", False)
            except ClientError:
                pass

            result["trails"].append(trail_info)

            # Organization trail takes precedence - skip account-level CloudTrail
            if is_org_trail:
                result["is_org_trail"] = True
                result["multi_region_trail_exists"] = True
                result["org_trail_name"] = trail_name
                result["org_trail_bucket"] = trail_info["s3_bucket"]
                # Don't process further - org trail overrides everything
                continue

            if trail_info["is_multi_region"]:
                # Check if this is Control Tower managed
                is_control_tower = trail_name.startswith("aws-controltower")

                # Check if this is a baseline-managed trail
                # If so, mark as not existing so Terraform continues to manage it
                is_baseline_managed = trail_name == f"{resource_prefix}-trail"

                if is_control_tower:
                    result["multi_region_trail_exists"] = True
                    result["is_control_tower_managed"] = True
                elif is_baseline_managed:
                    result["multi_region_trail_exists"] = False
                    result["is_baseline_managed"] = True
                else:
                    # External trail (not CT, not baseline)
                    result["multi_region_trail_exists"] = True

                result["multi_region_trail_name"] = trail_name
                result["multi_region_trail_bucket"] = trail_info["s3_bucket"]
    except ClientError as e:
        print(f"Warning: CloudTrail discovery error: {e}", file=sys.stderr)

    return result


def discover_security_hub(region: str) -> dict:
    """Discover Security Hub state in a region."""
    client = boto3.client("securityhub", region_name=region)
    result = {"enabled": False, "is_org_managed": False}

    try:
        # Check if Security Hub is enabled
        hub = client.describe_hub()
        result["enabled"] = True
        result["hub_arn"] = hub.get("HubArn", "")
        result["auto_enable_controls"] = hub.get("AutoEnableControls", False)

        # Check if this account is managed by an organization administrator
        try:
            admin = client.get_administrator_account()
            if admin.get("Administrator", {}).get("AccountId"):
                result["is_org_managed"] = True
                result["administrator_account_id"] = admin["Administrator"]["AccountId"]
        except ClientError as e:
            # No administrator = not org-managed, which is fine
            if e.response["Error"]["Code"] not in [
                "InvalidAccessException",
                "ResourceNotFoundException",
            ]:
                print(
                    f"Warning: Security Hub admin check error in {region}: {e}",
                    file=sys.stderr,
                )

        # Get enabled standards
        standards = client.get_enabled_standards()
        result["enabled_standards"] = []
        for std in standards.get("StandardsSubscriptions", []):
            arn = std.get("StandardsArn", "")
            if "nist-800-53" in arn.lower():
                result["enabled_standards"].append("NIST-800-53")
            elif "cis-aws-foundations-benchmark" in arn.lower():
                result["enabled_standards"].append("CIS")
            elif "aws-foundational-security-best-practices" in arn.lower():
                result["enabled_standards"].append("AFSBP")
            elif "pci-dss" in arn.lower():
                result["enabled_standards"].append("PCI-DSS")

        # Check for finding aggregator (only relevant in aggregator region)
        if region == "us-east-1":
            try:
                aggregators = client.list_finding_aggregators()
                result["has_aggregator"] = (
                    len(aggregators.get("FindingAggregators", [])) > 0
                )
            except ClientError:
                result["has_aggregator"] = False

    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        if error_code in ["InvalidAccessException", "ResourceNotFoundException"]:
            # Security Hub not enabled
            pass
        else:
            print(
                f"Warning: Security Hub discovery error in {region}: {e}",
                file=sys.stderr,
            )

    return result


def discover_inspector(region: str, current_account_id: str) -> dict:
    """Discover Inspector v2 state in a region."""
    client = boto3.client("inspector2", region_name=region)
    result = {"enabled": False, "resource_types": [], "is_org_managed": False}

    try:
        # Get account status
        status = client.batch_get_account_status(accountIds=[current_account_id])

        for account in status.get("accounts", []):
            state = account.get("state", {})
            if state.get("status") == "ENABLED":
                result["enabled"] = True

            # Check resource types
            # Map API names to Terraform resource type names
            resource_type_map = {
                "ec2": "EC2",
                "ecr": "ECR",
                "lambda": "LAMBDA",
                "lambdaCode": "LAMBDA_CODE",  # API returns "lambdaCode", Terraform expects "LAMBDA_CODE"
            }
            resource_state = account.get("resourceState", {})
            for api_name, tf_name in resource_type_map.items():
                type_state = resource_state.get(api_name, {})
                if type_state.get("status") == "ENABLED":
                    result["resource_types"].append(tf_name)

        # Check if Inspector is org-managed (delegated admin exists and is different from this account)
        try:
            delegated = client.get_delegated_admin_account()
            delegated_account_id = delegated.get("delegatedAdmin", {}).get("accountId")
            if delegated_account_id and delegated_account_id != current_account_id:
                result["is_org_managed"] = True
                result["delegated_admin_account_id"] = delegated_account_id
        except ClientError as e:
            # No delegated admin = not org-managed, or access denied (member accounts may not have access)
            error_code = e.response["Error"]["Code"]
            if error_code == "AccessDeniedException":
                # If we can't check delegated admin but Inspector is already enabled,
                # it's likely org-managed (member accounts have limited access)
                if result["enabled"]:
                    result["is_org_managed"] = True
            elif error_code not in ["ResourceNotFoundException"]:
                print(
                    f"Warning: Inspector delegated admin check error in {region}: {e}",
                    file=sys.stderr,
                )

    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        if error_code in ["AccessDeniedException"]:
            # Inspector not enabled or no permission
            pass
        else:
            print(
                f"Warning: Inspector discovery error in {region}: {e}", file=sys.stderr
            )

    return result


def discover_guardduty(region: str, current_account_id: str) -> dict:
    """Discover GuardDuty state in a region.

    Detects:
    - GuardDuty enabled status
    - Organization-managed GuardDuty (delegated admin exists)
    - Detector configuration
    """
    client = boto3.client("guardduty", region_name=region)
    result = {
        "enabled": False,
        "is_org_managed": False,
        "detector_id": None,
    }

    try:
        # List detectors
        detectors = client.list_detectors()
        detector_ids = detectors.get("DetectorIds", [])

        if detector_ids:
            detector_id = detector_ids[0]
            result["detector_id"] = detector_id

            # Get detector details
            try:
                detector = client.get_detector(DetectorId=detector_id)
                status = detector.get("Status", "DISABLED")
                result["enabled"] = status == "ENABLED"
            except ClientError:
                pass

        # Check if GuardDuty is org-managed (delegated admin exists)
        # Only check if we have a detector
        if result["detector_id"]:
            try:
                # Try to get the administrator account (for member accounts)
                admin = client.get_administrator_account(
                    DetectorId=result["detector_id"]
                )
                if admin.get("Administrator", {}).get("AccountId"):
                    result["is_org_managed"] = True
                    result["administrator_account_id"] = admin["Administrator"][
                        "AccountId"
                    ]
            except ClientError as e:
                error_code = e.response["Error"]["Code"]
                if error_code == "BadRequestException":
                    # This account might be the admin itself, check for delegated admin
                    try:
                        org_client = boto3.client(
                            "organizations", region_name="us-east-1"
                        )
                        delegated = org_client.list_delegated_administrators(
                            ServicePrincipal="guardduty.amazonaws.com"
                        )
                        admins = delegated.get("DelegatedAdministrators", [])
                        if admins:
                            admin_id = admins[0]["Id"]
                            if admin_id != current_account_id:
                                result["is_org_managed"] = True
                                result["delegated_admin_account_id"] = admin_id
                    except ClientError:
                        # Can't check org - might not have permissions
                        pass
                elif error_code not in [
                    "InvalidAccessException",
                    "ResourceNotFoundException",
                ]:
                    # Unexpected error
                    pass

    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        if error_code not in ["AccessDeniedException", "BadRequestException"]:
            print(
                f"Warning: GuardDuty discovery error in {region}: {e}", file=sys.stderr
            )

    return result


def get_account_info() -> dict:
    """Get basic account information."""
    sts = boto3.client("sts")
    identity = sts.get_caller_identity()
    return {"account_id": identity["Account"], "caller_arn": identity["Arn"]}


def discover_s3_bucket(bucket_name: str, resource_prefix: str) -> dict:
    """Check if S3 bucket exists.

    Baseline buckets (logs, access-logging, tfstate) are managed by Terraform.
    We always report them as not existing so Terraform continues to manage them.
    Resources are imported into Terraform state by entrypoint.sh.
    """
    client = boto3.client("s3", region_name="us-east-1")
    result = {"exists": False, "name": bucket_name}

    try:
        client.head_bucket(Bucket=bucket_name)

        # Baseline buckets are managed by Terraform - mark as not existing
        # so Terraform continues to manage them across runs
        is_baseline_bucket = (
            f"{resource_prefix}-security-logging-" in bucket_name
            or f"{resource_prefix}-access-logging-" in bucket_name
            or f"{resource_prefix}-tfstate-" in bucket_name
        )

        if is_baseline_bucket:
            # Mark as not existing so Terraform keeps managing it
            result["exists"] = False
        else:
            # External bucket - report actual state
            result["exists"] = True

    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        if error_code == "404":
            result["exists"] = False
        elif error_code == "403":
            # Bucket exists but we don't have access - assume external
            result["exists"] = True
        else:
            print(f"Warning: S3 bucket discovery error: {e}", file=sys.stderr)

    return result


def main():
    """Main discovery function."""
    print("Starting AWS account discovery...", file=sys.stderr)

    # Load configuration
    config = load_config()
    print("Configuration loaded", file=sys.stderr)

    # Get resource prefix from config
    resource_prefix = config.get("resource_prefix", "secops")
    print(f"Resource prefix: {resource_prefix}", file=sys.stderr)

    # Get account info
    account_info = get_account_info()
    print(f"Account: {account_info['account_id']}", file=sys.stderr)

    # Expected bucket names
    logging_bucket_name = (
        f"{resource_prefix}-security-logging-{account_info['account_id']}-us-east-1"
    )

    discovery_result = {
        "account": account_info,
        "regions": TARGET_REGIONS,
        "logging_bucket": {},
        "config": {},
        "cloudtrail": {},
        "security_hub": {},
        "inspector": {},
        "guardduty": {},
    }

    # Get current account ID for org-management detection
    current_account_id = account_info["account_id"]

    # Discover S3 buckets
    print("Discovering S3 logging bucket...", file=sys.stderr)
    discovery_result["logging_bucket"] = discover_s3_bucket(
        logging_bucket_name, resource_prefix
    )
    discovery_result["logging_bucket"]["name"] = logging_bucket_name

    # Discover CloudTrail (global)
    print("Discovering CloudTrail...", file=sys.stderr)
    discovery_result["cloudtrail"] = discover_cloudtrail(resource_prefix)

    # Discover regional services
    for region in TARGET_REGIONS:
        print(f"Discovering services in {region}...", file=sys.stderr)

        discovery_result["config"][region] = discover_config(
            region, resource_prefix, current_account_id
        )
        discovery_result["security_hub"][region] = discover_security_hub(region)
        discovery_result["inspector"][region] = discover_inspector(
            region, current_account_id
        )
        discovery_result["guardduty"][region] = discover_guardduty(
            region, current_account_id
        )

    # Generate Terraform variables
    tfvars = generate_tfvars(discovery_result, config)

    # Output discovery result
    print("\n=== Discovery Complete ===", file=sys.stderr)
    print(json.dumps(discovery_result, indent=2, default=str))

    # Write tfvars file
    tfvars_path = "/work/terraform/bootstrap.auto.tfvars.json"
    with open(tfvars_path, "w", encoding="utf-8") as f:
        json.dump(tfvars, f, indent=2, default=str)
    print(f"\nTerraform variables written to {tfvars_path}", file=sys.stderr)

    return discovery_result


def generate_tfvars(discovery: dict, config: dict) -> dict:
    """Generate Terraform variables from discovery results."""
    lifecycle = config.get("s3_lifecycle", {})
    alternate_contacts = config.get("alternate_contacts", {})
    vpc_config = config.get("vpc_block_public_access", {})

    # Get custom tags from config, merge with default ManagedBy tag
    custom_tags = config.get("tags", {})
    default_tags = {"ManagedBy": "portfolio-aws-account-baseline"}
    all_tags = {**default_tags, **custom_tags}

    tfvars = {
        "account_id": discovery["account"]["account_id"],
        "target_regions": TARGET_REGIONS,
        "aggregator_region": "us-east-1",
        "resource_prefix": config.get("resource_prefix", "secops"),
        # Tags to apply to all resources
        "tags": all_tags,
        # VPC Block Public Access configuration
        "vpc_block_public_access_mode": vpc_config.get("mode", "ingress"),
        # S3 bucket state
        "logging_bucket_exists": discovery["logging_bucket"]["exists"],
        # S3 lifecycle settings from config
        "s3_lifecycle_config_logging": lifecycle.get("config_logging", {}),
        "s3_lifecycle_access_logging": lifecycle.get("access_logging", {}),
        "s3_lifecycle_tfstate": lifecycle.get("tfstate", {"transition_to_ia_days": 90}),
        # CloudWatch Logs settings
        "cloudwatch_logs_retention_days": lifecycle.get("cloudwatch_logs", {}).get(
            "retention_days", 365
        ),
        # Alternate Contacts from config
        "enable_alternate_contacts": alternate_contacts.get(
            "enable_alternate_contacts", False
        ),
        "billing_contact": alternate_contacts.get(
            "billing_contact", {"name": "", "title": "", "email": "", "phone": ""}
        ),
        "operations_contact": alternate_contacts.get(
            "operations_contact", {"name": "", "title": "", "email": "", "phone": ""}
        ),
        "security_contact": alternate_contacts.get(
            "security_contact", {"name": "", "title": "", "email": "", "phone": ""}
        ),
        # Config state per region
        "config_exists": {
            region: discovery["config"][region]["exists"] for region in TARGET_REGIONS
        },
        # Check if ANY region has Control Tower Config
        "config_is_control_tower_managed": any(
            discovery["config"][region].get("is_control_tower_managed", False)
            for region in TARGET_REGIONS
        ),
        # Config org-management detection - if ANY region delivers to external bucket
        "config_is_org_managed": any(
            discovery["config"][region].get("is_org_managed", False)
            for region in TARGET_REGIONS
        ),
        # CloudTrail state
        "cloudtrail_multi_region_exists": discovery["cloudtrail"][
            "multi_region_trail_exists"
        ],
        "cloudtrail_is_control_tower_managed": discovery["cloudtrail"].get(
            "is_control_tower_managed", False
        ),
        "cloudtrail_trail_name": discovery["cloudtrail"].get(
            "multi_region_trail_name", ""
        ),
        # Organization trail detection - org-baseline creates org trails
        "cloudtrail_is_org_trail": discovery["cloudtrail"].get("is_org_trail", False),
        # Control Tower detection - if CT manages CloudTrail OR Config, skip both services
        # CT manages CloudTrail and Config together, so detecting either means CT is in control
        "control_tower_exists": (
            discovery["cloudtrail"].get("is_control_tower_managed", False)
            or any(
                discovery["config"][region].get("is_control_tower_managed", False)
                for region in TARGET_REGIONS
            )
        ),
        # Security Hub state per region
        "security_hub_enabled": {
            region: discovery["security_hub"][region]["enabled"]
            for region in TARGET_REGIONS
        },
        "security_hub_standards": {
            region: discovery["security_hub"][region].get("enabled_standards", [])
            for region in TARGET_REGIONS
        },
        "security_hub_has_aggregator": discovery["security_hub"]
        .get("us-east-1", {})
        .get("has_aggregator", False),
        # Security Hub org-management detection - if ANY region shows org-managed, skip all regions
        "security_hub_is_org_managed": any(
            discovery["security_hub"][region].get("is_org_managed", False)
            for region in TARGET_REGIONS
        ),
        # Security Hub disabled controls from config (align with org-baseline)
        "security_hub_disabled_controls": config.get("security_hub", {}).get(
            "disabled_controls", []
        ),
        # Inspector state per region
        "inspector_enabled": {
            region: discovery["inspector"][region]["enabled"]
            for region in TARGET_REGIONS
        },
        "inspector_resource_types": {
            region: discovery["inspector"][region].get("resource_types", [])
            for region in TARGET_REGIONS
        },
        # Inspector org-management detection - if ANY region shows org-managed, skip all regions
        "inspector_is_org_managed": any(
            discovery["inspector"][region].get("is_org_managed", False)
            for region in TARGET_REGIONS
        ),
        # GuardDuty state per region
        "guardduty_enabled": {
            region: discovery["guardduty"][region]["enabled"]
            for region in TARGET_REGIONS
        },
        # GuardDuty org-management detection - if ANY region shows org-managed, skip all regions
        "guardduty_is_org_managed": any(
            discovery["guardduty"][region].get("is_org_managed", False)
            for region in TARGET_REGIONS
        ),
    }

    return tfvars


if __name__ == "__main__":
    main()
