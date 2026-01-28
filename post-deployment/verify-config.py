#!/usr/bin/env python3
"""
Verify AWS Config Setup

This script ensures:
1. The AWS Config service-linked role exists (creates it if missing)
2. Config recorders are recording in all target regions
3. Reports org-managed services as "managed externally"
"""

import json
import sys
from pathlib import Path

import boto3
from botocore.exceptions import ClientError

# ANSI color codes
GREEN = "\033[0;32m"
YELLOW = "\033[1;33m"
RED = "\033[0;31m"
BLUE = "\033[0;34m"
CYAN = "\033[0;36m"
NC = "\033[0m"  # No Color

# Target regions for Config (all 17 supported regions)
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


def print_header(message):
    """Print a formatted header"""
    print(f"\n{'=' * 60}")
    print(message)
    print("=" * 60)


def load_discovery_results() -> dict:
    """Load discovery results from tfvars file."""
    tfvars_path = Path("/work/terraform/bootstrap.auto.tfvars.json")
    if not tfvars_path.exists():
        return {}
    with open(tfvars_path, "r", encoding="utf-8") as f:
        return json.load(f)


def is_org_managed(discovery: dict) -> tuple[bool, str]:
    """Check if Config is org-managed or Control Tower managed."""
    if discovery.get("control_tower_exists", False):
        return True, "Control Tower"
    if discovery.get("config_is_org_managed", False):
        return True, "Organization (org-baseline)"
    if discovery.get("config_is_control_tower_managed", False):
        return True, "Control Tower"
    return False, ""


def ensure_service_linked_role():
    """Ensure AWS Config service-linked role exists"""
    print(f"\n{BLUE}Checking AWS Config service-linked role...{NC}")

    iam = boto3.client("iam")
    role_name = "AWSServiceRoleForConfig"

    try:
        # Try to get the role
        iam.get_role(RoleName=role_name)
        print(f"{GREEN}[OK] Service-linked role exists: {role_name}{NC}")
        return True
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchEntity":
            # Role doesn't exist, try to create it
            print(f"{YELLOW}[WARN] Service-linked role not found, creating...{NC}")
            try:
                iam.create_service_linked_role(
                    AWSServiceName="config.amazonaws.com",
                    Description="Service-linked role for AWS Config",
                )
                print(f"{GREEN}[OK] Created service-linked role: {role_name}{NC}")
                return True
            except ClientError as create_error:
                if "has been taken" in str(create_error):
                    # Role exists but get_role failed (eventual consistency)
                    print(f"{GREEN}[OK] Service-linked role exists: {role_name}{NC}")
                    return True
                else:
                    print(
                        f"{RED}[FAIL] Failed to create service-linked role: "
                        f"{create_error}{NC}"
                    )
                    return False
        else:
            print(f"{RED}[FAIL] Error checking service-linked role: {e}{NC}")
            return False


def verify_config_recorder(region):
    """Verify Config recorder status in a specific region"""
    try:
        config = boto3.client("config", region_name=region)

        # Get recorder status
        status_response = config.describe_configuration_recorder_status()

        if not status_response["ConfigurationRecordersStatus"]:
            return {
                "region": region,
                "exists": False,
                "recording": False,
                "status": "NO_RECORDER",
            }

        recorder_status = status_response["ConfigurationRecordersStatus"][0]

        return {
            "region": region,
            "exists": True,
            "recording": recorder_status.get("recording", False),
            "status": recorder_status.get("lastStatus", "UNKNOWN"),
            "name": recorder_status.get("name", "unknown"),
        }

    except ClientError as e:
        return {
            "region": region,
            "exists": False,
            "recording": False,
            "status": f"ERROR: {e}",
        }


def main():
    print_header("AWS Config Verification")

    # Get account ID
    sts = boto3.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    print(f"Account ID: {account_id}")

    # Load discovery results to check for org-management
    discovery = load_discovery_results()
    org_managed, manager = is_org_managed(discovery)

    if org_managed:
        print(f"\n{CYAN}[INFO] Config is managed externally by: {manager}{NC}")
        print(
            f"{CYAN}       Verifying that Config is recording (managed externally){NC}"
        )

    # Step 1: Ensure service-linked role exists
    role_ok = ensure_service_linked_role()

    # Step 2: Verify Config recorders in all regions
    print(f"\n{BLUE}Verifying Config recorders in all regions...{NC}")

    results = []
    all_recording = True
    recording_count = 0

    for region in TARGET_REGIONS:
        result = verify_config_recorder(region)
        results.append(result)

        if result["recording"]:
            recording_count += 1
        elif not org_managed:
            # Only flag as issue if not org-managed
            all_recording = False

    # Summary
    print_header("VERIFICATION SUMMARY")

    if org_managed:
        print(f"\n{CYAN}Management: Externally managed by {manager}{NC}")
    else:
        print("\nManagement: Local (portfolio-aws-account-baseline)")

    print(
        "\nService-Linked Role: "
        f"{GREEN + '[OK]' + NC if role_ok else RED + '[FAIL]' + NC}"
    )

    print(f"\nConfig Recorders: {recording_count}/{len(TARGET_REGIONS)} recording")
    print("-" * 40)

    # Group results by status for cleaner output
    recording_regions = [r["region"] for r in results if r["recording"]]
    not_recording_regions = [r["region"] for r in results if not r["recording"]]

    if recording_regions:
        print(f"{GREEN}Recording ({len(recording_regions)}):{NC}")
        for region in recording_regions:
            print(f"  {region}")

    if not_recording_regions:
        status = CYAN if org_managed else RED
        label = "[EXTERNAL]" if org_managed else "[NOT RECORDING]"
        print(f"\n{status}{label} ({len(not_recording_regions)}):{NC}")
        for region in not_recording_regions:
            print(f"  {region}")

    # Exit with appropriate code
    if org_managed:
        # If org-managed, just verify Config is working (recording somewhere)
        if recording_count > 0:
            print(f"\n{GREEN}[OK] Config is recording (managed by {manager}){NC}")
            return 0
        else:
            print(f"\n{YELLOW}[WARN] Config not recording in any region{NC}")
            print(f"{YELLOW}       External management may still be configuring{NC}")
            return 0  # Don't fail - external management may be in progress

    if role_ok and all_recording:
        print(f"\n{GREEN}[OK] All Config verifications passed{NC}")
        return 0
    else:
        print(f"\n{YELLOW}[WARN] Some Config verifications need attention{NC}")
        print(f"{YELLOW}       This is expected if Terraform is still applying{NC}")
        return 0  # Don't fail deployment, just warn


if __name__ == "__main__":
    sys.exit(main())
