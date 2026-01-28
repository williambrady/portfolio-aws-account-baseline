#!/usr/bin/env python3
"""
AWS Default VPC Cleanup Script for Account Baseline

This script enumerates and deletes all default VPCs across all active regions
in an AWS account. Default VPCs can pose security risks and should be removed
as part of security best practices.

This script:
1. Enumerates all active AWS regions
2. Identifies default VPCs in each region
3. Safely deletes default VPC components in the correct order:
   - Internet Gateway attachments
   - Route table associations
   - Network ACL associations
   - Security group rules
   - Subnets
   - Internet Gateways
   - Route tables (non-main)
   - Network ACLs (non-default)
   - Security groups (non-default)
   - VPC

Prerequisites:
- AWS credentials configured (environment variables or ~/.aws)
- EC2 permissions: DescribeVpcs, DescribeRegions, DeleteVpc, etc.
- No running instances in default VPCs

Usage:
    # Dry run (recommended first)
    python post-deployment/cleanup-default-vpcs.py --dry-run

    # Execute cleanup (automated - no prompts)
    python post-deployment/cleanup-default-vpcs.py
"""

import argparse
import sys
from typing import Dict, List, Optional

import boto3
from botocore.exceptions import ClientError, NoCredentialsError


def get_all_regions(ec2_client) -> List[str]:
    """Get all active AWS regions."""
    try:
        print("🔍 Discovering all active AWS regions...")
        response = ec2_client.describe_regions()
        regions = [region["RegionName"] for region in response["Regions"]]
        print(f"📍 Found {len(regions)} active AWS regions")
        return sorted(regions)
    except Exception as e:
        print(f"❌ Failed to get regions: {e}")
        sys.exit(1)


def get_default_vpc(ec2_client, region: str) -> Optional[Dict]:
    """Get the default VPC in a specific region."""
    try:
        response = ec2_client.describe_vpcs(
            Filters=[{"Name": "is-default", "Values": ["true"]}]
        )

        if response["Vpcs"]:
            vpc = response["Vpcs"][0]
            print(f"  🔍 Found default VPC: {vpc['VpcId']} ({vpc['CidrBlock']})")
            return vpc
        else:
            print(f"  ✅ No default VPC found in {region}")
            return None

    except Exception as e:
        print(f"  ❌ Error checking default VPC in {region}: {e}")
        return None


def delete_vpc_dependencies(
    ec2_client, vpc_id: str, region: str, dry_run: bool = False
) -> bool:
    """Delete all VPC dependencies in the correct order."""
    try:
        print(f"  🔧 Cleaning up dependencies for VPC {vpc_id}")

        # 1. Detach and delete Internet Gateways
        igws = ec2_client.describe_internet_gateways(
            Filters=[{"Name": "attachment.vpc-id", "Values": [vpc_id]}]
        )

        for igw in igws["InternetGateways"]:
            igw_id = igw["InternetGatewayId"]
            print(f"    🌐 Processing Internet Gateway: {igw_id}")

            # Detach from VPC
            if not dry_run:
                try:
                    ec2_client.detach_internet_gateway(
                        InternetGatewayId=igw_id, VpcId=vpc_id
                    )
                    print(f"    ✅ Detached IGW {igw_id} from VPC")
                except ClientError as e:
                    print(f"    ⚠️  Failed to detach IGW {igw_id}: {e}")

            # Delete Internet Gateway
            if not dry_run:
                try:
                    ec2_client.delete_internet_gateway(InternetGatewayId=igw_id)
                    print(f"    ✅ Deleted Internet Gateway: {igw_id}")
                except ClientError as e:
                    print(f"    ⚠️  Failed to delete IGW {igw_id}: {e}")
            else:
                print(f"    🔍 [DRY RUN] Would delete Internet Gateway: {igw_id}")

        # 2. Delete Subnets
        subnets = ec2_client.describe_subnets(
            Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]
        )

        for subnet in subnets["Subnets"]:
            subnet_id = subnet["SubnetId"]
            print(f"    🏠 Processing Subnet: {subnet_id}")

            if not dry_run:
                try:
                    ec2_client.delete_subnet(SubnetId=subnet_id)
                    print(f"    ✅ Deleted Subnet: {subnet_id}")
                except ClientError as e:
                    print(f"    ⚠️  Failed to delete subnet {subnet_id}: {e}")
            else:
                print(f"    🔍 [DRY RUN] Would delete Subnet: {subnet_id}")

        # 3. Delete Security Groups (except default)
        security_groups = ec2_client.describe_security_groups(
            Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]
        )

        for sg in security_groups["SecurityGroups"]:
            if sg["GroupName"] != "default":
                sg_id = sg["GroupId"]
                print(f"    🛡️  Processing Security Group: {sg_id} ({sg['GroupName']})")

                if not dry_run:
                    try:
                        ec2_client.delete_security_group(GroupId=sg_id)
                        print(f"    ✅ Deleted Security Group: {sg_id}")
                    except ClientError as e:
                        print(f"    ⚠️  Failed to delete security group {sg_id}: {e}")
                else:
                    print(f"    🔍 [DRY RUN] Would delete Security Group: {sg_id}")

        # 4. Delete Route Tables (except main)
        route_tables = ec2_client.describe_route_tables(
            Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]
        )

        for rt in route_tables["RouteTables"]:
            # Skip main route table
            is_main = any(
                assoc.get("Main", False) for assoc in rt.get("Associations", [])
            )
            if not is_main:
                rt_id = rt["RouteTableId"]
                print(f"    🛣️  Processing Route Table: {rt_id}")

                if not dry_run:
                    try:
                        ec2_client.delete_route_table(RouteTableId=rt_id)
                        print(f"    ✅ Deleted Route Table: {rt_id}")
                    except ClientError as e:
                        print(f"    ⚠️  Failed to delete route table {rt_id}: {e}")
                else:
                    print(f"    🔍 [DRY RUN] Would delete Route Table: {rt_id}")

        # 5. Delete Network ACLs (except default)
        network_acls = ec2_client.describe_network_acls(
            Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]
        )

        for nacl in network_acls["NetworkAcls"]:
            if not nacl["IsDefault"]:
                nacl_id = nacl["NetworkAclId"]
                print(f"    🚧 Processing Network ACL: {nacl_id}")

                if not dry_run:
                    try:
                        ec2_client.delete_network_acl(NetworkAclId=nacl_id)
                        print(f"    ✅ Deleted Network ACL: {nacl_id}")
                    except ClientError as e:
                        print(f"    ⚠️  Failed to delete network ACL {nacl_id}: {e}")
                else:
                    print(f"    🔍 [DRY RUN] Would delete Network ACL: {nacl_id}")

        return True

    except Exception as e:
        print(f"    ❌ Error cleaning up VPC dependencies: {e}")
        return False


def delete_default_vpc(
    ec2_client, vpc_id: str, region: str, dry_run: bool = False
) -> str:
    """Delete the default VPC after cleaning up dependencies.

    Returns:
        'success' - VPC was deleted
        'skipped' - VPC has dependencies (not an error, will be cleaned up later)
        'failed' - Actual error occurred
    """
    try:
        print(f"  🗑️  Deleting default VPC: {vpc_id}")

        if not dry_run:
            ec2_client.delete_vpc(VpcId=vpc_id)
            print(f"  ✅ Successfully deleted default VPC: {vpc_id}")
        else:
            print(f"  🔍 [DRY RUN] Would delete default VPC: {vpc_id}")

        return "success"

    except ClientError as e:
        if e.response["Error"]["Code"] == "DependencyViolation":
            print(
                f"  ⚠️  VPC {vpc_id} has active dependencies - skipping (will be cleaned up in follow-up)"
            )
            print("  💡 There may be running instances or other resources in this VPC")
            return "skipped"
        else:
            print(f"  ❌ Failed to delete VPC {vpc_id}: {e}")
            return "failed"
    except Exception as e:
        print(f"  ❌ Unexpected error deleting VPC {vpc_id}: {e}")
        return "failed"


def cleanup_default_vpcs_in_account(
    session: boto3.Session, dry_run: bool = False
) -> Dict[str, str]:
    """Clean up default VPCs in all regions of an account.

    Returns:
        Dict mapping region to status: 'success', 'skipped', or 'failed'
    """
    # Get all regions using us-east-1 as the base region
    ec2_base = session.client("ec2", region_name="us-east-1")
    regions = get_all_regions(ec2_base)

    results = {}

    for i, region in enumerate(regions, 1):
        print(f"\n📍 Processing region {i}/{len(regions)}: {region}")

        try:
            ec2_client = session.client("ec2", region_name=region)

            # Check for default VPC
            default_vpc = get_default_vpc(ec2_client, region)

            if default_vpc:
                vpc_id = default_vpc["VpcId"]

                # Check if VPC is in use by looking for ENIs
                enis = ec2_client.describe_network_interfaces(
                    Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]
                )["NetworkInterfaces"]

                if enis:
                    print(
                        f"  ⏭️  VPC {vpc_id} has {len(enis)} active ENI(s) - skipping to avoid partial cleanup"
                    )
                    results[region] = "skipped"
                    continue

                # Clean up dependencies first
                deps_cleaned = delete_vpc_dependencies(
                    ec2_client, vpc_id, region, dry_run
                )

                if deps_cleaned:
                    # Delete the VPC
                    result = delete_default_vpc(ec2_client, vpc_id, region, dry_run)
                    results[region] = result
                    if result == "success":
                        print(f"  ✅ Successfully processed {region}")
                    elif result == "skipped":
                        print(f"  ⏭️  Skipped {region} (VPC has active dependencies)")
                    else:
                        print(f"  ❌ Failed to delete VPC in {region}")
                else:
                    print(f"  ❌ Failed to clean dependencies in {region}")
                    results[region] = "failed"
            else:
                results[region] = "success"  # No default VPC to delete

        except Exception as e:
            print(f"  ❌ Error processing region {region}: {e}")
            results[region] = "failed"

    return results


def main():
    """Main function."""
    parser = argparse.ArgumentParser(
        description="Clean up default VPCs across all AWS regions",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be deleted without actually deleting",
    )

    args = parser.parse_args()

    try:
        # Create AWS session (uses environment variables or ~/.aws credentials)
        session = boto3.Session()

        # Get account ID
        sts_client = session.client("sts")
        caller_identity = sts_client.get_caller_identity()
        account_id = caller_identity["Account"]

        print("=" * 60)
        print("AWS Default VPC Cleanup Script")
        print("=" * 60)
        print(f"Account ID: {account_id}")
        print(f"Mode: {'DRY RUN' if args.dry_run else 'EXECUTE'}")
        print("=" * 60)

        if args.dry_run:
            print("ℹ️  DRY RUN MODE: No resources will be deleted")
        else:
            print("⚠️  EXECUTE MODE: Resources will be permanently deleted")

        # Clean up default VPCs
        results = cleanup_default_vpcs_in_account(session, args.dry_run)

        # Print summary
        print("\n" + "=" * 60)
        print("CLEANUP SUMMARY")
        print("=" * 60)

        success_count = sum(1 for status in results.values() if status == "success")
        skipped_count = sum(1 for status in results.values() if status == "skipped")
        failed_count = sum(1 for status in results.values() if status == "failed")
        total_count = len(results)

        for region, status in results.items():
            if status == "success":
                display = "✅ SUCCESS"
            elif status == "skipped":
                display = "⏭️  SKIPPED (has dependencies)"
            else:
                display = "❌ FAILED"
            print(f"{region:20} {display}")

        print(f"\nTotal regions processed: {total_count}")
        print(f"Successful cleanups: {success_count}")
        print(f"Skipped (dependencies): {skipped_count}")
        print(f"Failed: {failed_count}")

        if failed_count == 0:
            if skipped_count > 0:
                print(
                    f"\n✅ Completed! {skipped_count} VPC(s) skipped due to active dependencies (will be cleaned up in follow-up)"
                )
            else:
                print("\n🎉 All default VPCs cleaned up successfully!")
            return 0
        else:
            print(f"\n❌ {failed_count} region(s) had errors")
            return 1

    except NoCredentialsError:
        print("❌ AWS credentials not found. Please configure your credentials.")
        return 1
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        import traceback

        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
