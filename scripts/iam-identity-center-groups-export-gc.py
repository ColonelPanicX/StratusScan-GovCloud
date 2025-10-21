#!/usr/bin/env python3

"""
===========================
= AWS GOVCLOUD RESOURCE SCANNER =
===========================

Title: AWS GovCloud IAM Identity Center Groups Export Script
Version: v1.0.0-GovCloud
Date: SEP-23-2025

Description:
This script specifically exports IAM Identity Center (formerly AWS SSO) groups from AWS GovCloud
environments. It provides detailed group information including members, external IDs, and metadata
for security auditing and compliance reporting.

GovCloud Modifications:
- Added GovCloud environment validation
- Updated partition handling for aws-us-gov
- Added GovCloud-specific compliance markers in output filenames
- Enhanced error handling for GovCloud-specific service limitations
- Integration with StratusScan GovCloud utils module

Collected information includes: Group details, member counts, external IDs, creation dates,
and modification timestamps for comprehensive group governance analysis.
"""

import os
import sys
import boto3
import datetime
import time
from pathlib import Path
from botocore.exceptions import ClientError, NoCredentialsError

# Add path to import utils module
try:
    # Try to import directly (if utils_govcloud.py is in Python path)
    import utils_govcloud as utils
except ImportError:
    # If import fails, try to find the module relative to this script
    script_dir = Path(__file__).parent.absolute()

    # Check if we're in the scripts directory
    if script_dir.name.lower() == 'scripts':
        # Add the parent directory (StratusScan root) to the path
        sys.path.append(str(script_dir.parent))
    else:
        # Add the current directory to the path
        sys.path.append(str(script_dir))

    # Try import again
    try:
        import utils_govcloud as utils
    except ImportError:
        print("ERROR: Could not import the utils_govcloud module. Make sure utils_govcloud.py is in the StratusScan directory.")
        sys.exit(1)

def check_dependencies():
    """
    Check if required dependencies are installed and offer to install them if missing.

    Returns:
        bool: True if all dependencies are satisfied, False otherwise
    """
    required_packages = ['pandas', 'openpyxl']
    missing_packages = []

    for package in required_packages:
        try:
            __import__(package)
            utils.log_info(f"[OK] {package} is already installed")
        except ImportError:
            missing_packages.append(package)

    if missing_packages:
        utils.log_warning(f"Packages required but not installed: {', '.join(missing_packages)}")
        response = input("Would you like to install these packages now? (y/n): ").lower().strip()

        if response == 'y':
            import subprocess
            for package in missing_packages:
                utils.log_info(f"Installing {package}...")
                try:
                    subprocess.check_call([sys.executable, "-m", "pip", "install", package])
                    utils.log_success(f"{package} installed successfully")
                except subprocess.CalledProcessError as e:
                    utils.log_error(f"Error installing {package}", e)
                    return False
        else:
            print("Cannot continue without required packages. Exiting.")
            return False

    return True

def get_account_info():
    """
    Get the current AWS account ID and name with GovCloud validation.

    Returns:
        tuple: (account_id, account_name)
    """
    try:
        sts = boto3.client('sts')
        account_id = sts.get_caller_identity()['Account']

        # Validate GovCloud environment
        caller_arn = sts.get_caller_identity()['Arn']
        if not utils.is_govcloud_environment():
            utils.log_warning("You appear to be connected to commercial AWS, not GovCloud!")
            utils.log_warning("This script is optimized for AWS GovCloud IL4 environments.")

        # Use utils module for account name mapping
        account_name = utils.get_account_name(account_id, default=f"GOVCLOUD-{account_id}")

        return account_id, account_name
    except Exception as e:
        utils.log_error("Error getting account information", e)
        return "Unknown", "Unknown-GovCloud-Account"

def print_title():
    """
    Print the script title and account information.

    Returns:
        tuple: (account_id, account_name)
    """
    print("====================================================================")
    print("                   AWS RESOURCE SCANNER                            ")
    print("====================================================================")
    print("AWS GOVCLOUD IAM IDENTITY CENTER GROUPS EXPORT")
    print("====================================================================")
    print("Version: v1.0.0-GovCloud                       Date: SEP-23-2025")
    print("Environment: AWS GovCloud IL4 (FedRAMP Moderate)")
    print("====================================================================")

    # Get account information
    account_id, account_name = get_account_info()
    print(f"Account ID: {account_id}")
    print(f"Account Name: {account_name}")
    print("====================================================================")

    return account_id, account_name

def get_identity_center_instance():
    """
    Get the IAM Identity Center instance ARN and Identity Store ID.

    Returns:
        tuple: (instance_arn, identity_store_id) or (None, None) if not configured
    """
    try:
        sso_admin_client = boto3.client('sso-admin', region_name='us-gov-west-1')

        # List Identity Center instances
        response = sso_admin_client.list_instances()
        instances = response.get('Instances', [])

        if not instances:
            utils.log_warning("No IAM Identity Center instances found in this account.")
            utils.log_info("IAM Identity Center may not be enabled or configured.")
            return None, None

        # Use the first instance (typically there's only one)
        instance = instances[0]
        instance_arn = instance['InstanceArn']
        identity_store_id = instance['IdentityStoreId']

        utils.log_success(f"Found IAM Identity Center instance: {instance_arn}")
        return instance_arn, identity_store_id

    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == 'AccessDeniedException':
            utils.log_error("Access denied to IAM Identity Center. Check permissions.")
        elif error_code == 'ResourceNotFoundException':
            utils.log_warning("IAM Identity Center not found or not enabled in this account.")
        else:
            utils.log_error(f"Error accessing IAM Identity Center: {e}")
        return None, None
    except Exception as e:
        utils.log_error("Error getting Identity Center instance", e)
        return None, None

def get_group_members(identitystore_client, identity_store_id, group_id):
    """
    Get detailed member information for a group.

    Args:
        identitystore_client: boto3 identitystore client
        identity_store_id: Identity Store ID
        group_id: Group ID

    Returns:
        list: List of member details
    """
    members = []
    try:
        paginator = identitystore_client.get_paginator('list_group_memberships')

        for page in paginator.paginate(
            IdentityStoreId=identity_store_id,
            GroupId=group_id
        ):
            for membership in page.get('GroupMemberships', []):
                member_id = membership['MemberId']

                # Get member details
                if 'UserId' in member_id:
                    try:
                        user_response = identitystore_client.describe_user(
                            IdentityStoreId=identity_store_id,
                            UserId=member_id['UserId']
                        )
                        member_name = user_response.get('UserName', member_id['UserId'])
                        member_type = 'User'
                        display_name = user_response.get('DisplayName', 'N/A')
                    except Exception:
                        member_name = member_id['UserId']
                        member_type = 'User'
                        display_name = 'N/A'
                elif 'GroupId' in member_id:
                    try:
                        group_response = identitystore_client.describe_group(
                            IdentityStoreId=identity_store_id,
                            GroupId=member_id['GroupId']
                        )
                        member_name = group_response.get('DisplayName', member_id['GroupId'])
                        member_type = 'Group'
                        display_name = group_response.get('DisplayName', 'N/A')
                    except Exception:
                        member_name = member_id['GroupId']
                        member_type = 'Group'
                        display_name = 'N/A'
                else:
                    member_name = 'Unknown'
                    member_type = 'Unknown'
                    display_name = 'N/A'

                members.append({
                    'name': member_name,
                    'type': member_type,
                    'display_name': display_name,
                    'membership_id': membership.get('MembershipId', 'N/A')
                })

    except Exception as e:
        utils.log_warning(f"Could not get members for group {group_id}: {e}")

    return members

def collect_identity_center_groups(identity_store_id):
    """
    Collect IAM Identity Center groups with detailed information.

    Args:
        identity_store_id: The Identity Store ID

    Returns:
        list: List of group information dictionaries
    """
    if not identity_store_id:
        return []

    groups_data = []

    try:
        identitystore_client = boto3.client('identitystore', region_name='us-gov-west-1')

        # Get all groups using pagination
        paginator = identitystore_client.get_paginator('list_groups')

        # Count total groups first for progress tracking
        total_groups = 0
        for page in paginator.paginate(IdentityStoreId=identity_store_id):
            total_groups += len(page.get('Groups', []))

        if total_groups > 0:
            utils.log_info(f"Found {total_groups} Identity Center groups to process")
        else:
            utils.log_warning("No Identity Center groups found")
            return []

        # Reset paginator and process groups
        paginator = identitystore_client.get_paginator('list_groups')
        processed = 0

        for page in paginator.paginate(IdentityStoreId=identity_store_id):
            groups = page.get('Groups', [])

            for group in groups:
                processed += 1
                progress = (processed / total_groups) * 100 if total_groups > 0 else 0
                group_name = group.get('DisplayName', 'Unknown')

                utils.log_info(f"[{progress:.1f}%] Processing group {processed}/{total_groups}: {group_name}")

                # Get detailed group member information
                members = get_group_members(identitystore_client, identity_store_id, group['GroupId'])

                # Format member information
                member_names = [m['name'] for m in members]
                member_types = [m['type'] for m in members]
                user_members = [m['name'] for m in members if m['type'] == 'User']
                group_members = [m['name'] for m in members if m['type'] == 'Group']

                # Get external ID
                external_ids = group.get('ExternalIds', [])
                external_id = external_ids[0].get('Id', 'N/A') if external_ids else 'N/A'

                group_info = {
                    'Group ID': group.get('GroupId', 'N/A'),
                    'Group Name': group.get('DisplayName', 'N/A'),
                    'Description': group.get('Description', 'N/A'),
                    'External ID': external_id,
                    'Total Members': len(members),
                    'User Members': len(user_members),
                    'Group Members': len(group_members),
                    'Member Names': ', '.join(member_names) if member_names else 'None',
                    'User Member Names': ', '.join(user_members) if user_members else 'None',
                    'Group Member Names': ', '.join(group_members) if group_members else 'None',
                    'Created Date': group.get('Meta', {}).get('Created', 'N/A'),
                    'Last Modified': group.get('Meta', {}).get('LastModified', 'N/A'),
                    'Resource Version': group.get('Meta', {}).get('ResourceType', 'N/A')
                }

                groups_data.append(group_info)

                # Small delay to avoid API throttling
                time.sleep(0.1)

    except Exception as e:
        utils.log_error("Error collecting Identity Center groups", e)

    return groups_data

def export_to_excel(groups_data, account_id, account_name):
    """
    Export Identity Center groups data to Excel file with GovCloud naming convention.

    Args:
        groups_data: List of group information dictionaries
        account_id: AWS account ID
        account_name: AWS account name

    Returns:
        str: Filename of exported file or None if failed
    """
    if not groups_data:
        utils.log_warning("No Identity Center groups data to export.")
        return None

    try:
        # Import pandas after dependency check
        import pandas as pd

        # Generate filename with GovCloud identifier
        current_date = datetime.datetime.now().strftime("%m.%d.%Y")

        # Use utils module to generate filename and save data with GovCloud identifier
        filename = utils.create_export_filename(
            account_name,
            "iam-identity-center-groups",
            "",
            current_date
        )

        # Create data frame
        groups_df = pd.DataFrame(groups_data)

        # Create summary data
        total_groups = len(groups_data)
        total_members = sum(group.get('Total Members', 0) for group in groups_data)
        groups_with_users = len([g for g in groups_data if g.get('User Members', 0) > 0])
        groups_with_nested_groups = len([g for g in groups_data if g.get('Group Members', 0) > 0])
        groups_with_external_ids = len([g for g in groups_data if g.get('External ID', 'N/A') != 'N/A'])

        summary_data = {
            'Metric': [
                'Total Groups',
                'Total Members (All Types)',
                'Groups with User Members',
                'Groups with Nested Groups',
                'Groups with External IDs',
                'Empty Groups',
                'Largest Group Size',
                'Average Group Size'
            ],
            'Count': [
                total_groups,
                total_members,
                groups_with_users,
                groups_with_nested_groups,
                groups_with_external_ids,
                len([g for g in groups_data if g.get('Total Members', 0) == 0]),
                max([g.get('Total Members', 0) for g in groups_data]) if groups_data else 0,
                round(total_members / total_groups, 2) if total_groups > 0 else 0
            ]
        }

        summary_df = pd.DataFrame(summary_data)

        # Prepare data frames for multi-sheet export
        data_frames = {
            'Groups Summary': summary_df,
            'Groups Details': groups_df
        }

        # Save using utils function for multi-sheet Excel
        output_path = utils.save_multiple_dataframes_to_excel(data_frames, filename)

        if output_path:
            utils.log_success("GovCloud IAM Identity Center groups data exported successfully!")
            utils.log_info(f"File location: {output_path}")
            utils.log_govcloud_info(f"Export contains {total_groups} groups with {total_members} total members")
            return str(output_path)
        else:
            utils.log_error("Error exporting to Excel. Please check the logs.")
            return None

    except Exception as e:
        utils.log_error("Error exporting to Excel", e)
        return None

def main():
    """
    Main function to orchestrate the Identity Center groups collection.
    """
    try:
        # Check dependencies first
        if not check_dependencies():
            return

        # Import pandas after dependency check
        import pandas as pd

        # Print title and get account info
        account_id, account_name = print_title()

        # Validate GovCloud environment
        if not utils.is_govcloud_environment():
            proceed = input("\nWarning: Not detected as GovCloud environment. Continue anyway? (y/n): ").lower()
            if proceed != 'y':
                print("Exiting script...")
                sys.exit(0)

        try:
            # Test AWS credentials
            sts = boto3.client('sts')
            sts.get_caller_identity()
            utils.log_success("AWS credentials validated")

        except NoCredentialsError:
            utils.log_error("AWS credentials not found. Please configure your credentials using:")
            print("  - AWS CLI: aws configure")
            print("  - Environment variables: AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY")
            print("  - IAM role (if running on EC2)")
            return
        except Exception as e:
            utils.log_error("Error validating AWS credentials", e)
            return

        utils.log_info("Starting IAM Identity Center groups collection from GovCloud...")
        print("====================================================================")

        # Get Identity Center instance
        instance_arn, identity_store_id = get_identity_center_instance()

        if not identity_store_id:
            utils.log_error("Could not find IAM Identity Center instance. Exiting.")
            return

        # Collect Identity Center groups
        utils.log_info("Collecting Identity Center groups...")
        groups_data = collect_identity_center_groups(identity_store_id)

        if not groups_data:
            utils.log_warning("No Identity Center groups collected. Exiting.")
            return

        print("\n====================================================================")
        print("COLLECTION COMPLETE")
        print("====================================================================")

        # Export to Excel
        filename = export_to_excel(groups_data, account_id, account_name)

        if filename:
            utils.log_govcloud_info(f"Results exported with GovCloud compliance markers")
            utils.log_info(f"Total groups processed: {len(groups_data)}")

            # Display some summary statistics
            total_members = sum(group.get('Total Members', 0) for group in groups_data)
            groups_with_members = len([g for g in groups_data if g.get('Total Members', 0) > 0])
            utils.log_info(f"Total members across all groups: {total_members}")
            utils.log_info(f"Groups with members: {groups_with_members}")

            print("\nScript execution completed.")
        else:
            utils.log_error("Export failed. Please check the logs.")

    except KeyboardInterrupt:
        print("\n\nOperation cancelled by user.")
        sys.exit(0)
    except Exception as e:
        utils.log_error("Unexpected error occurred", e)
        sys.exit(1)

if __name__ == "__main__":
    main()