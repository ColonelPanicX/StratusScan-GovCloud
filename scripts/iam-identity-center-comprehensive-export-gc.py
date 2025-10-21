#!/usr/bin/env python3

"""
===========================
= AWS GOVCLOUD RESOURCE SCANNER =
===========================

Title: AWS GovCloud IAM Identity Center Comprehensive Export Script
Version: v1.0.0-GovCloud
Date: SEP-25-2025

Description:
This script performs a comprehensive export of all IAM Identity Center resources from AWS GovCloud
environments including users, groups, and permission sets. All data is consolidated into a single
Excel workbook with separate sheets for each resource type, plus summary sheets for comprehensive
identity governance analysis.

GovCloud Modifications:
- Added GovCloud environment validation
- Updated partition handling for aws-us-gov
- Added GovCloud-specific compliance markers in output filenames
- Enhanced error handling for GovCloud-specific service limitations
- Integration with StratusScan GovCloud utils module

Collected information includes:
- Users with group memberships, account assignments, and application assignments
- Groups with member details and permission assignments
- Permission Sets with policies, assignments, and trust relationships
- Comprehensive summary analytics and compliance metrics
"""

import os
import sys
import boto3
import datetime
import time
import json
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

def convert_datetime_to_string(dt_obj):
    """
    Convert datetime object to timezone-unaware string for Excel compatibility.

    Args:
        dt_obj: datetime object (can be timezone-aware or unaware)

    Returns:
        str: Formatted datetime string or 'N/A' if None/invalid
    """
    if dt_obj is None:
        return 'N/A'

    try:
        if hasattr(dt_obj, 'strftime'):
            # If timezone-aware, convert to UTC and make timezone-naive
            if hasattr(dt_obj, 'tzinfo') and dt_obj.tzinfo is not None:
                # Convert to UTC and remove timezone info
                utc_dt = dt_obj.utctimetuple()
                dt_obj = datetime.datetime(*utc_dt[:6])

            return dt_obj.strftime('%Y-%m-%d %H:%M:%S UTC')
        else:
            return str(dt_obj)
    except Exception:
        return 'N/A'

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
    print("AWS GOVCLOUD IAM IDENTITY CENTER COMPREHENSIVE COLLECTION")
    print("====================================================================")
    print("Version: v1.0.0-GovCloud                       Date: SEP-25-2025")
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

def collect_comprehensive_users(identity_store_id, instance_arn):
    """
    Collect comprehensive IAM Identity Center user information.

    Args:
        identity_store_id: The Identity Store ID
        instance_arn: IAM Identity Center instance ARN

    Returns:
        list: List of comprehensive user information dictionaries
    """
    if not identity_store_id:
        return []

    users_data = []

    try:
        identitystore_client = boto3.client('identitystore', region_name='us-gov-west-1')
        sso_admin_client = boto3.client('sso-admin', region_name='us-gov-west-1')

        # Get all users using pagination
        paginator = identitystore_client.get_paginator('list_users')

        # Count total users first for progress tracking
        total_users = 0
        for page in paginator.paginate(IdentityStoreId=identity_store_id):
            total_users += len(page.get('Users', []))

        if total_users > 0:
            utils.log_info(f"Found {total_users} Identity Center users to process")

        # Reset paginator and process users
        paginator = identitystore_client.get_paginator('list_users')
        processed = 0

        for page in paginator.paginate(IdentityStoreId=identity_store_id):
            users = page.get('Users', [])

            for user in users:
                processed += 1
                progress = (processed / total_users) * 100 if total_users > 0 else 0
                user_name = user.get('UserName', 'Unknown')

                utils.log_info(f"[{progress:.1f}%] Processing user {processed}/{total_users}: {user_name}")

                # Get comprehensive user information
                group_memberships = get_user_group_memberships(identitystore_client, identity_store_id, user['UserId'])
                account_assignments = get_user_account_assignments(sso_admin_client, instance_arn, user['UserId'])
                application_assignments = get_user_application_assignments(sso_admin_client, instance_arn, user['UserId'])

                # Get additional user attributes
                addresses = user.get('Addresses', [])
                phone_numbers = user.get('PhoneNumbers', [])

                primary_address = 'N/A'
                if addresses:
                    primary_addr = next((addr for addr in addresses if addr.get('Primary', False)), addresses[0])
                    if primary_addr:
                        addr_parts = []
                        if primary_addr.get('StreetAddress'):
                            addr_parts.append(primary_addr['StreetAddress'])
                        if primary_addr.get('Locality'):
                            addr_parts.append(primary_addr['Locality'])
                        if primary_addr.get('Region'):
                            addr_parts.append(primary_addr['Region'])
                        if primary_addr.get('PostalCode'):
                            addr_parts.append(primary_addr['PostalCode'])
                        primary_address = ', '.join(addr_parts)

                primary_phone = 'N/A'
                if phone_numbers:
                    primary_ph = next((phone for phone in phone_numbers if phone.get('Primary', False)), phone_numbers[0])
                    if primary_ph:
                        primary_phone = primary_ph.get('Value', 'N/A')

                user_info = {
                    'User ID': user.get('UserId', 'N/A'),
                    'User Name': user.get('UserName', 'N/A'),
                    'Display Name': user.get('DisplayName', 'N/A'),
                    'Nick Name': user.get('NickName', 'N/A'),
                    'Profile URL': user.get('ProfileUrl', 'N/A'),
                    'Given Name': user.get('Name', {}).get('GivenName', 'N/A'),
                    'Middle Name': user.get('Name', {}).get('MiddleName', 'N/A'),
                    'Family Name': user.get('Name', {}).get('FamilyName', 'N/A'),
                    'Formatted Name': user.get('Name', {}).get('Formatted', 'N/A'),
                    'Honorific Prefix': user.get('Name', {}).get('HonorificPrefix', 'N/A'),
                    'Honorific Suffix': user.get('Name', {}).get('HonorificSuffix', 'N/A'),
                    'Email': get_user_email(user),
                    'Email Verified': 'Yes' if get_user_email_verified(user) else 'No',
                    'Primary Phone': primary_phone,
                    'Primary Address': primary_address[:200],  # Limit length
                    'User Type': user.get('UserType', 'N/A'),
                    'Title': user.get('Title', 'N/A'),
                    'Preferred Language': user.get('PreferredLanguage', 'N/A'),
                    'Locale': user.get('Locale', 'N/A'),
                    'Timezone': user.get('Timezone', 'N/A'),
                    'Status': 'Active' if user.get('Active', True) else 'Inactive',
                    'External ID': get_user_external_id(user),
                    'Groups': group_memberships,
                    'AWS Accounts': account_assignments,
                    'Applications': application_assignments,
                    'Group Count': len(group_memberships.split(', ')) if group_memberships != 'None' else 0,
                    'Account Assignment Count': len(account_assignments.split(', ')) if account_assignments not in ['None', 'Unknown'] else 0,
                    'Application Assignment Count': len(application_assignments.split(', ')) if application_assignments not in ['None', 'Unknown', 'Service Not Available'] else 0,
                    'Created Date': convert_datetime_to_string(user.get('Meta', {}).get('Created')),
                    'Last Modified': convert_datetime_to_string(user.get('Meta', {}).get('LastModified')),
                    'Resource Type': user.get('Meta', {}).get('ResourceType', 'N/A')
                }

                users_data.append(user_info)

                # Small delay to avoid API throttling
                time.sleep(0.1)

    except Exception as e:
        utils.log_error("Error collecting Identity Center users", e)

    return users_data

def collect_comprehensive_groups(identity_store_id, instance_arn):
    """
    Collect comprehensive IAM Identity Center group information.

    Args:
        identity_store_id: The Identity Store ID
        instance_arn: IAM Identity Center instance ARN

    Returns:
        list: List of comprehensive group information dictionaries
    """
    if not identity_store_id:
        return []

    groups_data = []

    try:
        identitystore_client = boto3.client('identitystore', region_name='us-gov-west-1')
        sso_admin_client = boto3.client('sso-admin', region_name='us-gov-west-1')

        # Get all groups using pagination
        paginator = identitystore_client.get_paginator('list_groups')

        # Count total groups first for progress tracking
        total_groups = 0
        for page in paginator.paginate(IdentityStoreId=identity_store_id):
            total_groups += len(page.get('Groups', []))

        if total_groups > 0:
            utils.log_info(f"Found {total_groups} Identity Center groups to process")

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

                # Get comprehensive group information
                member_count = get_group_member_count(identitystore_client, identity_store_id, group['GroupId'])
                member_details = get_group_member_details(identitystore_client, identity_store_id, group['GroupId'])
                account_assignments = get_group_account_assignments(sso_admin_client, instance_arn, group['GroupId'])

                group_info = {
                    'Group ID': group.get('GroupId', 'N/A'),
                    'Group Name': group.get('DisplayName', 'N/A'),
                    'Description': group.get('Description', 'N/A'),
                    'External ID': get_group_external_id(group),
                    'Member Count': member_count,
                    'Member Details': member_details[:500],  # Limit length for Excel
                    'Account Assignments': account_assignments,
                    'Assignment Count': len(account_assignments.split(', ')) if account_assignments not in ['None', 'Unknown'] else 0,
                    'Created Date': convert_datetime_to_string(group.get('Meta', {}).get('Created')),
                    'Last Modified': convert_datetime_to_string(group.get('Meta', {}).get('LastModified')),
                    'Resource Type': group.get('Meta', {}).get('ResourceType', 'N/A')
                }

                groups_data.append(group_info)

                # Small delay to avoid API throttling
                time.sleep(0.1)

    except Exception as e:
        utils.log_error("Error collecting Identity Center groups", e)

    return groups_data

def collect_comprehensive_permission_sets(instance_arn):
    """
    Collect comprehensive IAM Identity Center permission set information.

    Args:
        instance_arn: IAM Identity Center instance ARN

    Returns:
        list: List of comprehensive permission set information dictionaries
    """
    if not instance_arn:
        return []

    permission_sets_data = []

    try:
        sso_admin_client = boto3.client('sso-admin', region_name='us-gov-west-1')

        # Get all permission sets using pagination
        paginator = sso_admin_client.get_paginator('list_permission_sets')

        # Count total permission sets first for progress tracking
        total_permission_sets = 0
        for page in paginator.paginate(InstanceArn=instance_arn):
            total_permission_sets += len(page.get('PermissionSets', []))

        if total_permission_sets > 0:
            utils.log_info(f"Found {total_permission_sets} permission sets to process")

        # Reset paginator and process permission sets
        paginator = sso_admin_client.get_paginator('list_permission_sets')
        processed = 0

        for page in paginator.paginate(InstanceArn=instance_arn):
            permission_sets = page.get('PermissionSets', [])

            for permission_set_arn in permission_sets:
                processed += 1
                progress = (processed / total_permission_sets) * 100 if total_permission_sets > 0 else 0

                utils.log_info(f"[{progress:.1f}%] Processing permission set {processed}/{total_permission_sets}")

                # Get comprehensive permission set details
                try:
                    ps_response = sso_admin_client.describe_permission_set(
                        InstanceArn=instance_arn,
                        PermissionSetArn=permission_set_arn
                    )

                    permission_set = ps_response['PermissionSet']

                    # Get detailed policy information
                    managed_policies = get_permission_set_managed_policies_detailed(sso_admin_client, instance_arn, permission_set_arn)
                    inline_policy = get_permission_set_inline_policy_detailed(sso_admin_client, instance_arn, permission_set_arn)
                    permissions_boundary = get_permission_set_permissions_boundary(sso_admin_client, instance_arn, permission_set_arn)

                    # Get assignment details
                    assignments_details = get_permission_set_assignments_detailed(sso_admin_client, instance_arn, permission_set_arn)

                    # Get tags
                    tags = get_permission_set_tags(sso_admin_client, instance_arn, permission_set_arn)

                    # Calculate session duration in hours
                    session_duration = permission_set.get('SessionDuration', 'PT1H')
                    session_hours = parse_duration_to_hours(session_duration)

                    permission_set_info = {
                        'Permission Set ARN': permission_set_arn,
                        'Name': permission_set.get('Name', 'N/A'),
                        'Description': permission_set.get('Description', 'N/A'),
                        'Session Duration': session_duration,
                        'Session Duration (Hours)': session_hours,
                        'Relay State': permission_set.get('RelayState', 'N/A'),
                        'Managed Policies Count': managed_policies['count'],
                        'Managed Policies': managed_policies['names'][:500],  # Limit length
                        'AWS Managed Policies': managed_policies['aws_managed'][:300],
                        'Customer Managed Policies': managed_policies['customer_managed'][:300],
                        'Has Inline Policy': 'Yes' if inline_policy['exists'] else 'No',
                        'Inline Policy Size (Chars)': inline_policy['size'],
                        'Inline Policy Summary': inline_policy['summary'][:200],
                        'Permissions Boundary': permissions_boundary,
                        'Total Account Assignments': assignments_details['total_assignments'],
                        'User Assignments': assignments_details['user_assignments'],
                        'Group Assignments': assignments_details['group_assignments'],
                        'Assignment Details': assignments_details['details'][:500],
                        'Created Date': convert_datetime_to_string(permission_set.get('CreatedDate')),
                        'Tags': tags[:300]
                    }

                    permission_sets_data.append(permission_set_info)

                except Exception as e:
                    utils.log_warning(f"Error processing permission set {permission_set_arn}: {e}")

                # Small delay to avoid API throttling
                time.sleep(0.1)

    except Exception as e:
        utils.log_error("Error collecting permission sets", e)

    return permission_sets_data

# Helper functions for user data collection
def get_user_email(user):
    """Extract email from user object."""
    emails = user.get('Emails', [])
    if emails:
        primary_email = next((email['Value'] for email in emails if email.get('Primary', False)), None)
        return primary_email or emails[0].get('Value', 'N/A')
    return 'N/A'

def get_user_email_verified(user):
    """Check if user email is verified."""
    emails = user.get('Emails', [])
    if emails:
        primary_email = next((email for email in emails if email.get('Primary', False)), emails[0])
        return primary_email.get('Verified', False)
    return False

def get_user_external_id(user):
    """Extract external ID from user object."""
    external_ids = user.get('ExternalIds', [])
    if external_ids:
        return external_ids[0].get('Id', 'N/A')
    return 'N/A'

def get_user_group_memberships(identitystore_client, identity_store_id, user_id):
    """Get group memberships for a user."""
    try:
        paginator = identitystore_client.get_paginator('list_group_memberships_for_member')
        group_names = []

        for page in paginator.paginate(
            IdentityStoreId=identity_store_id,
            MemberId={'UserId': user_id}
        ):
            for membership in page.get('GroupMemberships', []):
                group_id = membership['GroupId']

                # Get group details
                try:
                    group_response = identitystore_client.describe_group(
                        IdentityStoreId=identity_store_id,
                        GroupId=group_id
                    )
                    group_name = group_response.get('DisplayName', group_id)
                    group_names.append(group_name)
                except Exception:
                    group_names.append(group_id)  # Fallback to ID if name unavailable

        return ', '.join(group_names) if group_names else 'None'

    except Exception as e:
        utils.log_warning(f"Could not get group memberships for user {user_id}: {e}")
        return 'Unknown'

def get_user_account_assignments(sso_admin_client, instance_arn, user_id):
    """Get AWS account assignments for a user."""
    try:
        # Get all accounts first to map account IDs to names
        org_client = boto3.client('organizations')
        accounts = {}
        try:
            paginator = org_client.get_paginator('list_accounts')
            for page in paginator.paginate():
                for account in page.get('Accounts', []):
                    accounts[account['Id']] = account.get('Name', account['Id'])
        except Exception:
            # If organizations access fails, we'll use account IDs
            pass

        # Get account assignments for the user
        paginator = sso_admin_client.get_paginator('list_account_assignments')
        assignments = []

        # We need to check across all permission sets and accounts
        # First, get all permission sets
        ps_paginator = sso_admin_client.get_paginator('list_permission_sets')
        permission_sets = []

        for page in ps_paginator.paginate(InstanceArn=instance_arn):
            permission_sets.extend(page.get('PermissionSets', []))

        # For each permission set, check for assignments
        for permission_set_arn in permission_sets:
            try:
                for page in paginator.paginate(
                    InstanceArn=instance_arn,
                    PermissionSetArn=permission_set_arn
                ):
                    for assignment in page.get('AccountAssignments', []):
                        if (assignment.get('PrincipalType') == 'USER' and
                            assignment.get('PrincipalId') == user_id):

                            account_id = assignment.get('TargetId')
                            account_name = accounts.get(account_id, account_id)

                            # Get permission set name
                            try:
                                ps_response = sso_admin_client.describe_permission_set(
                                    InstanceArn=instance_arn,
                                    PermissionSetArn=permission_set_arn
                                )
                                ps_name = ps_response['PermissionSet'].get('Name', 'Unknown')
                            except Exception:
                                ps_name = permission_set_arn.split('/')[-1]  # Use ARN suffix as fallback

                            assignments.append(f"{account_name}:{ps_name}")
            except Exception as e:
                continue  # Skip permission sets that can't be accessed

        return ', '.join(assignments) if assignments else 'None'

    except Exception as e:
        utils.log_warning(f"Could not get account assignments for user {user_id}: {e}")
        return 'Unknown'

def get_user_application_assignments(sso_admin_client, instance_arn, user_id):
    """Get application assignments for a user."""
    try:
        # List all applications first
        try:
            apps_paginator = sso_admin_client.get_paginator('list_applications')
            applications = []

            for page in apps_paginator.paginate(InstanceArn=instance_arn):
                applications.extend(page.get('Applications', []))
        except Exception:
            # list_applications might not be available in all GovCloud regions
            return 'Service Not Available'

        user_applications = []

        # For each application, check if user has assignments
        for app in applications:
            app_arn = app.get('ApplicationArn')
            app_name = app.get('Name', app_arn.split('/')[-1] if app_arn else 'Unknown')

            try:
                # List assignments for this application
                assign_paginator = sso_admin_client.get_paginator('list_application_assignments')

                for page in assign_paginator.paginate(ApplicationArn=app_arn):
                    for assignment in page.get('ApplicationAssignments', []):
                        if (assignment.get('PrincipalType') == 'USER' and
                            assignment.get('PrincipalId') == user_id):
                            user_applications.append(app_name)
                            break  # Found assignment for this app, move to next
            except Exception:
                # Skip applications that can't be accessed or don't support assignments
                continue

        return ', '.join(user_applications) if user_applications else 'None'

    except Exception as e:
        # Application assignments might not be available in all GovCloud regions
        return 'Service Not Available'

# Helper functions for group data collection
def get_group_external_id(group):
    """Extract external ID from group object."""
    external_ids = group.get('ExternalIds', [])
    if external_ids:
        return external_ids[0].get('Id', 'N/A')
    return 'N/A'

def get_group_member_count(identitystore_client, identity_store_id, group_id):
    """Get the number of members in a group."""
    try:
        paginator = identitystore_client.get_paginator('list_group_memberships')
        member_count = 0

        for page in paginator.paginate(
            IdentityStoreId=identity_store_id,
            GroupId=group_id
        ):
            member_count += len(page.get('GroupMemberships', []))

        return member_count

    except Exception as e:
        utils.log_warning(f"Could not get member count for group {group_id}: {e}")
        return 0

def get_group_member_details(identitystore_client, identity_store_id, group_id):
    """Get detailed member information for a group."""
    try:
        paginator = identitystore_client.get_paginator('list_group_memberships')
        member_names = []

        for page in paginator.paginate(
            IdentityStoreId=identity_store_id,
            GroupId=group_id
        ):
            for membership in page.get('GroupMemberships', []):
                member_id = membership['MemberId']
                member_type = member_id.get('UserId') if 'UserId' in member_id else 'Group'

                if 'UserId' in member_id:
                    try:
                        user_response = identitystore_client.describe_user(
                            IdentityStoreId=identity_store_id,
                            UserId=member_id['UserId']
                        )
                        user_name = user_response.get('UserName', member_id['UserId'])
                        member_names.append(f"User: {user_name}")
                    except Exception:
                        member_names.append(f"User: {member_id['UserId']}")

        return ', '.join(member_names) if member_names else 'No Members'

    except Exception as e:
        utils.log_warning(f"Could not get member details for group {group_id}: {e}")
        return 'Unknown'

def get_group_account_assignments(sso_admin_client, instance_arn, group_id):
    """Get AWS account assignments for a group."""
    try:
        # Get all accounts first to map account IDs to names
        org_client = boto3.client('organizations')
        accounts = {}
        try:
            paginator = org_client.get_paginator('list_accounts')
            for page in paginator.paginate():
                for account in page.get('Accounts', []):
                    accounts[account['Id']] = account.get('Name', account['Id'])
        except Exception:
            pass

        # Get account assignments for the group
        paginator = sso_admin_client.get_paginator('list_account_assignments')
        assignments = []

        # Get all permission sets first
        ps_paginator = sso_admin_client.get_paginator('list_permission_sets')
        permission_sets = []

        for page in ps_paginator.paginate(InstanceArn=instance_arn):
            permission_sets.extend(page.get('PermissionSets', []))

        # For each permission set, check for group assignments
        for permission_set_arn in permission_sets:
            try:
                for page in paginator.paginate(
                    InstanceArn=instance_arn,
                    PermissionSetArn=permission_set_arn
                ):
                    for assignment in page.get('AccountAssignments', []):
                        if (assignment.get('PrincipalType') == 'GROUP' and
                            assignment.get('PrincipalId') == group_id):

                            account_id = assignment.get('TargetId')
                            account_name = accounts.get(account_id, account_id)

                            # Get permission set name
                            try:
                                ps_response = sso_admin_client.describe_permission_set(
                                    InstanceArn=instance_arn,
                                    PermissionSetArn=permission_set_arn
                                )
                                ps_name = ps_response['PermissionSet'].get('Name', 'Unknown')
                            except Exception:
                                ps_name = permission_set_arn.split('/')[-1]

                            assignments.append(f"{account_name}:{ps_name}")
            except Exception:
                continue

        return ', '.join(assignments) if assignments else 'None'

    except Exception as e:
        utils.log_warning(f"Could not get account assignments for group {group_id}: {e}")
        return 'Unknown'

# Helper functions for permission set data collection
def get_permission_set_managed_policies_detailed(sso_admin_client, instance_arn, permission_set_arn):
    """Get detailed managed policies information for a permission set."""
    try:
        paginator = sso_admin_client.get_paginator('list_managed_policies_in_permission_set')
        policies = []
        aws_managed = []
        customer_managed = []

        for page in paginator.paginate(
            InstanceArn=instance_arn,
            PermissionSetArn=permission_set_arn
        ):
            for policy in page.get('AttachedManagedPolicies', []):
                policy_name = policy.get('Name', policy.get('Arn', 'Unknown'))
                policy_arn = policy.get('Arn', '')

                policies.append(policy_name)

                if 'aws:policy/' in policy_arn:
                    aws_managed.append(policy_name)
                else:
                    customer_managed.append(policy_name)

        return {
            'count': len(policies),
            'names': ', '.join(policies),
            'aws_managed': ', '.join(aws_managed),
            'customer_managed': ', '.join(customer_managed)
        }

    except Exception as e:
        return {
            'count': 0,
            'names': 'Unknown',
            'aws_managed': 'Unknown',
            'customer_managed': 'Unknown'
        }

def get_permission_set_inline_policy_detailed(sso_admin_client, instance_arn, permission_set_arn):
    """Get detailed inline policy information for a permission set."""
    try:
        response = sso_admin_client.get_inline_policy_for_permission_set(
            InstanceArn=instance_arn,
            PermissionSetArn=permission_set_arn
        )
        inline_policy = response.get('InlinePolicy', '')

        if inline_policy:
            try:
                policy_doc = json.loads(inline_policy)
                statements = policy_doc.get('Statement', [])
                if not isinstance(statements, list):
                    statements = [statements]

                statement_count = len(statements)
                actions = []
                resources = []

                for stmt in statements:
                    # Extract actions
                    stmt_actions = stmt.get('Action', [])
                    if isinstance(stmt_actions, str):
                        stmt_actions = [stmt_actions]
                    actions.extend(stmt_actions)

                    # Extract resources
                    stmt_resources = stmt.get('Resource', [])
                    if isinstance(stmt_resources, str):
                        stmt_resources = [stmt_resources]
                    resources.extend(stmt_resources)

                # Create summary
                summary = f"Statements: {statement_count}, Actions: {len(set(actions))}, Resources: {len(set(resources))}"

                return {
                    'exists': True,
                    'size': len(inline_policy),
                    'summary': summary
                }
            except json.JSONDecodeError:
                return {
                    'exists': True,
                    'size': len(inline_policy),
                    'summary': f"Policy size: {len(inline_policy)} characters"
                }
        else:
            return {
                'exists': False,
                'size': 0,
                'summary': 'No inline policy'
            }

    except ClientError as e:
        if e.response['Error']['Code'] == 'ResourceNotFoundException':
            return {
                'exists': False,
                'size': 0,
                'summary': 'No inline policy'
            }
        return {
            'exists': False,
            'size': 0,
            'summary': 'Unknown'
        }
    except Exception:
        return {
            'exists': False,
            'size': 0,
            'summary': 'Unknown'
        }

def get_permission_set_permissions_boundary(sso_admin_client, instance_arn, permission_set_arn):
    """Get permissions boundary for a permission set."""
    try:
        response = sso_admin_client.get_permissions_boundary_for_permission_set(
            InstanceArn=instance_arn,
            PermissionSetArn=permission_set_arn
        )

        boundary = response.get('PermissionsBoundary', {})
        if boundary:
            boundary_type = boundary.get('ManagedPolicyArn')
            if boundary_type:
                return f"Managed Policy: {boundary_type}"
            else:
                return 'Configured (Unknown Type)'
        else:
            return 'Not Set'

    except ClientError as e:
        if e.response['Error']['Code'] == 'ResourceNotFoundException':
            return 'Not Set'
        return 'Unknown'
    except Exception:
        return 'Unknown'

def get_permission_set_assignments_detailed(sso_admin_client, instance_arn, permission_set_arn):
    """Get detailed assignment information for a permission set."""
    try:
        paginator = sso_admin_client.get_paginator('list_account_assignments')
        assignments = []
        user_count = 0
        group_count = 0

        for page in paginator.paginate(
            InstanceArn=instance_arn,
            PermissionSetArn=permission_set_arn
        ):
            for assignment in page.get('AccountAssignments', []):
                principal_type = assignment.get('PrincipalType')
                principal_id = assignment.get('PrincipalId')
                account_id = assignment.get('TargetId')

                if principal_type == 'USER':
                    user_count += 1
                elif principal_type == 'GROUP':
                    group_count += 1

                assignments.append(f"{principal_type}: {principal_id} -> Account: {account_id}")

        assignment_details = '; '.join(assignments[:10])  # Limit to first 10
        if len(assignments) > 10:
            assignment_details += f" (and {len(assignments) - 10} more)"

        return {
            'total_assignments': len(assignments),
            'user_assignments': user_count,
            'group_assignments': group_count,
            'details': assignment_details
        }

    except Exception as e:
        return {
            'total_assignments': 0,
            'user_assignments': 0,
            'group_assignments': 0,
            'details': 'Unknown'
        }

def get_permission_set_tags(sso_admin_client, instance_arn, permission_set_arn):
    """Get tags for a permission set."""
    try:
        response = sso_admin_client.list_tags_for_resource(
            InstanceArn=instance_arn,
            ResourceArn=permission_set_arn
        )
        tags = response.get('Tags', [])
        tag_strings = [f"{tag['Key']}={tag['Value']}" for tag in tags]
        return ', '.join(tag_strings) if tag_strings else 'No Tags'

    except Exception as e:
        return 'Unknown'

def parse_duration_to_hours(duration):
    """Parse ISO 8601 duration to hours."""
    try:
        # Simple parser for PT[n]H format
        if duration.startswith('PT') and duration.endswith('H'):
            hours_str = duration[2:-1]
            return float(hours_str)
        elif duration.startswith('PT') and 'M' in duration:
            # Handle minutes - PT30M = 0.5 hours
            minutes_str = duration[2:duration.find('M')]
            return float(minutes_str) / 60
        else:
            return 'N/A'
    except Exception:
        return 'N/A'

def clean_dataframe_datetimes(df):
    """
    Clean timezone-aware datetimes in a pandas DataFrame for Excel compatibility.

    Args:
        df: pandas DataFrame

    Returns:
        pandas DataFrame: DataFrame with timezone-unaware datetime strings
    """
    try:
        import pandas as pd

        # Convert any datetime columns to strings
        for col in df.columns:
            if df[col].dtype == 'datetime64[ns, UTC]' or any(isinstance(val, datetime.datetime) for val in df[col].dropna()):
                # Convert datetime objects to strings
                df[col] = df[col].apply(lambda x: convert_datetime_to_string(x) if pd.notna(x) else 'N/A')

        return df
    except Exception as e:
        utils.log_warning(f"Error cleaning datetime objects in dataframe: {e}")
        return df

def export_to_excel(users_data, groups_data, permission_sets_data, account_id, account_name):
    """
    Export comprehensive IAM Identity Center data to Excel file with GovCloud naming convention.
    """
    if not users_data and not groups_data and not permission_sets_data:
        utils.log_warning("No IAM Identity Center data to export.")
        return None

    try:
        # Import pandas after dependency check
        import pandas as pd

        # Generate filename with GovCloud identifier
        current_date = datetime.datetime.now().strftime("%m.%d.%Y")

        # Use utils module to generate filename and save data with GovCloud identifier
        filename = utils.create_export_filename(
            account_name,
            "iam-identity-center-comprehensive",
            "",
            current_date
        )

        # Create data frames for multi-sheet export
        data_frames = {}

        if users_data:
            users_df = pd.DataFrame(users_data)
            users_df = clean_dataframe_datetimes(users_df)
            data_frames['Users'] = users_df

        if groups_data:
            groups_df = pd.DataFrame(groups_data)
            groups_df = clean_dataframe_datetimes(groups_df)
            data_frames['Groups'] = groups_df

        if permission_sets_data:
            permission_sets_df = pd.DataFrame(permission_sets_data)
            permission_sets_df = clean_dataframe_datetimes(permission_sets_df)
            data_frames['Permission Sets'] = permission_sets_df

        # Create comprehensive summary data
        summary_data = {
            'Category': [
                'Total Users',
                'Active Users',
                'Inactive Users',
                'Users with Groups',
                'Users with Account Access',
                'Users with Application Access',
                'Total Groups',
                'Groups with Members',
                'Groups with Account Assignments',
                'Total Permission Sets',
                'Permission Sets with Managed Policies',
                'Permission Sets with Inline Policies',
                'Permission Sets with Permissions Boundaries',
                'Average Session Duration (Hours)',
                'Total Account Assignments',
                'User-Based Assignments',
                'Group-Based Assignments'
            ],
            'Count': [
                len(users_data),
                len([u for u in users_data if u.get('Status') == 'Active']),
                len([u for u in users_data if u.get('Status') == 'Inactive']),
                len([u for u in users_data if u.get('Group Count', 0) > 0]),
                len([u for u in users_data if u.get('Account Assignment Count', 0) > 0]),
                len([u for u in users_data if u.get('Application Assignment Count', 0) > 0]),
                len(groups_data),
                len([g for g in groups_data if g.get('Member Count', 0) > 0]),
                len([g for g in groups_data if g.get('Assignment Count', 0) > 0]),
                len(permission_sets_data),
                len([p for p in permission_sets_data if p.get('Managed Policies Count', 0) > 0]),
                len([p for p in permission_sets_data if p.get('Has Inline Policy') == 'Yes']),
                len([p for p in permission_sets_data if p.get('Permissions Boundary', 'Not Set') != 'Not Set']),
                get_average_session_duration(permission_sets_data),
                sum([p.get('Total Account Assignments', 0) for p in permission_sets_data]),
                sum([p.get('User Assignments', 0) for p in permission_sets_data]),
                sum([p.get('Group Assignments', 0) for p in permission_sets_data])
            ]
        }

        summary_df = pd.DataFrame(summary_data)
        summary_df = clean_dataframe_datetimes(summary_df)
        data_frames['Summary'] = summary_df

        # Save using utils function for multi-sheet Excel
        output_path = utils.save_multiple_dataframes_to_excel(data_frames, filename)

        if output_path:
            utils.log_success("GovCloud IAM Identity Center comprehensive data exported successfully!")
            utils.log_info(f"File location: {output_path}")
            utils.log_govcloud_info(f"Export contains {len(users_data)} users, {len(groups_data)} groups, and {len(permission_sets_data)} permission sets")
            return str(output_path)
        else:
            utils.log_error("Error exporting to Excel. Please check the logs.")
            return None

    except Exception as e:
        utils.log_error("Error exporting to Excel", e)
        return None

def get_average_session_duration(permission_sets_data):
    """Calculate average session duration across permission sets."""
    try:
        durations = []
        for ps in permission_sets_data:
            duration = ps.get('Session Duration (Hours)')
            if isinstance(duration, (int, float)) and duration > 0:
                durations.append(duration)

        if durations:
            return round(sum(durations) / len(durations), 2)
        else:
            return 'N/A'
    except Exception:
        return 'N/A'

def main():
    """
    Main function to orchestrate the comprehensive IAM Identity Center information collection.
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

        utils.log_info("Starting comprehensive IAM Identity Center information collection from GovCloud...")
        print("====================================================================")

        # Get Identity Center instance
        instance_arn, identity_store_id = get_identity_center_instance()

        if not instance_arn:
            utils.log_error("Could not find IAM Identity Center instance. Exiting.")
            return

        # Collect comprehensive Identity Center data
        utils.log_info("Collecting comprehensive Identity Center users...")
        users_data = collect_comprehensive_users(identity_store_id, instance_arn)

        utils.log_info("Collecting comprehensive Identity Center groups...")
        groups_data = collect_comprehensive_groups(identity_store_id, instance_arn)

        utils.log_info("Collecting comprehensive permission sets...")
        permission_sets_data = collect_comprehensive_permission_sets(instance_arn)

        if not users_data and not groups_data and not permission_sets_data:
            utils.log_warning("No Identity Center data collected. Exiting.")
            return

        print("\n====================================================================")
        print("COLLECTION COMPLETE")
        print("====================================================================")

        # Export to Excel
        filename = export_to_excel(users_data, groups_data, permission_sets_data, account_id, account_name)

        if filename:
            utils.log_govcloud_info(f"Results exported with GovCloud compliance markers")
            utils.log_info(f"Total users processed: {len(users_data)}")
            utils.log_info(f"Total groups processed: {len(groups_data)}")
            utils.log_info(f"Total permission sets processed: {len(permission_sets_data)}")

            # Display comprehensive statistics
            if users_data:
                active_users = len([u for u in users_data if u.get('Status') == 'Active'])
                users_with_access = len([u for u in users_data if u.get('Account Assignment Count', 0) > 0])
                utils.log_info(f"Active users: {active_users}")
                utils.log_info(f"Users with account access: {users_with_access}")

            if groups_data:
                groups_with_members = len([g for g in groups_data if g.get('Member Count', 0) > 0])
                utils.log_info(f"Groups with members: {groups_with_members}")

            if permission_sets_data:
                ps_with_policies = len([p for p in permission_sets_data if p.get('Managed Policies Count', 0) > 0 or p.get('Has Inline Policy') == 'Yes'])
                utils.log_info(f"Permission sets with policies: {ps_with_policies}")

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