#!/usr/bin/env python3

"""
===========================
= AWS GOVCLOUD RESOURCE SCANNER =
===========================

Title: AWS GovCloud IAM Comprehensive Export Script
Version: v1.0.0-GovCloud
Date: SEP-23-2025

Description:
This script performs a comprehensive export of all IAM resources from AWS GovCloud environments
including users, roles, and policies. All data is consolidated into a single Excel workbook with
separate sheets for each resource type, plus summary sheets for comprehensive analysis.

GovCloud Modifications:
- Added GovCloud environment validation
- Updated partition handling for aws-us-gov
- Added GovCloud-specific compliance markers in output filenames
- Enhanced error handling for GovCloud-specific service limitations
- Integration with StratusScan GovCloud utils module

Collected information includes: IAM Users (with authentication details), IAM Roles (with trust
relationships), IAM Policies (with risk assessment), and comprehensive summary analytics.
"""

import os
import sys
import boto3
import datetime
import time
import json
import re
import urllib.parse
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

        # Try to get account alias first, then fall back to utils mapping
        try:
            iam_client = boto3.client('iam')
            aliases = iam_client.list_account_aliases()['AccountAliases']
            if aliases:
                account_name = aliases[0]
            else:
                # Use utils module for account name mapping
                account_name = utils.get_account_name(account_id, default=f"GOVCLOUD-{account_id}")
        except Exception:
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
    print("AWS GOVCLOUD IAM COMPREHENSIVE EXPORT")
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

# Import functions from existing IAM scripts by copying their core logic

def calculate_age_in_days(date_obj):
    """Calculate the age of a date object in days."""
    if date_obj is None:
        return "Never"

    if isinstance(date_obj, str):
        return date_obj

    try:
        # Remove timezone info if present for calculation
        if date_obj.tzinfo is not None:
            date_obj = date_obj.replace(tzinfo=None)

        age = datetime.datetime.now() - date_obj
        return age.days
    except Exception:
        return "Unknown"

def get_user_mfa_devices(iam_client, username):
    """Get MFA devices for a user."""
    try:
        virtual_mfa = iam_client.list_mfa_devices(UserName=username)
        mfa_devices = virtual_mfa.get('MFADevices', [])
        return "Enabled" if mfa_devices else "Disabled"
    except Exception as e:
        utils.log_warning(f"Could not check MFA for user {username}: {e}")
        return "Unknown"

def get_user_groups(iam_client, username):
    """Get groups that a user belongs to."""
    try:
        response = iam_client.get_groups_for_user(UserName=username)
        groups = [group['GroupName'] for group in response['Groups']]
        return ", ".join(groups) if groups else "None"
    except Exception as e:
        utils.log_warning(f"Could not get groups for user {username}: {e}")
        return "Unknown"

def get_user_policies(iam_client, username):
    """Get all policies attached to a user (both attached and inline)."""
    policies = []

    try:
        # Get attached managed policies
        attached_policies = iam_client.list_attached_user_policies(UserName=username)
        for policy in attached_policies['AttachedPolicies']:
            policies.append(policy['PolicyName'])

        # Get inline policies
        inline_policies = iam_client.list_user_policies(UserName=username)
        for policy_name in inline_policies['PolicyNames']:
            policies.append(f"{policy_name} (Inline)")

        return ", ".join(policies) if policies else "None"
    except Exception as e:
        utils.log_warning(f"Could not get policies for user {username}: {e}")
        return "Unknown"

def get_password_info(iam_client, username):
    """Get password-related information for a user."""
    try:
        login_profile = iam_client.get_login_profile(UserName=username)
        password_creation = login_profile['LoginProfile']['CreateDate']
        password_age = calculate_age_in_days(password_creation)
        console_access = "Enabled"
        return password_age, console_access
    except ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchEntity':
            return "No Password", "Disabled"
        else:
            return "Unknown", "Unknown"
    except Exception as e:
        utils.log_warning(f"Could not get password info for user {username}: {e}")
        return "Unknown", "Unknown"

def get_access_key_info(iam_client, username):
    """Get access key information for a user."""
    try:
        response = iam_client.list_access_keys(UserName=username)
        access_keys = response['AccessKeyMetadata']

        if not access_keys:
            return "None", "No Keys", "Never"

        # Process all access keys
        key_info = []
        active_ages = []
        last_used_dates = []

        for key in access_keys:
            key_id = key['AccessKeyId']
            status = key['Status']
            created_date = key['CreateDate']

            key_info.append(f"{key_id} ({status})")

            if status == 'Active':
                key_age = calculate_age_in_days(created_date)
                active_ages.append(str(key_age))

                # Get last used information
                try:
                    last_used_response = iam_client.get_access_key_last_used(AccessKeyId=key_id)
                    last_used_date = last_used_response.get('AccessKeyLastUsed', {}).get('LastUsedDate')
                    if last_used_date:
                        days_since_used = calculate_age_in_days(last_used_date)
                        last_used_dates.append(f"{days_since_used} days ago")
                    else:
                        last_used_dates.append("Never")
                except Exception:
                    last_used_dates.append("Unknown")

        # Format return values
        access_key_ids = ", ".join(key_info)
        active_key_age = ", ".join(active_ages) if active_ages else "No Active Keys"
        access_key_last_used = ", ".join(last_used_dates) if last_used_dates else "Never"

        return access_key_ids, active_key_age, access_key_last_used

    except Exception as e:
        utils.log_warning(f"Could not get access key info for user {username}: {e}")
        return "Unknown", "Unknown", "Unknown"

def collect_iam_users():
    """Collect IAM user information from AWS GovCloud."""
    utils.log_info("Collecting IAM users from GovCloud environment...")

    try:
        iam_client = boto3.client('iam', region_name='us-gov-west-1')
    except Exception as e:
        utils.log_error("Error creating IAM client", e)
        return []

    user_data = []

    try:
        # Get all IAM users
        paginator = iam_client.get_paginator('list_users')

        total_users = 0
        for page in paginator.paginate():
            users = page['Users']
            total_users += len(users)

        utils.log_info(f"Found {total_users} IAM users to process")

        # Reset paginator and process users
        paginator = iam_client.get_paginator('list_users')
        processed = 0

        for page in paginator.paginate():
            users = page['Users']

            for user in users:
                username = user['UserName']
                processed += 1
                progress = (processed / total_users) * 100

                utils.log_info(f"[{progress:.1f}%] Processing user {processed}/{total_users}: {username}")

                # Basic user information
                creation_date = user['CreateDate'].strftime('%Y-%m-%d %H:%M:%S UTC') if user['CreateDate'] else "Unknown"
                password_last_used = user.get('PasswordLastUsed')

                # Format console last sign-in
                if password_last_used:
                    console_last_signin = password_last_used.strftime('%Y-%m-%d %H:%M:%S UTC')
                else:
                    console_last_signin = "Never"

                # Get additional user information
                groups = get_user_groups(iam_client, username)
                mfa_status = get_user_mfa_devices(iam_client, username)
                password_age, console_access = get_password_info(iam_client, username)
                access_key_id, active_key_age, access_key_last_used = get_access_key_info(iam_client, username)
                permission_policies = get_user_policies(iam_client, username)

                # Compile user data
                user_info = {
                    'User Name': username,
                    'Groups': groups,
                    'MFA': mfa_status,
                    'Password Age': f"{password_age} days" if isinstance(password_age, int) else password_age,
                    'Console Last Sign-in': console_last_signin,
                    'Access Key ID': access_key_id,
                    'Active Key Age': f"{active_key_age} days" if isinstance(active_key_age, int) else active_key_age,
                    'Access Key Last Used': access_key_last_used,
                    'Creation Date': creation_date,
                    'Console Access': console_access,
                    'Permission Policies': permission_policies
                }

                user_data.append(user_info)

                # Small delay to avoid API throttling
                time.sleep(0.1)

    except Exception as e:
        utils.log_error("Error collecting IAM user information", e)
        return []

    utils.log_success(f"Successfully collected information for {len(user_data)} users")
    return user_data

def calculate_days_since_last_used(last_used_date):
    """Calculate days since role was last used."""
    if last_used_date is None:
        return "Never"

    try:
        # Remove timezone info if present for calculation
        if last_used_date.tzinfo is not None:
            last_used_date = last_used_date.replace(tzinfo=None)

        days_since = (datetime.datetime.now() - last_used_date).days
        return str(days_since)
    except Exception:
        return "Unknown"

def analyze_trust_policy(trust_policy_doc):
    """Analyze the trust policy to extract key information."""
    trusted_entities = []
    cross_account_accounts = []
    services = []

    try:
        statements = trust_policy_doc.get('Statement', [])
        if not isinstance(statements, list):
            statements = [statements]

        for statement in statements:
            if statement.get('Effect') == 'Allow':
                principals = statement.get('Principal', {})

                if isinstance(principals, str):
                    if principals == '*':
                        trusted_entities.append("Anyone (*)")
                    else:
                        trusted_entities.append(principals)
                elif isinstance(principals, dict):
                    # AWS accounts
                    if 'AWS' in principals:
                        aws_principals = principals['AWS']
                        if not isinstance(aws_principals, list):
                            aws_principals = [aws_principals]

                        for principal in aws_principals:
                            if isinstance(principal, str):
                                if principal == '*':
                                    trusted_entities.append("Any AWS Account (*)")
                                elif 'arn:aws' in principal or 'arn:aws-us-gov' in principal:
                                    # Extract account ID from ARN
                                    match = re.search(r':(\d{12}):', principal)
                                    if match:
                                        account_id = match.group(1)
                                        cross_account_accounts.append(account_id)
                                        trusted_entities.append(f"AWS Account: {account_id}")
                                    else:
                                        trusted_entities.append(f"AWS: {principal}")
                                else:
                                    trusted_entities.append(f"AWS: {principal}")

                    # AWS Services
                    if 'Service' in principals:
                        service_principals = principals['Service']
                        if not isinstance(service_principals, list):
                            service_principals = [service_principals]

                        for service in service_principals:
                            services.append(service)
                            trusted_entities.append(f"Service: {service}")

                    # Federated (SAML, OIDC)
                    if 'Federated' in principals:
                        federated_principals = principals['Federated']
                        if not isinstance(federated_principals, list):
                            federated_principals = [federated_principals]

                        for fed in federated_principals:
                            trusted_entities.append(f"Federated: {fed}")

        # Create summary
        trust_summary_parts = []
        if services:
            trust_summary_parts.append(f"Services: {len(services)}")
        if cross_account_accounts:
            trust_summary_parts.append(f"Cross-Account: {len(cross_account_accounts)}")
        if not services and not cross_account_accounts and trusted_entities:
            trust_summary_parts.append("Other principals")

        trust_summary = ", ".join(trust_summary_parts) if trust_summary_parts else "None"

        # Cross-account info
        cross_account_access = "Yes" if cross_account_accounts else "No"
        cross_account_details = ", ".join(cross_account_accounts) if cross_account_accounts else "None"

        return (
            ", ".join(trusted_entities[:5]) + ("..." if len(trusted_entities) > 5 else ""),
            trust_summary,
            f"{cross_account_access} ({cross_account_details})" if cross_account_accounts else "No",
            ", ".join(services) if services else "None"
        )

    except Exception as e:
        utils.log_warning(f"Error analyzing trust policy: {e}")
        return "Unknown", "Unknown", "Unknown", "Unknown"

def determine_role_type(role_name, role_path, trust_policy_doc):
    """Determine the type of IAM role."""
    # Check for service-linked roles
    if role_path.startswith('/aws-service-role/') or 'ServiceLinkedRole' in role_name:
        return "Service-linked"

    # Check for cross-account roles by analyzing trust policy
    try:
        statements = trust_policy_doc.get('Statement', [])
        if not isinstance(statements, list):
            statements = [statements]

        for statement in statements:
            if statement.get('Effect') == 'Allow':
                principals = statement.get('Principal', {})
                if isinstance(principals, dict) and 'AWS' in principals:
                    aws_principals = principals['AWS']
                    if not isinstance(aws_principals, list):
                        aws_principals = [aws_principals]

                    for principal in aws_principals:
                        if isinstance(principal, str) and ('arn:aws' in principal or 'arn:aws-us-gov' in principal):
                            # Check if it's a different account
                            match = re.search(r':(\d{12}):', principal)
                            if match:
                                return "Cross-account"
    except Exception:
        pass

    return "Standard"

def get_role_policies(iam_client, role_name):
    """Get all policies attached to a role (both managed and inline)."""
    policies = []

    try:
        # Get attached managed policies
        attached_policies = iam_client.list_attached_role_policies(RoleName=role_name)
        for policy in attached_policies['AttachedPolicies']:
            policies.append(policy['PolicyName'])

        # Get inline policies
        inline_policies = iam_client.list_role_policies(RoleName=role_name)
        for policy_name in inline_policies['PolicyNames']:
            policies.append(f"{policy_name} (Inline)")

        return ", ".join(policies) if policies else "None"
    except Exception as e:
        utils.log_warning(f"Could not get policies for role {role_name}: {e}")
        return "Unknown"

def get_role_tags(iam_client, role_name):
    """Get tags for a role."""
    try:
        response = iam_client.list_role_tags(RoleName=role_name)
        tags = response.get('Tags', [])
        tag_strings = [f"{tag['Key']}={tag['Value']}" for tag in tags]
        return ", ".join(tag_strings) if tag_strings else "None"
    except Exception as e:
        utils.log_warning(f"Could not get tags for role {role_name}: {e}")
        return "Unknown"

def collect_iam_roles():
    """Collect IAM role information from AWS GovCloud."""
    utils.log_info("Collecting IAM roles from GovCloud environment...")

    try:
        iam_client = boto3.client('iam', region_name='us-gov-west-1')
    except Exception as e:
        utils.log_error("Error creating IAM client", e)
        return []

    role_data = []

    try:
        # Get all IAM roles
        paginator = iam_client.get_paginator('list_roles')

        total_roles = 0
        for page in paginator.paginate():
            roles = page['Roles']
            total_roles += len(roles)

        utils.log_info(f"Found {total_roles} IAM roles to process")

        # Reset paginator and process roles
        paginator = iam_client.get_paginator('list_roles')
        processed = 0

        for page in paginator.paginate():
            roles = page['Roles']

            for role in roles:
                role_name = role['RoleName']
                processed += 1
                progress = (processed / total_roles) * 100

                utils.log_info(f"[{progress:.1f}%] Processing role {processed}/{total_roles}: {role_name}")

                # Basic role information
                creation_date = role['CreateDate'].strftime('%Y-%m-%d %H:%M:%S UTC') if role['CreateDate'] else "Unknown"
                role_path = role.get('Path', '/')
                description = role.get('Description', 'None')
                max_session_duration = role.get('MaxSessionDuration', 3600) // 3600  # Convert to hours

                # Parse trust policy
                trust_policy_doc = role.get('AssumeRolePolicyDocument', {})
                trusted_entities, trust_summary, cross_account_info, service_usage = analyze_trust_policy(trust_policy_doc)

                # Determine role type
                role_type = determine_role_type(role_name, role_path, trust_policy_doc)

                # Get role usage information
                try:
                    role_usage = iam_client.get_role(RoleName=role_name)
                    role_last_used = role_usage['Role'].get('RoleLastUsed', {})
                    last_used_date = role_last_used.get('LastUsedDate')
                    last_used_region = role_last_used.get('Region', 'Unknown')

                    if last_used_date:
                        last_used_str = last_used_date.strftime('%Y-%m-%d %H:%M:%S UTC')
                        days_since_used = calculate_days_since_last_used(last_used_date)
                    else:
                        last_used_str = "Never"
                        days_since_used = "Never"

                except Exception as e:
                    utils.log_warning(f"Could not get usage info for role {role_name}: {e}")
                    last_used_str = "Unknown"
                    days_since_used = "Unknown"

                # Get additional role information
                permission_policies = get_role_policies(iam_client, role_name)
                tags = get_role_tags(iam_client, role_name)

                # Compile role data
                role_info = {
                    'Role Name': role_name,
                    'Role Type': role_type,
                    'Trusted Entities': trusted_entities,
                    'Trust Policy Summary': trust_summary,
                    'Permission Policies': permission_policies,
                    'Last Used': last_used_str,
                    'Days Since Last Used': days_since_used,
                    'Max Session Duration (Hours)': max_session_duration,
                    'Cross-Account Access': cross_account_info,
                    'Service Usage': service_usage,
                    'Creation Date': creation_date,
                    'Path': role_path,
                    'Description': description,
                    'Tags': tags
                }

                role_data.append(role_info)

                # Small delay to avoid API throttling
                time.sleep(0.1)

    except Exception as e:
        utils.log_error("Error collecting IAM role information", e)
        return []

    utils.log_success(f"Successfully collected information for {len(role_data)} roles")
    return role_data

def analyze_policy_document(policy_doc):
    """Analyze a policy document to extract key information."""
    analysis = {
        'permission_summary': 'Unknown',
        'resource_scope': 'Unknown',
        'has_wildcard_actions': 'No',
        'has_wildcard_resources': 'No',
        'statement_count': 0,
        'condition_usage': 'No',
        'risk_level': 'Low'
    }

    try:
        if not policy_doc or 'Statement' not in policy_doc:
            return analysis

        statements = policy_doc['Statement']
        if not isinstance(statements, list):
            statements = [statements]

        analysis['statement_count'] = len(statements)

        actions = set()
        resources = set()
        has_conditions = False
        has_wildcard_actions = False
        has_wildcard_resources = False

        for statement in statements:
            # Skip Deny statements for permission summary
            if statement.get('Effect') != 'Allow':
                continue

            # Analyze actions
            stmt_actions = statement.get('Action', [])
            if isinstance(stmt_actions, str):
                stmt_actions = [stmt_actions]
            elif not isinstance(stmt_actions, list):
                stmt_actions = []

            for action in stmt_actions:
                actions.add(action)
                if '*' in action:
                    has_wildcard_actions = True

            # Analyze resources
            stmt_resources = statement.get('Resource', [])
            if isinstance(stmt_resources, str):
                stmt_resources = [stmt_resources]
            elif not isinstance(stmt_resources, list):
                stmt_resources = []

            for resource in stmt_resources:
                resources.add(resource)
                if resource == '*':
                    has_wildcard_resources = True

            # Check for conditions
            if 'Condition' in statement:
                has_conditions = True

        # Create permission summary (top actions)
        action_list = list(actions)[:10]  # Limit to top 10 actions
        if len(action_list) > 5:
            analysis['permission_summary'] = ', '.join(action_list[:5]) + f' (+{len(action_list)-5} more)'
        else:
            analysis['permission_summary'] = ', '.join(action_list) if action_list else 'None'

        # Create resource scope summary
        resource_list = list(resources)
        if '*' in resource_list:
            analysis['resource_scope'] = 'All resources (*)'
        elif len(resource_list) > 3:
            analysis['resource_scope'] = f'{len(resource_list)} specific resources'
        else:
            analysis['resource_scope'] = ', '.join(resource_list[:3]) if resource_list else 'None'

        # Set flags
        analysis['has_wildcard_actions'] = 'Yes' if has_wildcard_actions else 'No'
        analysis['has_wildcard_resources'] = 'Yes' if has_wildcard_resources else 'No'
        analysis['condition_usage'] = 'Yes' if has_conditions else 'No'

        # Calculate risk level
        risk_factors = 0
        if has_wildcard_actions:
            risk_factors += 2
        if has_wildcard_resources:
            risk_factors += 2
        if not has_conditions and (has_wildcard_actions or has_wildcard_resources):
            risk_factors += 1

        if risk_factors >= 4:
            analysis['risk_level'] = 'High'
        elif risk_factors >= 2:
            analysis['risk_level'] = 'Medium'
        else:
            analysis['risk_level'] = 'Low'

    except Exception as e:
        utils.log_warning(f"Error analyzing policy document: {e}")

    return analysis

def get_policy_entities(iam_client, policy_arn):
    """Get entities (users, groups, roles) attached to a policy."""
    users = []
    groups = []
    roles = []

    try:
        # Get policy entities
        paginator = iam_client.get_paginator('list_entities_for_policy')
        for page in paginator.paginate(PolicyArn=policy_arn):
            # Users
            for user in page.get('PolicyUsers', []):
                users.append(user['UserName'])

            # Groups
            for group in page.get('PolicyGroups', []):
                groups.append(group['GroupName'])

            # Roles
            for role in page.get('PolicyRoles', []):
                roles.append(role['RoleName'])

        total_count = len(users) + len(groups) + len(roles)

        return (
            ', '.join(users) if users else 'None',
            ', '.join(groups) if groups else 'None',
            ', '.join(roles) if roles else 'None',
            total_count
        )

    except Exception as e:
        utils.log_warning(f"Could not get entities for policy {policy_arn}: {e}")
        return 'Unknown', 'Unknown', 'Unknown', 0

def collect_managed_policies(include_aws_managed=False):
    """Collect customer managed and optionally AWS managed policies."""
    policies_data = []

    try:
        iam_client = boto3.client('iam', region_name='us-gov-west-1')

        # Get customer managed policies
        utils.log_info("Collecting customer managed policies...")
        paginator = iam_client.get_paginator('list_policies')

        # Count total policies first
        total_policies = 0
        for page in paginator.paginate(Scope='Local'):
            total_policies += len(page['Policies'])

        utils.log_info(f"Found {total_policies} managed policies to process")

        processed = 0

        # Process customer managed policies
        paginator = iam_client.get_paginator('list_policies')
        for page in paginator.paginate(Scope='Local'):
            policies = page['Policies']

            for policy in policies:
                processed += 1
                progress = (processed / total_policies) * 100
                policy_name = policy['PolicyName']

                utils.log_info(f"[{progress:.1f}%] Processing policy {processed}/{total_policies}: {policy_name}")

                policy_info = process_managed_policy(iam_client, policy, 'Customer Managed')
                if policy_info:
                    policies_data.append(policy_info)

                time.sleep(0.05)  # Small delay to avoid throttling

    except Exception as e:
        utils.log_error("Error collecting managed policies", e)

    return policies_data

def process_managed_policy(iam_client, policy, policy_type):
    """Process a single managed policy."""
    try:
        policy_name = policy['PolicyName']
        policy_arn = policy['Arn']
        policy_id = policy['PolicyId']
        creation_date = policy['CreateDate'].strftime('%Y-%m-%d %H:%M:%S UTC') if policy['CreateDate'] else "Unknown"
        update_date = policy['UpdateDate'].strftime('%Y-%m-%d %H:%M:%S UTC') if policy['UpdateDate'] else "Unknown"
        days_since_updated = calculate_age_in_days(policy['UpdateDate'])
        path = policy.get('Path', '/')
        description = policy.get('Description', 'None')
        default_version_id = policy.get('DefaultVersionId', 'v1')

        # Get policy document
        try:
            policy_version = iam_client.get_policy_version(
                PolicyArn=policy_arn,
                VersionId=default_version_id
            )
            policy_doc = policy_version['PolicyVersion']['Document']
            analysis = analyze_policy_document(policy_doc)
        except Exception as e:
            utils.log_warning(f"Could not get policy document for {policy_name}: {e}")
            analysis = {
                'permission_summary': 'Unknown',
                'resource_scope': 'Unknown',
                'has_wildcard_actions': 'Unknown',
                'has_wildcard_resources': 'Unknown',
                'statement_count': 0,
                'condition_usage': 'Unknown',
                'risk_level': 'Unknown'
            }

        # Get attached entities
        attached_users, attached_groups, attached_roles, total_attachments = get_policy_entities(iam_client, policy_arn)

        # Determine usage status
        usage_status = 'Used' if total_attachments > 0 else 'Unused'

        return {
            'Policy Name': policy_name,
            'Policy Type': policy_type,
            'Policy ARN': policy_arn,
            'Policy ID': policy_id,
            'Attached To Count': total_attachments,
            'Attached Users': attached_users,
            'Attached Groups': attached_groups,
            'Attached Roles': attached_roles,
            'Permission Summary': analysis['permission_summary'],
            'Resource Scope': analysis['resource_scope'],
            'Has Wildcard Actions': analysis['has_wildcard_actions'],
            'Has Wildcard Resources': analysis['has_wildcard_resources'],
            'Statement Count': analysis['statement_count'],
            'Condition Usage': analysis['condition_usage'],
            'Version': default_version_id,
            'Default Version ID': default_version_id,
            'Creation Date': creation_date,
            'Last Updated': update_date,
            'Days Since Last Updated': days_since_updated,
            'Path': path,
            'Description': description,
            'Usage Status': usage_status,
            'Risk Level': analysis['risk_level']
        }

    except Exception as e:
        utils.log_warning(f"Error processing policy {policy.get('PolicyName', 'Unknown')}: {e}")
        return None

def export_to_excel(users_data, roles_data, policies_data, account_id, account_name):
    """Export comprehensive IAM data to Excel file with GovCloud naming convention."""
    if not users_data and not roles_data and not policies_data:
        utils.log_warning("No IAM data to export.")
        return None

    try:
        # Import pandas after dependency check
        import pandas as pd

        # Generate filename with GovCloud identifier
        current_date = datetime.datetime.now().strftime("%m.%d.%Y")

        # Use utils module to generate filename and save data with GovCloud identifier
        filename = utils.create_export_filename(
            account_name,
            "iam-comprehensive",
            "",
            current_date
        )

        # Create data frames for multi-sheet export
        data_frames = {}

        if users_data:
            users_df = pd.DataFrame(users_data)
            data_frames['IAM Users'] = users_df

        if roles_data:
            roles_df = pd.DataFrame(roles_data)
            data_frames['IAM Roles'] = roles_df

        if policies_data:
            policies_df = pd.DataFrame(policies_data)
            data_frames['IAM Policies'] = policies_df

        # Create comprehensive summary data
        summary_data = {
            'Category': [
                'IAM Users',
                'IAM Users - Active Console Access',
                'IAM Users - MFA Enabled',
                'IAM Users - Never Signed In',
                'IAM Users - With Access Keys',
                '',
                'IAM Roles',
                'IAM Roles - Service-linked',
                'IAM Roles - Cross-account',
                'IAM Roles - Standard',
                'IAM Roles - Never Used',
                'IAM Roles - Cross-Account Access',
                '',
                'IAM Policies',
                'IAM Policies - Customer Managed',
                'IAM Policies - Unused',
                'IAM Policies - High Risk',
                'IAM Policies - With Wildcards'
            ],
            'Count': [
                len(users_data),
                len([u for u in users_data if u.get('Console Access') == 'Enabled']) if users_data else 0,
                len([u for u in users_data if u.get('MFA') == 'Enabled']) if users_data else 0,
                len([u for u in users_data if u.get('Console Last Sign-in') == 'Never']) if users_data else 0,
                len([u for u in users_data if u.get('Access Key ID', 'None') != 'None']) if users_data else 0,
                '',
                len(roles_data),
                len([r for r in roles_data if r.get('Role Type') == 'Service-linked']) if roles_data else 0,
                len([r for r in roles_data if r.get('Role Type') == 'Cross-account']) if roles_data else 0,
                len([r for r in roles_data if r.get('Role Type') == 'Standard']) if roles_data else 0,
                len([r for r in roles_data if r.get('Last Used') == 'Never']) if roles_data else 0,
                len([r for r in roles_data if r.get('Cross-Account Access', '').startswith('Yes')]) if roles_data else 0,
                '',
                len(policies_data),
                len([p for p in policies_data if p.get('Policy Type') == 'Customer Managed']) if policies_data else 0,
                len([p for p in policies_data if p.get('Usage Status') == 'Unused']) if policies_data else 0,
                len([p for p in policies_data if p.get('Risk Level') == 'High']) if policies_data else 0,
                len([p for p in policies_data if p.get('Has Wildcard Actions') == 'Yes' or p.get('Has Wildcard Resources') == 'Yes']) if policies_data else 0
            ]
        }

        summary_df = pd.DataFrame(summary_data)
        data_frames['Summary'] = summary_df

        # Save using utils function for multi-sheet Excel
        output_path = utils.save_multiple_dataframes_to_excel(data_frames, filename)

        if output_path:
            utils.log_success("GovCloud comprehensive IAM data exported successfully!")
            utils.log_info(f"File location: {output_path}")
            utils.log_govcloud_info(f"Export contains {len(users_data)} users, {len(roles_data)} roles, and {len(policies_data)} policies")
            return str(output_path)
        else:
            utils.log_error("Error exporting to Excel. Please check the logs.")
            return None

    except Exception as e:
        utils.log_error("Error exporting to Excel", e)
        return None

def main():
    """Main function to orchestrate the comprehensive IAM information collection."""
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

        utils.log_info("Starting comprehensive IAM information collection from GovCloud...")
        print("====================================================================")

        # Collect all IAM data
        utils.log_info("Phase 1: Collecting IAM Users...")
        users_data = collect_iam_users()

        utils.log_info("Phase 2: Collecting IAM Roles...")
        roles_data = collect_iam_roles()

        utils.log_info("Phase 3: Collecting IAM Policies...")
        policies_data = collect_managed_policies()

        if not users_data and not roles_data and not policies_data:
            utils.log_warning("No IAM data collected. Exiting.")
            return

        print("\n====================================================================")
        print("COLLECTION COMPLETE")
        print("====================================================================")

        # Export to Excel
        filename = export_to_excel(users_data, roles_data, policies_data, account_id, account_name)

        if filename:
            utils.log_govcloud_info(f"Comprehensive IAM report exported with GovCloud compliance markers")
            utils.log_info(f"Total users processed: {len(users_data)}")
            utils.log_info(f"Total roles processed: {len(roles_data)}")
            utils.log_info(f"Total policies processed: {len(policies_data)}")

            # Display some summary statistics
            if users_data:
                mfa_users = len([u for u in users_data if u.get('MFA') == 'Enabled'])
                utils.log_info(f"Users with MFA enabled: {mfa_users}")

            if roles_data:
                cross_account_roles = len([r for r in roles_data if r.get('Cross-Account Access', '').startswith('Yes')])
                utils.log_info(f"Roles with cross-account access: {cross_account_roles}")

            if policies_data:
                high_risk_policies = len([p for p in policies_data if p.get('Risk Level') == 'High'])
                utils.log_info(f"High risk policies: {high_risk_policies}")

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