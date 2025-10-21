#!/usr/bin/env python3

"""
===========================
= AWS GOVCLOUD RESOURCE SCANNER =
===========================

Title: StratusScan GovCloud Configuration Tool
Version: v1.0.0-GovCloud
Date: AUG-26-2025

Description:
Interactive configuration tool for setting up the StratusScan GovCloud environment.
This script allows users to configure account mappings, default regions, and other
GovCloud-specific settings in the config_govcloud.json file.

Features:
- Interactive account ID and name mapping setup
- GovCloud region selection (us-gov-east-1, us-gov-west-1)
- Validates AWS account ID format (12 digits)
- Creates or updates config_govcloud.json file
- Preserves existing configuration while adding new entries
- Dependency validation and automatic installation
- Command-line options for dependency checking only

Usage:
- python configure_govcloud.py          (full configuration)
- python configure_govcloud.py --deps   (dependency check only)
- python configure_govcloud.py --perms  (AWS permissions check only)
"""

import os
import sys
import json
import re
import subprocess
import boto3
from pathlib import Path
from botocore.exceptions import ClientError, NoCredentialsError

def print_header():
    """Print the configuration tool header."""
    print("=" * 70)
    print("         STRATUSSCAN GOVCLOUD CONFIGURATION TOOL")
    print("=" * 70)
    print("Version: v1.0.0-GovCloud                    Date: AUG-26-2025")
    print("Environment: AWS GovCloud IL4 (FedRAMP Moderate)")
    print("=" * 70)
    print()

def validate_account_id(account_id):
    """
    Validate that the account ID is a 12-digit number.
    
    Args:
        account_id (str): The account ID to validate
        
    Returns:
        bool: True if valid, False otherwise
    """
    # Remove any whitespace
    account_id = account_id.strip()
    
    # Check if it's exactly 12 digits
    pattern = re.compile(r'^\d{12}$')
    return bool(pattern.match(account_id))

def get_govcloud_region_choice():
    """
    Get the user's choice for the default GovCloud region.
    
    Returns:
        str: The selected GovCloud region
    """
    print("\nGovCloud Region Selection:")
    print("Please select the default GovCloud region:")
    print("1. us-gov-east-1 (US GovCloud East)")
    print("2. us-gov-west-1 (US GovCloud West)")
    
    while True:
        try:
            choice = input("\nEnter your choice (1 or 2): ").strip()
            
            if choice == "1":
                return "us-gov-east-1"
            elif choice == "2":
                return "us-gov-west-1"
            else:
                print("Invalid choice. Please enter 1 or 2.")
        except KeyboardInterrupt:
            print("\n\nConfiguration cancelled by user.")
            sys.exit(0)

def load_existing_config(config_path):
    """
    Load existing configuration file if it exists.
    
    Args:
        config_path (Path): Path to the config file
        
    Returns:
        dict: Existing configuration or default structure
    """
    if config_path.exists():
        try:
            with open(config_path, 'r') as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            print(f"Warning: Could not read existing config file: {e}")
            print("Creating new configuration...")
    
    # Return default GovCloud configuration structure
    return {
        "__comment": "StratusScan GovCloud Configuration - Customize this file for your environment",
        "account_mappings": {},
        "agency_name": "YOUR-AGENCY",
        "govcloud_environment": "IL4",
        "default_regions": ["us-gov-east-1", "us-gov-west-1"],
        "resource_preferences": {
            "ec2": {
                "default_filter": "all",
                "include_stopped": True,
                "default_region": "us-gov-east-1"
            },
            "vpc": {
                "default_export_type": "all",
                "default_region": "us-gov-east-1"
            },
            "s3": {
                "default_region": "us-gov-east-1"
            },
            "ebs": {
                "default_region": "us-gov-east-1"
            },
            "rds": {
                "default_region": "us-gov-east-1"
            },
            "ecs": {
                "default_region": "us-gov-east-1"
            },
            "elb": {
                "default_region": "us-gov-east-1"
            },
            "compute_optimizer": {
                "enabled": True,
                "note": "Limited availability in GovCloud - may not be available in all regions",
                "default_region": "us-gov-east-1"
            }
        },
        "disabled_services": {
            "trusted_advisor": {
                "reason": "Not available in AWS GovCloud",
                "enabled": False,
                "alternative": "Use AWS Config Rules or custom compliance scripts"
            }
        },
        "govcloud_specific": {
            "partition": "aws-us-gov",
            "compliance_level": "FedRAMP Moderate",
            "valid_regions": ["us-gov-east-1", "us-gov-west-1"],
            "notes": [
                "This configuration is optimized for AWS GovCloud IL4 (FedRAMP Moderate)",
                "Some AWS services have limited availability in GovCloud",
                "Trusted Advisor is not available - use AWS Config for compliance monitoring",
                "Always verify service availability in your specific GovCloud regions"
            ]
        }
    }

def get_account_mappings():
    """
    Interactively collect account ID and name mappings from the user.
    
    Returns:
        dict: Dictionary of account ID to name mappings
    """
    mappings = {}
    
    print("\n" + "=" * 50)
    print("ACCOUNT MAPPING CONFIGURATION")
    print("=" * 50)
    print("Enter your AWS GovCloud account ID and corresponding friendly name.")
    print("You can add multiple accounts. Press Enter without input when done.")
    print()
    
    while True:
        print(f"\nAccount #{len(mappings) + 1}:")
        
        # Get Account ID
        while True:
            account_id = input("Enter AWS Account ID (12 digits) or press Enter to finish: ").strip()
            
            # If empty, user is done
            if not account_id:
                if len(mappings) == 0:
                    print("Warning: No account mappings configured. You can add them later by running this script again.")
                return mappings
            
            # Validate account ID format
            if validate_account_id(account_id):
                # Check if account ID already exists
                if account_id in mappings:
                    overwrite = input(f"Account ID {account_id} already exists. Overwrite? (y/n): ").lower().strip()
                    if overwrite != 'y':
                        continue
                break
            else:
                print("Invalid account ID. Must be exactly 12 digits (e.g., 123456789012)")
        
        # Get Account Name
        while True:
            account_name = input(f"Enter friendly name for account {account_id}: ").strip()
            if account_name:
                break
            print("Account name cannot be empty.")
        
        # Store the mapping
        mappings[account_id] = account_name
        print(f"Added: {account_id} -> {account_name}")
        
        # Ask if user wants to add more
        more = input("\nWould you like to add another account? (y/n): ").lower().strip()
        if more != 'y':
            break
    
    return mappings

def get_agency_name(current_agency="YOUR-AGENCY"):
    """
    Get the agency/company name from the user.

    Args:
        current_agency (str): Current agency/company name in config

    Returns:
        str: Agency/company name
    """
    print(f"\nCurrent agency/company name: {current_agency}")
    agency = input("Enter your agency/company name (or press Enter to keep current): ").strip()
    
    if agency:
        return agency
    return current_agency

def update_resource_preferences(config, default_region):
    """
    Update resource preferences with the selected default region.
    
    Args:
        config (dict): Configuration dictionary
        default_region (str): Selected default region
    """
    if "resource_preferences" in config:
        for service, prefs in config["resource_preferences"].items():
            if isinstance(prefs, dict) and "default_region" in prefs:
                prefs["default_region"] = default_region

def save_configuration(config, config_path):
    """
    Save the configuration to the JSON file.
    
    Args:
        config (dict): Configuration dictionary
        config_path (Path): Path to save the config file
    """
    try:
        # Create backup if file exists
        if config_path.exists():
            backup_path = config_path.with_suffix('.json.backup')
            config_path.rename(backup_path)
            print(f"Backup created: {backup_path}")
        
        # Save new configuration
        with open(config_path, 'w') as f:
            json.dump(config, f, indent=2)
        
        print(f"\nConfiguration saved successfully to: {config_path}")
        return True
        
    except Exception as e:
        print(f"Error saving configuration: {e}")
        return False

def display_summary(config):
    """
    Display a summary of the current configuration.
    
    Args:
        config (dict): Configuration dictionary
    """
    print("\n" + "=" * 50)
    print("CONFIGURATION SUMMARY")
    print("=" * 50)
    
    # Agency/company name
    print(f"Agency/Company Name: {config.get('agency_name', 'Not set')}")
    
    # Default regions
    default_regions = config.get('default_regions', [])
    print(f"Default Regions: {', '.join(default_regions)}")
    
    # Account mappings
    mappings = config.get('account_mappings', {})
    print(f"\nAccount Mappings ({len(mappings)} configured):")
    if mappings:
        for account_id, name in mappings.items():
            print(f"  {account_id} -> {name}")
    else:
        print("  None configured")
    
    # Resource preferences (show EC2 default region as example)
    ec2_region = config.get('resource_preferences', {}).get('ec2', {}).get('default_region', 'Not set')
    print(f"\nDefault Resource Region: {ec2_region}")
    
    print("=" * 50)

def check_dependencies():
    """
    Check if required StratusScan dependencies are installed.

    Returns:
        tuple: (bool, list) - (all_dependencies_satisfied, missing_packages)
    """
    required_packages = [
        {'name': 'boto3', 'import_name': 'boto3', 'description': 'AWS SDK for Python'},
        {'name': 'pandas', 'import_name': 'pandas', 'description': 'Data manipulation and analysis library'},
        {'name': 'openpyxl', 'import_name': 'openpyxl', 'description': 'Excel file reading/writing library'}
    ]

    missing_packages = []
    installed_packages = []

    print("\n" + "=" * 50)
    print("DEPENDENCY CHECK")
    print("=" * 50)
    print("Checking required StratusScan dependencies...")

    for package in required_packages:
        try:
            __import__(package['import_name'])
            print(f"[OK] {package['name']} - {package['description']}")
            installed_packages.append(package)
        except ImportError:
            print(f"[MISSING] {package['name']} - {package['description']}")
            missing_packages.append(package)

    print(f"\nSummary: {len(installed_packages)}/{len(required_packages)} dependencies satisfied")

    if missing_packages:
        print(f"\nMissing packages: {', '.join([p['name'] for p in missing_packages])}")
        return False, missing_packages
    else:
        print("\n[SUCCESS] All dependencies are installed and ready!")
        return True, []

def install_dependencies(missing_packages):
    """
    Install missing dependencies with user confirmation.

    Args:
        missing_packages (list): List of package dictionaries to install

    Returns:
        bool: True if installation was successful, False otherwise
    """
    if not missing_packages:
        return True

    print("\n" + "=" * 50)
    print("DEPENDENCY INSTALLATION")
    print("=" * 50)

    print("The following packages need to be installed:")
    for package in missing_packages:
        print(f"  - {package['name']} - {package['description']}")

    confirm = input(f"\nWould you like to install these {len(missing_packages)} packages now? (y/n): ").lower().strip()

    if confirm != 'y':
        print("Dependency installation skipped.")
        print("Note: StratusScan may not work properly without these dependencies.")
        return False

    print(f"\nInstalling packages using pip...")

    all_successful = True

    for package in missing_packages:
        print(f"\n[INSTALLING] {package['name']}...")
        try:
            result = subprocess.run([
                sys.executable, "-m", "pip", "install", package['name']
            ], capture_output=True, text=True, check=True)

            print(f"[SUCCESS] {package['name']} installed successfully")

            # Verify the installation
            try:
                __import__(package['import_name'])
                print(f"[VERIFIED] {package['name']} import verification successful")
            except ImportError:
                print(f"[WARNING] {package['name']} installed but import verification failed")
                all_successful = False

        except subprocess.CalledProcessError as e:
            print(f"[ERROR] Failed to install {package['name']}")
            print(f"Error: {e.stderr.strip()}")
            all_successful = False
        except Exception as e:
            print(f"[ERROR] Unexpected error installing {package['name']}: {e}")
            all_successful = False

    if all_successful:
        print(f"\n[SUCCESS] All dependencies installed successfully!")
        print("StratusScan is now ready to use.")
    else:
        print(f"\n[WARNING] Some dependencies failed to install.")
        print("You may need to install them manually or check your Python environment.")

    return all_successful

def dependency_management_menu():
    """
    Interactive menu for dependency management.

    Returns:
        bool: True if dependencies are satisfied, False otherwise
    """
    while True:
        # Check current dependency status
        deps_satisfied, missing_packages = check_dependencies()

        if deps_satisfied:
            print(f"\n[SUCCESS] All dependencies are satisfied!")
            return True

        print(f"\n[OPTIONS] Dependency Management Options:")
        print("1. Install missing dependencies automatically")
        print("2. Show installation commands for manual installation")
        print("3. Continue without installing dependencies")
        print("4. Check dependencies again")

        choice = input("\nSelect an option (1-4): ").strip()

        if choice == '1':
            success = install_dependencies(missing_packages)
            if success:
                return True
            else:
                print("\nSome dependencies failed to install. You can:")
                print("- Try option 2 for manual installation commands")
                print("- Continue with option 3 (not recommended)")
                continue

        elif choice == '2':
            print(f"\n[MANUAL] Installation Commands:")
            print("Run the following commands in your terminal:")
            print(f"")
            for package in missing_packages:
                print(f"pip install {package['name']}")
            print(f"\nAlternatively, install all at once:")
            print(f"pip install {' '.join([p['name'] for p in missing_packages])}")
            print(f"\nAfter manual installation, choose option 4 to check again.")
            continue

        elif choice == '3':
            print(f"\n[WARNING] Continuing without all dependencies installed.")
            print("Note: StratusScan scripts may fail to run properly.")
            return False

        elif choice == '4':
            print(f"\nRechecking dependencies...")
            continue

        else:
            print("Invalid choice. Please select 1-4.")
            continue

def get_aws_managed_policy_recommendations():
    """
    Get comprehensive AWS managed policy recommendations for StratusScan.

    Returns:
        dict: Dictionary of service categories and their recommended managed policies
    """
    return {
        'core_permissions': {
            'policies': ['ReadOnlyAccess'],
            'description': 'Comprehensive read-only access to most AWS services',
            'priority': 'HIGH',
            'reason': 'Provides broad read access needed for resource scanning'
        },
        'alternative_minimal': {
            'policies': [
                'AmazonEC2ReadOnlyAccess',
                'AmazonS3ReadOnlyAccess',
                'AmazonRDSReadOnlyAccess',
                'AmazonVPCReadOnlyAccess',
                'IAMReadOnlyAccess',
                'AWSCloudTrailReadOnlyAccess',
                'CloudWatchReadOnlyAccess'
            ],
            'description': 'Minimal set of service-specific read-only policies',
            'priority': 'MEDIUM',
            'reason': 'More granular control but requires multiple policy attachments'
        },
        'cost_management': {
            'policies': ['AWSBillingReadOnlyAccess'],
            'description': 'Access to Cost Explorer for service usage analysis',
            'priority': 'MEDIUM',
            'reason': 'Required for services-in-use detection via cost data'
        },
        'identity_center': {
            'policies': ['AWSSSOReadOnly'],
            'description': 'Read access to AWS IAM Identity Center (SSO)',
            'priority': 'LOW',
            'reason': 'Only needed if using Identity Center export scripts'
        },
        'security_services': {
            'policies': ['SecurityAudit'],
            'description': 'Read access to security-related configurations',
            'priority': 'MEDIUM',
            'reason': 'Provides access to security services like GuardDuty, Security Hub'
        }
    }

def test_aws_permissions():
    """
    Test current AWS permissions by attempting key API calls.

    Returns:
        dict: Dictionary of permission test results
    """
    permission_tests = {
        'sts:GetCallerIdentity': {
            'test_function': lambda: boto3.client('sts').get_caller_identity(),
            'required': True,
            'service': 'AWS Security Token Service',
            'description': 'Basic AWS authentication verification'
        },
        'ec2:DescribeInstances': {
            'test_function': lambda: boto3.client('ec2', region_name='us-gov-west-1').describe_instances(MaxResults=5),
            'required': True,
            'service': 'Amazon EC2',
            'description': 'List EC2 instances for compute resource scanning'
        },
        's3:ListBuckets': {
            'test_function': lambda: boto3.client('s3').list_buckets(),
            'required': True,
            'service': 'Amazon S3',
            'description': 'List S3 buckets for storage resource scanning'
        },
        'iam:ListUsers': {
            'test_function': lambda: boto3.client('iam').list_users(MaxItems=5),
            'required': True,
            'service': 'AWS Identity and Access Management',
            'description': 'List IAM users for identity management scanning'
        },
        'rds:DescribeDBInstances': {
            'test_function': lambda: boto3.client('rds', region_name='us-gov-west-1').describe_db_instances(),
            'required': True,
            'service': 'Amazon RDS',
            'description': 'List RDS instances for database resource scanning'
        },
        'ec2:DescribeVpcs': {
            'test_function': lambda: boto3.client('ec2', region_name='us-gov-west-1').describe_vpcs(),
            'required': True,
            'service': 'Amazon VPC',
            'description': 'List VPCs for network resource scanning'
        },
        'ce:GetDimensionValues': {
            'test_function': lambda: boto3.client('ce', region_name='us-gov-west-1').get_dimension_values(
                TimePeriod={'Start': '2024-01-01', 'End': '2024-01-02'},
                Dimension='SERVICE'
            ),
            'required': False,
            'service': 'AWS Cost Explorer',
            'description': 'Access cost data for comprehensive service discovery'
        },
        'cloudtrail:LookupEvents': {
            'test_function': lambda: boto3.client('cloudtrail', region_name='us-gov-west-1').lookup_events(MaxItems=1),
            'required': False,
            'service': 'AWS CloudTrail',
            'description': 'Access event history for service usage analysis'
        },
        'sso-admin:ListInstances': {
            'test_function': lambda: boto3.client('sso-admin', region_name='us-gov-west-1').list_instances(),
            'required': False,
            'service': 'AWS IAM Identity Center',
            'description': 'List Identity Center instances for SSO analysis'
        },
        'identitystore:ListUsers': {
            'test_function': lambda: boto3.client('identitystore', region_name='us-gov-west-1').list_users(
                IdentityStoreId='d-example123456'  # This will likely fail but tests the permission
            ),
            'required': False,
            'service': 'AWS Identity Store',
            'description': 'Access Identity Store for user/group analysis'
        }
    }

    results = {}

    for permission, config in permission_tests.items():
        try:
            config['test_function']()
            results[permission] = {
                'status': 'ALLOWED',
                'error': None,
                'required': config['required'],
                'service': config['service'],
                'description': config['description']
            }
        except ClientError as e:
            error_code = e.response['Error']['Code']
            results[permission] = {
                'status': 'DENIED',
                'error': error_code,
                'required': config['required'],
                'service': config['service'],
                'description': config['description']
            }
        except Exception as e:
            results[permission] = {
                'status': 'ERROR',
                'error': str(e),
                'required': config['required'],
                'service': config['service'],
                'description': config['description']
            }

    return results

def check_aws_permissions():
    """
    Check AWS permissions and provide recommendations.

    Returns:
        tuple: (bool, dict) - (has_required_permissions, detailed_results)
    """
    print("\n" + "=" * 50)
    print("AWS PERMISSIONS CHECK")
    print("=" * 50)
    print("Testing AWS permissions for StratusScan operations...")

    try:
        # Test basic AWS connectivity first
        sts = boto3.client('sts')
        identity = sts.get_caller_identity()
        user_arn = identity.get('Arn', 'Unknown')
        account_id = identity.get('Account', 'Unknown')

        print(f"\nAWS Identity: {user_arn}")
        print(f"Account ID: {account_id}")
        print(f"User ID: {identity.get('UserId', 'Unknown')}")

    except NoCredentialsError:
        print("\n[ERROR] No AWS credentials found!")
        print("Please configure your AWS credentials before running StratusScan.")
        return False, {'error': 'No AWS credentials configured'}
    except Exception as e:
        print(f"\n[ERROR] AWS authentication failed: {e}")
        return False, {'error': f'AWS authentication failed: {e}'}

    # Test individual permissions
    print(f"\nTesting individual permissions...")
    permission_results = test_aws_permissions()

    # Analyze results
    required_passed = 0
    required_failed = 0
    optional_passed = 0
    optional_failed = 0

    print(f"\nPermission Test Results:")
    print("-" * 50)

    for permission, result in permission_results.items():
        status_icon = "[OK]" if result['status'] == 'ALLOWED' else "[DENIED]"
        priority = "REQUIRED" if result['required'] else "OPTIONAL"

        print(f"{status_icon} {permission} ({priority})")
        print(f"    Service: {result['service']}")
        print(f"    Purpose: {result['description']}")

        if result['status'] != 'ALLOWED':
            print(f"    Error: {result['error']}")

        # Count results
        if result['required']:
            if result['status'] == 'ALLOWED':
                required_passed += 1
            else:
                required_failed += 1
        else:
            if result['status'] == 'ALLOWED':
                optional_passed += 1
            else:
                optional_failed += 1

        print()

    # Summary
    total_required = required_passed + required_failed
    total_optional = optional_passed + optional_failed

    print("=" * 50)
    print("PERMISSIONS SUMMARY")
    print("=" * 50)
    print(f"Required permissions: {required_passed}/{total_required} passed")
    print(f"Optional permissions: {optional_passed}/{total_optional} passed")

    has_required_permissions = required_failed == 0

    if has_required_permissions:
        print("\n[SUCCESS] All required permissions are available!")
        if optional_failed > 0:
            print(f"[INFO] {optional_failed} optional permissions are missing.")
            print("Some advanced features may not be available.")
    else:
        print(f"\n[WARNING] {required_failed} required permissions are missing!")
        print("StratusScan scripts may fail without these permissions.")

    return has_required_permissions, {
        'required_passed': required_passed,
        'required_failed': required_failed,
        'optional_passed': optional_passed,
        'optional_failed': optional_failed,
        'detailed_results': permission_results
    }

def show_policy_recommendations(permission_results):
    """
    Show AWS managed policy recommendations based on permission test results.

    Args:
        permission_results (dict): Results from permission testing
    """
    print("\n" + "=" * 50)
    print("AWS MANAGED POLICY RECOMMENDATIONS")
    print("=" * 50)

    policy_recommendations = get_aws_managed_policy_recommendations()

    # Check if user has required permissions
    has_required = permission_results.get('required_failed', 0) == 0

    if has_required:
        print("[SUCCESS] You already have the required permissions!")
        print("No additional policies needed for basic StratusScan functionality.")

        # Check optional permissions
        if permission_results.get('optional_failed', 0) > 0:
            print(f"\n[OPTIONAL] To enable all features, consider these policies:")

            if 'ce:GetDimensionValues' in [p for p, r in permission_results.get('detailed_results', {}).items()
                                          if r.get('status') != 'ALLOWED']:
                print(f"\nFor Cost Analysis features:")
                for policy in policy_recommendations['cost_management']['policies']:
                    print(f"  - {policy}")
                print(f"  Purpose: {policy_recommendations['cost_management']['description']}")

            if any('sso' in p.lower() or 'identity' in p.lower() for p, r in permission_results.get('detailed_results', {}).items()
                   if r.get('status') != 'ALLOWED'):
                print(f"\nFor Identity Center features:")
                for policy in policy_recommendations['identity_center']['policies']:
                    print(f"  - {policy}")
                print(f"  Purpose: {policy_recommendations['identity_center']['description']}")
    else:
        print("[REQUIRED] You need additional permissions to run StratusScan.")
        print("Choose ONE of these approaches:\n")

        # Recommend primary approach
        print("RECOMMENDED: Single comprehensive policy")
        print("-" * 40)
        for policy in policy_recommendations['core_permissions']['policies']:
            print(f"• {policy}")
        print(f"Benefits: {policy_recommendations['core_permissions']['description']}")
        print(f"Priority: {policy_recommendations['core_permissions']['priority']}")
        print(f"Reason: {policy_recommendations['core_permissions']['reason']}\n")

        # Alternative approach
        print("ALTERNATIVE: Multiple service-specific policies")
        print("-" * 40)
        for policy in policy_recommendations['alternative_minimal']['policies']:
            print(f"• {policy}")
        print(f"Benefits: {policy_recommendations['alternative_minimal']['description']}")
        print(f"Priority: {policy_recommendations['alternative_minimal']['priority']}")
        print(f"Reason: {policy_recommendations['alternative_minimal']['reason']}\n")

        # Additional policies
        print("ADDITIONAL: Enhanced features (optional)")
        print("-" * 40)
        for category in ['cost_management', 'security_services']:
            info = policy_recommendations[category]
            for policy in info['policies']:
                print(f"• {policy}")
            print(f"  Purpose: {info['description']}\n")

    print("=" * 50)
    print("HOW TO ATTACH POLICIES")
    print("=" * 50)
    print("1. Go to the AWS IAM Console")
    print("2. Navigate to Users or Roles (depending on your authentication method)")
    print("3. Select your user/role")
    print("4. Click 'Add permissions' > 'Attach policies directly'")
    print("5. Search for and select the recommended managed policies above")
    print("6. Click 'Add permissions' to apply")
    print("\nNote: These are all AWS managed policies - no custom policies needed!")

def permissions_management_menu():
    """
    Interactive menu for AWS permissions management.

    Returns:
        bool: True if permissions are adequate, False otherwise
    """
    while True:
        # Check current permission status
        has_required, results = check_aws_permissions()

        print(f"\n[OPTIONS] Permissions Management Options:")
        print("1. Show AWS managed policy recommendations")
        print("2. Re-test permissions (after applying policies)")
        print("3. Continue with current permissions")
        print("4. Show detailed permission test results")

        choice = input("\nSelect an option (1-4): ").strip()

        if choice == '1':
            show_policy_recommendations(results)
            continue

        elif choice == '2':
            print(f"\nRe-testing permissions...")
            continue

        elif choice == '3':
            if not has_required:
                print(f"\n[WARNING] Continuing without all required permissions!")
                print("StratusScan scripts may encounter errors or produce incomplete results.")
                confirm = input("Are you sure you want to continue? (y/n): ").lower().strip()
                if confirm != 'y':
                    continue
            return has_required

        elif choice == '4':
            # Show detailed results
            detailed = results.get('detailed_results', {})
            print(f"\n[DETAILS] Complete Permission Test Results:")
            print("-" * 50)

            for permission, result in detailed.items():
                print(f"Permission: {permission}")
                print(f"  Status: {result['status']}")
                print(f"  Required: {'Yes' if result['required'] else 'No'}")
                print(f"  Service: {result['service']}")
                print(f"  Description: {result['description']}")
                if result['error']:
                    print(f"  Error: {result['error']}")
                print()
            continue

        else:
            print("Invalid choice. Please select 1-4.")
            continue

def main():
    """Main function to run the configuration tool."""
    try:
        # Print header
        print_header()

        # Check and manage dependencies
        print("Checking StratusScan dependencies before configuration...")
        dependency_management_menu()

        # Check and manage AWS permissions
        print("\nChecking AWS permissions for StratusScan operations...")
        permissions_management_menu()

        # Get the config file path (same directory as this script)
        script_dir = Path(__file__).parent.absolute()
        config_path = script_dir / "config_govcloud.json"

        print(f"\nConfiguration file: {config_path}")
        
        # Load existing configuration
        config = load_existing_config(config_path)
        
        # Show current configuration if it exists
        if config_path.exists():
            print("\nCurrent configuration loaded:")
            display_summary(config)
            
            modify = input("\nWould you like to modify the configuration? (y/n): ").lower().strip()
            if modify != 'y':
                print("Configuration unchanged. Exiting...")
                return
        
        # Get agency name
        current_agency = config.get('agency_name', 'YOUR-AGENCY')
        agency_name = get_agency_name(current_agency)
        config['agency_name'] = agency_name
        
        # Get default GovCloud region
        print(f"\nCurrent default regions: {', '.join(config.get('default_regions', []))}")
        change_region = input("Would you like to change the primary default region? (y/n): ").lower().strip()
        
        if change_region == 'y':
            default_region = get_govcloud_region_choice()
            # Update all default regions to prioritize the selected one
            config['default_regions'] = [default_region, "us-gov-east-1" if default_region == "us-gov-west-1" else "us-gov-west-1"]
            # Update resource preferences
            update_resource_preferences(config, default_region)
            print(f"Default region updated to: {default_region}")
        
        # Get account mappings
        print(f"\nCurrent account mappings: {len(config.get('account_mappings', {}))}")
        modify_accounts = input("Would you like to add/modify account mappings? (y/n): ").lower().strip()
        
        if modify_accounts == 'y':
            new_mappings = get_account_mappings()
            # Merge with existing mappings
            existing_mappings = config.get('account_mappings', {})
            existing_mappings.update(new_mappings)
            config['account_mappings'] = existing_mappings
        
        # Display final configuration summary
        display_summary(config)
        
        # Confirm save
        save_confirm = input("\nSave this configuration? (y/n): ").lower().strip()
        
        if save_confirm == 'y':
            if save_configuration(config, config_path):
                print("\n✅ Configuration completed successfully!")
                print(f"You can now use StratusScan GovCloud with your configured settings.")
                print(f"Run 'python stratusscan-govcloud.py' to start the main menu.")
            else:
                print("\n❌ Configuration save failed.")
                sys.exit(1)
        else:
            print("\nConfiguration not saved. Exiting...")
    
    except KeyboardInterrupt:
        print("\n\nConfiguration cancelled by user.")
        sys.exit(0)
    except Exception as e:
        print(f"\nAn unexpected error occurred: {e}")
        sys.exit(1)

if __name__ == "__main__":
    # Check for command-line arguments
    if len(sys.argv) > 1:
        if '--deps' in sys.argv or '--dependencies' in sys.argv:
            # Run dependency check only
            print_header()
            print("Running dependency check only...\n")
            dependency_management_menu()
            print("\nDependency check complete.")
            sys.exit(0)
        elif '--perms' in sys.argv or '--permissions' in sys.argv:
            # Run permissions check only
            print_header()
            print("Running AWS permissions check only...\n")
            permissions_management_menu()
            print("\nPermissions check complete.")
            sys.exit(0)
        elif '--help' in sys.argv or '-h' in sys.argv:
            print("StratusScan GovCloud Configuration Tool")
            print("\nUsage:")
            print("  python configure_govcloud.py           # Full configuration")
            print("  python configure_govcloud.py --deps    # Dependency check only")
            print("  python configure_govcloud.py --perms   # Permissions check only")
            print("  python configure_govcloud.py --help    # Show this help")
            sys.exit(0)
        else:
            print(f"Unknown argument: {sys.argv[1]}")
            print("Use --help for usage information.")
            sys.exit(1)

    # Run full configuration
    main()