#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
===========================
= AWS GOVCLOUD RESOURCE SCANNER =
===========================

Title: AWS GovCloud RDS Instance Export Script
Version: v2.1.0-GovCloud
Date: AUG-19-2025

Description: 
This script exports a list of all RDS instances across available AWS GovCloud 
regions into a spreadsheet. The export includes DB Identifier, DB Cluster 
Identifier, Role, Engine, Engine Version, RDS Extended Support, Region, Size, 
Storage Type, Storage, Provisioned IOPS, Port, Endpoint, Master Username, VPC 
(Name and ID), Subnet IDs, Security Groups (Name and ID), DB Subnet Group Name, 
DB Certificate Expiry, Created Time, and Encryption information.

GovCloud Modifications:
- Limited to GovCloud regions (us-gov-east-1, us-gov-west-1)
- Added GovCloud region validation
- Updated partition handling for aws-us-gov
- Added GovCloud-specific compliance markers in output filenames
- Enhanced error handling for GovCloud-specific service limitations
"""

import os
import sys
import datetime
import json
import boto3
import time
import botocore.exceptions
from pathlib import Path

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

def print_title():
    """
    Print the title banner for the script.
    
    Returns:
        tuple: (account_id, account_name) - AWS account ID and mapped account name
    """
    print("====================================================================")
    print("                   AWS RESOURCE SCANNER                            ")
    print("====================================================================")
    print("            AWS GOVCLOUD RDS INSTANCE EXPORT SCRIPT v2.1.0        ")
    print("====================================================================")
    
    # Get the current AWS account ID using STS (Security Token Service)
    try:
        sts_client = boto3.client('sts')
        account_id = sts_client.get_caller_identity()['Account']
        
        # Validate GovCloud environment
        caller_arn = sts_client.get_caller_identity()['Arn']
        if not utils.is_govcloud_environment():
            utils.log_warning("You appear to be connected to commercial AWS, not GovCloud!")
            utils.log_warning("This script is optimized for AWS GovCloud IL4 environments.")
        
        # Map account ID to friendly name using utils module
        account_name = utils.get_account_name(account_id, default="UNKNOWN-ACCOUNT")
        print(f"Account ID: {account_id}")
        print(f"Account Name: {account_name}")
        print(f"Environment: AWS GovCloud IL4 (FedRAMP Moderate)")
    except Exception as e:
        utils.log_error("Unable to determine account information", e)
        account_id = "UNKNOWN"
        account_name = "UNKNOWN-ACCOUNT"
    
    print("====================================================================")
    return account_id, account_name

def check_and_install_dependencies():
    """
    Check for required dependencies and prompt to install if missing.
    This function ensures pandas and openpyxl are available for Excel export functionality.
    """
    required_packages = ['pandas', 'openpyxl']
    missing_packages = []
    
    # Check for each required package by attempting to import
    for package in required_packages:
        try:
            __import__(package)
            utils.log_info(f"[OK] {package} is already installed.")
        except ImportError:
            missing_packages.append(package)
    
    # If there are missing packages, prompt user to install them
    if missing_packages:
        utils.log_warning("Missing required dependencies:")
        for package in missing_packages:
            print(f"- {package}")
        
        while True:
            response = input("\nDo you want to install the missing dependencies? (y/n): ").strip().lower()
            if response == 'y':
                utils.log_info("Installing missing dependencies...")
                for package in missing_packages:
                    utils.log_info(f"Installing {package}...")
                    os.system(f"pip install {package}")
                
                # Verify installations by attempting to import again
                all_installed = True
                for package in missing_packages:
                    try:
                        __import__(package)
                        utils.log_success(f"{package} installed successfully.")
                    except ImportError:
                        utils.log_error(f"Failed to install {package}.")
                        all_installed = False
                
                if not all_installed:
                    utils.log_error("Some dependencies could not be installed. Please install them manually:")
                    for package in missing_packages:
                        print(f"pip install {package}")
                    sys.exit(1)
                break
            elif response == 'n':
                utils.log_error("Cannot proceed without required dependencies.")
                utils.log_info("Please install the following packages manually and try again:")
                for package in missing_packages:
                    print(f"pip install {package}")
                sys.exit(1)
            else:
                print("Invalid input. Please enter 'y' for yes or 'n' for no.")
    
    # Import required packages now that they're confirmed to be installed
    global pd
    import pandas as pd

def get_govcloud_regions():
    """
    Get a list of available GovCloud regions.
    
    Returns:
        list: A list of GovCloud region names
    """
    try:
        # Use utils function to get available GovCloud regions
        regions = utils.get_available_govcloud_regions()
        if not regions:
            utils.log_warning("No accessible GovCloud regions found. Using default list.")
            regions = utils.get_govcloud_regions()
        return regions
    except Exception as e:
        utils.log_error("Error getting GovCloud regions", e)
        return utils.get_govcloud_regions()

def is_valid_govcloud_region(region_name):
    """
    Check if a region name is a valid GovCloud region.
    
    Args:
        region_name (str): AWS region name to validate
        
    Returns:
        bool: True if valid, False otherwise
    """
    return utils.validate_govcloud_region(region_name)

def get_security_group_info(rds_client, sg_ids):
    """
    Get security group names and IDs from a list of security group IDs.
    
    Args:
        rds_client: The boto3 RDS client (used to determine region)
        sg_ids (list): A list of security group IDs
        
    Returns:
        str: Formatted list of security group names and IDs in format "name (id), name (id), ..."
    """
    if not sg_ids:
        return ""
    
    try:
        # Create EC2 client in the same region as the RDS client
        region = rds_client.meta.region_name
        ec2_client = boto3.client('ec2', region_name=region)
        
        # Get security group information using EC2 describe_security_groups API
        response = ec2_client.describe_security_groups(GroupIds=sg_ids)
        # Format as "name (id), name (id), ..."
        sg_info = [f"{sg['GroupName']} ({sg['GroupId']})" for sg in response['SecurityGroups']]
        return ", ".join(sg_info)
    except Exception as e:
        # Return just the IDs if we can't get the names
        utils.log_warning(f"Could not get security group names for {sg_ids}: {e}")
        return ", ".join(sg_ids)

def get_vpc_info(rds_client, vpc_id):
    """
    Get VPC name and ID information from a VPC ID.
    
    Args:
        rds_client: The boto3 RDS client (used to determine region)
        vpc_id (str): The VPC ID
        
    Returns:
        str: Formatted VPC name and ID in format "name (id)" or just ID if name not found
    """
    if not vpc_id:
        return "N/A"
    
    try:
        # Create EC2 client in the same region as the RDS client
        region = rds_client.meta.region_name
        ec2_client = boto3.client('ec2', region_name=region)
        
        # Get VPC information using EC2 describe_vpcs API
        response = ec2_client.describe_vpcs(VpcIds=[vpc_id])
        if response['Vpcs']:
            vpc = response['Vpcs'][0]
            vpc_name = "Unnamed"
            # Check for Name tag in VPC tags
            for tag in vpc.get('Tags', []):
                if tag['Key'] == 'Name':
                    vpc_name = tag['Value']
                    break
            return f"{vpc_name} ({vpc_id})"
        return vpc_id
    except Exception as e:
        # Return just the ID if we can't get the VPC details
        utils.log_warning(f"Could not get VPC info for {vpc_id}: {e}")
        return vpc_id

def get_subnet_ids(subnet_group):
    """
    Extract subnet IDs from a DB subnet group.
    
    Args:
        subnet_group (dict): The DB subnet group information from RDS API
        
    Returns:
        str: Comma-separated list of subnet IDs
    """
    if not subnet_group or 'Subnets' not in subnet_group:
        return "N/A"
    
    try:
        # Extract subnet identifiers from the subnet group
        subnet_ids = [subnet['SubnetIdentifier'] for subnet in subnet_group['Subnets']]
        return ", ".join(subnet_ids)
    except Exception:
        return "N/A"

def get_rds_instances(region):
    """
    Get all RDS instances in a specific GovCloud region with detailed information.
    
    Args:
        region (str): AWS GovCloud region name
        
    Returns:
        list: List of dictionaries containing RDS instance information
    """
    # Validate region is GovCloud
    if not utils.validate_govcloud_region(region):
        utils.log_error(f"Invalid GovCloud region: {region}")
        return []
    
    rds_instances = []
    try:
        # Create RDS client for the specified GovCloud region
        rds_client = boto3.client('rds', region_name=region)
        
        # Get all DB instances using pagination to handle large numbers of instances
        paginator = rds_client.get_paginator('describe_db_instances')
        page_iterator = paginator.paginate()

        # Count total instances first for progress tracking
        total_instances = 0
        for page in paginator.paginate():
            total_instances += len(page['DBInstances'])

        if total_instances > 0:
            utils.log_info(f"Found {total_instances} RDS instances in {region} to process")

        # Reset paginator for actual processing
        paginator = rds_client.get_paginator('describe_db_instances')
        page_iterator = paginator.paginate()

        # Process each page of results
        processed = 0
        for page in page_iterator:
            for instance in page['DBInstances']:
                processed += 1
                instance_id = instance.get('DBInstanceIdentifier', 'Unknown')
                progress = (processed / total_instances) * 100 if total_instances > 0 else 0

                utils.log_info(f"[{progress:.1f}%] Processing RDS instance {processed}/{total_instances}: {instance_id}")
                # Extract security group IDs from VPC security groups
                sg_ids = [sg['VpcSecurityGroupId'] for sg in instance.get('VpcSecurityGroups', [])]
                sg_info = get_security_group_info(rds_client, sg_ids)
                
                # Get VPC information from DB subnet group
                vpc_id = instance.get('DBSubnetGroup', {}).get('VpcId', 'N/A')
                vpc_info = get_vpc_info(rds_client, vpc_id) if vpc_id != 'N/A' else 'N/A'
                
                # Get subnet IDs from DB subnet group
                subnet_ids = get_subnet_ids(instance.get('DBSubnetGroup', {}))
                
                # Get port information from endpoint
                port = instance.get('Endpoint', {}).get('Port', 'N/A') if 'Endpoint' in instance else 'N/A'
                
                # Get endpoint address - RDS connection endpoint
                endpoint_address = instance.get('Endpoint', {}).get('Address', 'N/A') if 'Endpoint' in instance else 'N/A'
                
                # Get master username - the primary database user
                master_username = instance.get('MasterUsername', 'N/A')
                
                # Determine if instance is part of a cluster and its role
                db_cluster_id = instance.get('DBClusterIdentifier', 'N/A')
                role = 'Standalone'
                if db_cluster_id != 'N/A':
                    try:
                        # Get cluster info to determine if this instance is primary or replica
                        cluster_info = rds_client.describe_db_clusters(
                            DBClusterIdentifier=db_cluster_id
                        )
                        if cluster_info and 'DBClusters' in cluster_info and cluster_info['DBClusters']:
                            cluster = cluster_info['DBClusters'][0]
                            # Check if this instance is the primary (writer) in the cluster
                            if 'DBClusterMembers' in cluster:
                                for member in cluster['DBClusterMembers']:
                                    if member.get('DBInstanceIdentifier') == instance['DBInstanceIdentifier']:
                                        role = 'Primary' if member.get('IsClusterWriter', False) else 'Replica'
                    except Exception as e:
                        # If we can't determine cluster role, leave as default
                        utils.log_warning(f"Could not determine cluster role for {instance['DBInstanceIdentifier']}: {e}")
                
                # Check for RDS Extended Support status
                extended_support = 'No'
                try:
                    if 'StatusInfos' in instance:
                        for status_info in instance['StatusInfos']:
                            if status_info.get('Status') == 'extended-support':
                                extended_support = 'Yes'
                except Exception:
                    pass
                
                # Format certificate expiry date
                cert_expiry = 'N/A'
                try:
                    if 'CertificateDetails' in instance and 'ValidTill' in instance['CertificateDetails']:
                        valid_till = instance['CertificateDetails']['ValidTill']
                        if isinstance(valid_till, datetime.datetime):
                            cert_expiry = valid_till.replace(tzinfo=None).strftime('%Y-%m-%d %H:%M:%S')
                except Exception:
                    pass
                
                # Format creation time
                created_time = 'N/A'
                try:
                    if 'InstanceCreateTime' in instance:
                        create_time = instance['InstanceCreateTime']
                        if isinstance(create_time, datetime.datetime):
                            created_time = create_time.replace(tzinfo=None).strftime('%Y-%m-%d %H:%M:%S')
                except Exception:
                    pass
                
                # Create comprehensive instance data dictionary
                instance_data = {
                    'DB Identifier': instance['DBInstanceIdentifier'],
                    'DB Cluster Identifier': db_cluster_id,
                    'Role': role,
                    'Engine': instance['Engine'],
                    'Engine Version': instance['EngineVersion'],
                    'RDS Extended Support': extended_support,
                    'Region': region,
                    'Size': instance['DBInstanceClass'],
                    'Storage Type': instance['StorageType'],
                    'Storage (GB)': instance['AllocatedStorage'],
                    'Provisioned IOPS': instance.get('Iops', 'N/A'),
                    'Port': port,
                    'Endpoint': endpoint_address,  # RDS connection endpoint
                    'Master Username': master_username,  # Primary database user
                    'VPC': vpc_info,
                    'Subnet IDs': subnet_ids,
                    'Security Groups': sg_info,
                    'DB Subnet Group Name': instance.get('DBSubnetGroup', {}).get('DBSubnetGroupName', 'N/A'),
                    'DB Certificate Expiry': cert_expiry,
                    'Created Time': created_time,
                    'Encryption': 'Yes' if instance.get('StorageEncrypted', False) else 'No',
                    'Owner ID': utils.get_account_name_formatted(instance.get('OwnerId', 'N/A'))
                }
                
                rds_instances.append(instance_data)

                # Small delay to avoid API throttling
                if processed < total_instances:  # Don't delay after the last instance
                    time.sleep(0.1)
        
        return rds_instances
    except botocore.exceptions.ClientError as e:
        # Handle specific AWS client errors
        if e.response['Error']['Code'] == 'AccessDenied':
            utils.log_warning(f"Access denied in GovCloud region {region}. Skipping...")
        elif e.response['Error']['Code'] == 'AuthFailure':
            utils.log_warning(f"Authentication failure in GovCloud region {region}. Skipping...")
        else:
            utils.log_error(f"Error in GovCloud region {region}", e)
        return []
    except Exception as e:
        utils.log_error(f"Error accessing GovCloud region {region}", e)
        return []

def export_to_excel(data, account_name, region_filter=None):
    """
    Export RDS instance data to an Excel file using pandas and openpyxl.
    
    Args:
        data (list): List of dictionaries containing RDS instance information
        account_name (str): Name of the AWS account for filename
        region_filter (str, optional): Region filter to include in filename
        
    Returns:
        str: Path to the exported file, or None if export failed
    """
    if not data:
        utils.log_warning("No RDS instances found to export.")
        return None
    
    try:
        # Import pandas (should be installed by now)
        import pandas as pd
        
        # Process data to remove timezone information from datetime objects
        processed_data = []
        for item in data:
            processed_item = {}
            for key, value in item.items():
                if isinstance(value, datetime.datetime) and value.tzinfo is not None:
                    processed_item[key] = value.replace(tzinfo=None)
                else:
                    processed_item[key] = value
            processed_data.append(processed_item)
        
        # Convert processed data to pandas DataFrame
        df = pd.DataFrame(processed_data)
        
        # Define output file name with date and optional region filter
        today = datetime.datetime.now().strftime("%m.%d.%Y")
        region_suffix = f"{region_filter}" if region_filter else ""
        
        # Use the utility function for consistent GovCloud file naming
        filename = utils.create_export_filename(
            account_name, 
            "rds-instances", 
            region_suffix, 
            today
        )
        
        # Save using utils function
        saved_file = utils.save_dataframe_to_excel(df, filename, sheet_name='RDS Instances')
        
        if saved_file:
            utils.log_success("GovCloud RDS data exported successfully!")
            utils.log_info(f"File location: {saved_file}")
            return saved_file
        else:
            utils.log_error("Failed to save using utils.save_dataframe_to_excel()")
            return None
            
    except Exception as e:
        utils.log_error("Error exporting data", e)
        
        # Fallback to CSV if Excel export fails
        try:
            import pandas as pd
            csv_filename = filename.replace('.xlsx', '.csv')
            csv_file = utils.get_output_filepath(csv_filename)
            pd.DataFrame(data).to_csv(csv_file, index=False)
            utils.log_info(f"Exported to CSV instead: {csv_file}")
            return str(csv_file)
        except Exception as csv_error:
            utils.log_error("CSV export also failed", csv_error)
            return None

def main():
    """
    Main function to coordinate the GovCloud RDS instance export process.
    This function orchestrates the entire workflow from user input to final export.
    """
    # Print script title and get account information
    account_id, account_name = print_title()
    
    # Check and install dependencies before proceeding
    check_and_install_dependencies()
    
    if account_name == "UNKNOWN-ACCOUNT":
        proceed = utils.prompt_for_confirmation("Unable to determine account name. Proceed anyway?", default=False)
        if not proceed:
            utils.log_info("Exiting script...")
            sys.exit(0)
    
    # Get user input for GovCloud region selection
    print("\nGovCloud Region Selection:")
    print("Would you like the information for all GovCloud regions or a specific region?")
    print("Available GovCloud regions: us-gov-east-1, us-gov-west-1")
    region_choice = input("If all, write \"all\", or specify a GovCloud region name: ").strip().lower()
    
    # Get all available GovCloud regions for validation
    all_govcloud_regions = get_govcloud_regions()
    
    # Determine which regions to scan based on user input
    if region_choice == "all":
        regions_to_scan = all_govcloud_regions
        region_filter = None
        utils.log_info(f"Scanning all available GovCloud regions: {', '.join(regions_to_scan)}")
    else:
        # Validate the region name against available GovCloud regions
        if not is_valid_govcloud_region(region_choice):
            utils.log_warning(f"'{region_choice}' is not a valid GovCloud region.")
            utils.log_info("Valid GovCloud regions: us-gov-east-1, us-gov-west-1")
            utils.log_info("Defaulting to scanning all GovCloud regions.")
            regions_to_scan = all_govcloud_regions
            region_filter = None
        else:
            regions_to_scan = [region_choice]
            region_filter = region_choice
            utils.log_info(f"Scanning only the {region_choice} GovCloud region.")
    
    # Initialize data collection list
    all_rds_instances = []
    
    utils.log_info(f"Collecting RDS instance data across {len(regions_to_scan)} GovCloud region(s)...")
    
    # Process each region and collect RDS instance data
    for region in regions_to_scan:
        utils.log_info(f"Searching for RDS instances in GovCloud region: {region}")
        
        # Get RDS instances in the current region
        region_instances = get_rds_instances(region)
        
        # Add region instances to the total collection
        all_rds_instances.extend(region_instances)
        
        # Display count for this region for user feedback
        utils.log_info(f"Found {len(region_instances)} RDS instances in {region}")
    
    # Export results to Excel file
    utils.log_success(f"Found {len(all_rds_instances)} RDS instances in total across all GovCloud regions.")
    
    if all_rds_instances:
        output_file = export_to_excel(all_rds_instances, account_name, region_filter)
        if output_file:
            utils.log_govcloud_info(f"Export contains data from {len(regions_to_scan)} GovCloud region(s)")
            utils.log_govcloud_info(f"Total RDS instances exported: {len(all_rds_instances)}")
            print("\nScript execution completed.")
        else:
            utils.log_error("Failed to export data. Please check the logs.")
            sys.exit(1)
    else:
        utils.log_warning("No RDS instances found in any GovCloud region. No file exported.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nOperation cancelled by user.")
        sys.exit(1)
    except Exception as e:
        utils.log_error("An unexpected error occurred", e)
        sys.exit(1)