#!/usr/bin/env python3

"""
===========================
= AWS GOVCLOUD RESOURCE SCANNER =
===========================

Title: AWS GovCloud EBS Volume Data Export
Version: v1.1.0-GovCloud
Date: AUG-19-2025

Description: 
This script collects EBS volume information across GovCloud regions (us-gov-east-1, us-gov-west-1) 
in an account and exports the data to a spreadsheet file. The data includes volume ID, name, size,
state, instance ID (if attached), and GovCloud-specific compliance information.

GovCloud Modifications:
- Limited to GovCloud regions (us-gov-east-1, us-gov-west-1)
- Added GovCloud region validation
- Updated partition handling for aws-us-gov
- Added GovCloud-specific compliance markers in output filenames
- Enhanced error handling for GovCloud-specific service limitations
"""

import boto3
import os
import datetime
import csv
import sys
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
        response = input("Would you like to install these packages now? (y/n): ").lower()
        
        if response == 'y':
            import subprocess
            for package in missing_packages:
                utils.log_info(f"Installing {package}...")
                try:
                    subprocess.check_call([sys.executable, "-m", "pip", "install", package])
                    utils.log_success(f"Successfully installed {package}")
                except Exception as e:
                    utils.log_error(f"Error installing {package}", e)
                    print("Please install it manually with: pip install " + package)
                    return False
            return True
        else:
            print("Cannot proceed without required dependencies.")
            return False
    
    return True

def get_account_info():
    """
    Get the AWS account ID and name of the current session, with GovCloud validation.
    
    Returns:
        tuple: (account_id, account_name)
    """
    try:
        # Create a boto3 STS client to get account information
        sts_client = boto3.client('sts')
        # Get the account ID from the STS GetCallerIdentity API call
        account_id = sts_client.get_caller_identity()["Account"]
        
        # Validate GovCloud environment
        caller_arn = sts_client.get_caller_identity()['Arn']
        if not utils.is_govcloud_environment():
            utils.log_warning("You appear to be connected to commercial AWS, not GovCloud!")
            utils.log_warning("This script is optimized for AWS GovCloud IL4 environments.")
        
        # Get account name from utils
        account_name = utils.get_account_name(account_id, default="UNKNOWN-ACCOUNT")
        return account_id, account_name
    except Exception as e:
        utils.log_error("Error getting account information", e)
        return "UNKNOWN", "UNKNOWN-ACCOUNT"

def get_govcloud_regions():
    """
    Get a list of available GovCloud regions.
    
    Returns:
        list: List of GovCloud region names
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
        region_name (str): The region name to validate
        
    Returns:
        bool: True if valid, False otherwise
    """
    return utils.validate_govcloud_region(region_name)

def get_volume_name(volume):
    """
    Extract the volume name from tags.
    
    Args:
        volume (dict): The volume object from the API response
        
    Returns:
        str: The name of the volume or 'N/A' if not present
    """
    if 'Tags' in volume:
        for tag in volume['Tags']:
            if tag['Key'] == 'Name':
                return tag['Value']
    return 'N/A'

def format_tags(tags):
    """
    Format volume tags in the format "Key1:Value1, Key2:Value2, etc..."
    
    Args:
        tags (list): List of tag dictionaries with Key and Value
        
    Returns:
        str: Formatted tags string or 'N/A' if no tags
    """
    if not tags:
        return 'N/A'
    
    formatted_tags = []
    for tag in tags:
        if 'Key' in tag and 'Value' in tag:
            formatted_tags.append(f"{tag['Key']}:{tag['Value']}")
    
    if formatted_tags:
        return ', '.join(formatted_tags)
    else:
        return 'N/A'

def get_ebs_volumes(region):
    """
    Get all EBS volumes in a specific GovCloud region.
    
    Args:
        region (str): AWS GovCloud region name
        
    Returns:
        list: List of volume dictionaries with relevant information
    """
    # Validate region is GovCloud
    if not utils.validate_govcloud_region(region):
        utils.log_error(f"Invalid GovCloud region: {region}")
        return []
    
    # Create a boto3 EC2 client for the specified GovCloud region
    ec2_client = boto3.client('ec2', region_name=region)
    
    # Initialize an empty list to store volume information
    volumes_data = []
    
    try:
        # Use pagination to handle large numbers of volumes
        paginator = ec2_client.get_paginator('describe_volumes')
        for page in paginator.paginate():
            for volume in page['Volumes']:
                # Initialize variables for volume data
                volume_name = get_volume_name(volume)
                instance_id = "Not attached"
                device_name = "N/A"
                attachment_state = "N/A"
                
                # Get attachment information if the volume is attached
                if volume['Attachments']:
                    attachment = volume['Attachments'][0]
                    instance_id = attachment['InstanceId']
                    device_name = attachment['Device']
                    attachment_state = attachment['State']
                
                # Get KMS key information for encrypted volumes
                kms_key_id = volume.get('KmsKeyId', 'N/A') if volume.get('Encrypted', False) else 'N/A'
                
                # Get IOPS information
                iops = volume.get('Iops', 'N/A')
                
                # Get throughput information (for gp3 volumes)
                throughput = volume.get('Throughput', 'N/A')
                
                # Get multi-attach enabled status
                multi_attach = 'Yes' if volume.get('MultiAttachEnabled', False) else 'No'
                
                # Format tags
                volume_tags = format_tags(volume.get('Tags', []))
                
                # Get owner information
                owner_id = utils.get_account_name_formatted(volume.get('OwnerId', 'N/A'))
                
                # Format creation time
                create_time = volume['CreateTime'].strftime('%Y-%m-%d %H:%M:%S') if 'CreateTime' in volume else 'N/A'
                
                # Add volume data to the list with comprehensive information
                volumes_data.append({
                    'Region': region,
                    'Volume ID': volume['VolumeId'],
                    'Name': volume_name,
                    'Size (GB)': volume['Size'],
                    'State': volume['State'],
                    'Attached To': instance_id,
                    'Device Name': device_name,
                    'Attachment State': attachment_state,
                    'Volume Type': volume['VolumeType'],
                    'IOPS': iops,
                    'Throughput (MiB/s)': throughput,
                    'Encrypted': 'Yes' if volume['Encrypted'] else 'No',
                    'KMS Key ID': kms_key_id,
                    'Multi-Attach': multi_attach,
                    'Create Time': create_time,
                    'Availability Zone': volume['AvailabilityZone'],
                    'Snapshot ID': volume.get('SnapshotId', 'N/A'),
                    'Owner ID': owner_id,
                    'Tags': volume_tags
                })
    except Exception as e:
        utils.log_error(f"Error getting volumes in GovCloud region {region}", e)
    
    return volumes_data

def print_title():
    """
    Print a formatted title for the script and validate GovCloud environment.
    
    Returns:
        tuple: (account_id, account_name)
    """
    print("====================================================================")
    print("                   AWS RESOURCE SCANNER                            ")
    print("====================================================================")
    print("AWS GOVCLOUD EBS VOLUME DATA EXPORT")
    print("====================================================================")
    print("Version: v1.1.0-GovCloud                       Date: AUG-19-2025")
    print("Environment: AWS GovCloud IL4 (FedRAMP Moderate)")
    print("====================================================================")
    
    # Get account information
    account_id, account_name = get_account_info()
    
    print(f"Account ID: {account_id}")
    print(f"Account Name: {account_name}")
    print("====================================================================")
    return account_id, account_name

def create_excel_file(account_name, volumes_data, region_input="all"):
    """
    Export volumes data to an Excel file using pandas with GovCloud identifier.
    
    Args:
        account_name (str): Name of the AWS account
        volumes_data (list): List of dictionaries containing volume information
        region_input (str): Region specification for filename (default: "all")
        
    Returns:
        str: Path to the exported Excel file
    """
    # Import pandas here to avoid issues if it's not installed
    import pandas as pd
    
    # Convert data to pandas DataFrame
    df = pd.DataFrame(volumes_data)
    
    # Generate suffix based on region input
    suffix = "" if region_input == "all" else region_input
    
    # Generate filename using utils with GovCloud identifier
    filename = utils.create_export_filename(
        account_name, 
        "ebs-volumes", 
        suffix, 
        datetime.datetime.now().strftime("%m.%d.%Y")
    )
    
    # Save using the utility function in utils_govcloud.py
    saved_path = utils.save_dataframe_to_excel(df, filename)
    
    if saved_path:
        return saved_path
    else:
        # Fallback to direct save if utils function fails
        output_path = utils.get_output_filepath(filename)
        df.to_excel(output_path, index=False)
        return output_path

def main():
    """
    Main function to execute the script.
    """
    try:
        # Print the script title and get account information
        account_id, account_name = print_title()
        
        # Check for required dependencies
        if not check_dependencies():
            sys.exit(1)
            
        # Import pandas now that we've checked dependencies
        import pandas as pd
        
        if account_name == "UNKNOWN-ACCOUNT":
            proceed = utils.prompt_for_confirmation("Unable to determine account name. Proceed anyway?", default=False)
            if not proceed:
                utils.log_info("Exiting script...")
                sys.exit(0)
        
        # Get GovCloud regions
        utils.log_info("Getting list of AWS GovCloud regions...")
        all_regions = get_govcloud_regions()
        
        if not all_regions:
            utils.log_error("No GovCloud regions found. Please check your AWS credentials and permissions.")
            sys.exit(1)
            
        utils.log_info(f"Found {len(all_regions)} GovCloud regions: {', '.join(all_regions)}")
        
        # Prompt user for GovCloud region selection
        print("\nGovCloud Region Selection:")
        print("Would you like the information for all GovCloud regions or a specific region?")
        print("Available GovCloud regions: us-gov-east-1, us-gov-west-1")
        region_input = input("If all, write \"all\", or specify a GovCloud region name: ").strip().lower()
        
        # Determine which GovCloud regions to scan
        if region_input == "all":
            regions = all_regions
            utils.log_info("Collecting EBS data from all GovCloud regions...")
        else:
            # Validate the input region is a GovCloud region
            if is_valid_govcloud_region(region_input):
                regions = [region_input]
                utils.log_info(f"Collecting EBS data from GovCloud region: {region_input}")
            else:
                utils.log_warning(f"'{region_input}' is not a valid GovCloud region.")
                utils.log_info("Valid GovCloud regions: us-gov-east-1, us-gov-west-1")
                utils.log_info("Defaulting to all GovCloud regions...")
                regions = all_regions
                region_input = "all"
        
        # Initialize an empty list to store volume data from all regions
        all_volumes = []
        
        # Iterate through each GovCloud region and collect volume data
        for i, region in enumerate(regions):
            utils.log_info(f"Collecting EBS volume data from {region} ({i+1}/{len(regions)})...")
            try:
                # Get EBS volumes for the current GovCloud region
                region_volumes = get_ebs_volumes(region)
                all_volumes.extend(region_volumes)
                utils.log_info(f"  Found {len(region_volumes)} volumes in {region}.")
            except Exception as e:
                # Handle exceptions for regions that might not be accessible
                utils.log_error(f"Error collecting data from {region}", e)
        
        # Print summary of collected data
        utils.log_success(f"Total EBS volumes found across all GovCloud regions: {len(all_volumes)}")
        
        if not all_volumes:
            utils.log_warning("No volumes found in any GovCloud region. Exiting...")
            sys.exit(0)
        
        # Export data to Excel file
        utils.log_info("Exporting data to Excel format...")
        excel_path = create_excel_file(account_name, all_volumes, region_input)
        
        if excel_path:
            utils.log_success("GovCloud EBS volume data exported successfully!")
            utils.log_info(f"File location: {excel_path}")
            utils.log_govcloud_info(f"Export contains data from {len(regions)} GovCloud region(s)")
            utils.log_govcloud_info(f"Total volumes exported: {len(all_volumes)}")
            print("\nScript execution completed.")
        else:
            utils.log_error("Error exporting data. Please check the logs.")
            sys.exit(1)
        
    except KeyboardInterrupt:
        print("\n\nScript interrupted by user. Exiting...")
        sys.exit(0)
    except Exception as e:
        utils.log_error("Unexpected error occurred", e)
        sys.exit(1)

if __name__ == "__main__":
    main()