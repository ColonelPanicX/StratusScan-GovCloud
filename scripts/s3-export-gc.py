#!/usr/bin/env python3

""" 
===========================
= AWS GOVCLOUD RESOURCE SCANNER =
===========================

Title: AWS GovCloud S3 Bucket Inventory Export 
Version: v2.0.0-GovCloud
Date: AUG-19-2025 

Description:
This script exports information about S3 buckets across AWS GovCloud regions including 
bucket name, region, creation date, and total object count. Bucket sizes are retrieved 
using S3 Storage Lens where available. The data is exported to a spreadsheet file with 
a standardized naming convention including GovCloud identifiers for compliance and audit purposes.

GovCloud Modifications:
- Limited to GovCloud regions (us-gov-east-1, us-gov-west-1)
- Added GovCloud region validation
- Updated partition handling for aws-us-gov
- Added GovCloud-specific compliance markers in output filenames
- Enhanced error handling for GovCloud-specific service limitations
"""

import boto3
import pandas as pd
import sys
import os
import datetime
import time
import argparse
from botocore.exceptions import ClientError
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
    Prints a formatted title banner for the script to the console and validates GovCloud environment
    
    Returns:
        tuple: (account_id, account_name)
    """
    # Get the current AWS account ID using STS
    try:
        sts_client = boto3.client('sts')
        # Get the current account ID
        account_id = sts_client.get_caller_identity()["Account"]
        
        # Validate GovCloud environment
        caller_arn = sts_client.get_caller_identity()['Arn']
        if not utils.is_govcloud_environment():
            utils.log_warning("You appear to be connected to commercial AWS, not GovCloud!")
            utils.log_warning("This script is optimized for AWS GovCloud IL4 environments.")
        
        # Get the account name from the utils module
        account_name = utils.get_account_name(account_id, default="UNKNOWN-ACCOUNT")
    except Exception as e:
        utils.log_error("Error retrieving account information", e)
        account_id = "UNKNOWN"
        account_name = "UNKNOWN-ACCOUNT"
        
    # Print a formatted title banner
    print("====================================================================")
    print("                  AWS RESOURCE SCANNER                              ")
    print("====================================================================")
    print("AWS GOVCLOUD S3 BUCKET INVENTORY EXPORT SCRIPT")
    print("====================================================================")
    print("Version: v2.0.0-GovCloud                       Date: AUG-19-2025")
    print("Environment: AWS GovCloud IL4 (FedRAMP Moderate)")
    print("====================================================================")
    print(f"Account ID: {account_id}")
    print(f"Account Name: {account_name}")
    print("====================================================================")
    
    return account_id, account_name

def check_dependencies():
    """
    Checks if required dependencies are installed and prompts the user to install if missing
    
    Returns:
        bool: True if all dependencies are installed or user chose to install, False otherwise
    """
    required_packages = ['pandas', 'boto3', 'openpyxl']
    missing_packages = []
    
    # Check for each required package
    for package in required_packages:
        try:
            __import__(package)
            utils.log_info(f"[OK] {package} is already installed")
        except ImportError:
            missing_packages.append(package)
    
    # If there are missing packages, prompt user to install
    if missing_packages:
        utils.log_warning(f"The following required packages are missing: {', '.join(missing_packages)}")
        install_choice = input("Do you want to install these packages? ('y' for yes, 'n' for no): ")
        
        if install_choice.lower() == 'y':
            # Attempt to install the missing packages
            import subprocess
            for package in missing_packages:
                try:
                    utils.log_info(f"Installing {package}...")
                    subprocess.check_call([sys.executable, "-m", "pip", "install", package])
                    utils.log_success(f"Successfully installed {package}")
                except subprocess.CalledProcessError as e:
                    utils.log_error(f"Failed to install {package}", e)
                    return False
            return True
        else:
            utils.log_error("Script cannot continue without required dependencies.")
            return False
    
    return True

def get_govcloud_regions():
    """
    Get a list of available GovCloud regions
    
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
    Check if a region name is a valid GovCloud region
    
    Args:
        region_name (str): The region name to validate
        
    Returns:
        bool: True if valid, False otherwise
    """
    return utils.validate_govcloud_region(region_name)

def get_bucket_region(bucket_name):
    """
    Determine the region of a specific S3 bucket
    
    Args:
        bucket_name (str): Name of the S3 bucket
        
    Returns:
        str: AWS region name of the bucket
    """
    # Create an S3 client without specifying a region
    s3_client = boto3.client('s3')
    
    try:
        # Get the bucket's location
        response = s3_client.get_bucket_location(Bucket=bucket_name)
        location = response['LocationConstraint']
        
        # In GovCloud, handle the location constraint differently
        if location is None:
            # For GovCloud, None typically means us-gov-west-1 (default GovCloud region)
            return 'us-gov-west-1'
        return location
    except Exception as e:
        utils.log_warning(f"Error getting region for bucket {bucket_name}: {e}")
        return "unknown"

def get_bucket_object_count(bucket_name, region):
    """
    Get the total number of objects in a bucket
    
    Args:
        bucket_name (str): Name of the S3 bucket
        region (str): AWS GovCloud region where the bucket is located
        
    Returns:
        int: Total number of objects in the bucket
    """
    # Validate region is GovCloud
    if not utils.validate_govcloud_region(region):
        utils.log_error(f"Invalid GovCloud region: {region}")
        return 0
    
    # Create an S3 client in the bucket's region
    s3_client = boto3.client('s3', region_name=region)
    
    total_objects = 0
    
    try:
        # Use a paginator to handle buckets with many objects
        paginator = s3_client.get_paginator('list_objects_v2')
        
        # Paginate through all objects in the bucket
        for page in paginator.paginate(Bucket=bucket_name):
            if 'Contents' in page:
                total_objects += len(page['Contents'])
                    
        return total_objects
    except Exception as e:
        utils.log_warning(f"Error counting objects for bucket {bucket_name}: {e}")
        return 0

def check_storage_lens_availability():
    """
    Check if S3 Storage Lens is configured and available in GovCloud
    
    Returns:
        bool: True if Storage Lens is available, False otherwise
    """
    try:
        # Create S3 Control client in a GovCloud region
        s3control_client = boto3.client('s3control', region_name='us-gov-east-1')
        
        # Get caller identity for Account ID
        account_id = boto3.client('sts').get_caller_identity()["Account"]
        
        # List Storage Lens configurations
        response = s3control_client.list_storage_lens_configurations(
            AccountId=account_id
        )
        
        # Check if there are any Storage Lens configurations
        if 'StorageLensConfigurationList' in response and len(response['StorageLensConfigurationList']) > 0:
            utils.log_info("Found S3 Storage Lens configurations. Will attempt to use for bucket metrics.")
            return True
        else:
            utils.log_info("No S3 Storage Lens configurations found. Will use standard object counting for metrics.")
            return False
    except Exception as e:
        utils.log_warning(f"Error checking Storage Lens availability: {e}")
        utils.log_info("Will use standard object counting for metrics.")
        return False

def get_latest_storage_lens_data(account_id):
    """
    Get the latest available Storage Lens data from GovCloud
    
    Args:
        account_id (str): AWS account ID
        
    Returns:
        dict: Dictionary mapping bucket names to their metrics
    """
    try:
        # Create S3 Control client in GovCloud region
        s3control_client = boto3.client('s3control', region_name='us-gov-east-1')
        
        # List Storage Lens configurations
        configurations = s3control_client.list_storage_lens_configurations(
            AccountId=account_id
        )
        
        if 'StorageLensConfigurationList' not in configurations or len(configurations['StorageLensConfigurationList']) == 0:
            return {}
            
        # Get the first configuration ID (default configuration if available)
        config_id = configurations['StorageLensConfigurationList'][0]['Id']
        
        # Try to get data from CloudWatch metrics in GovCloud
        latest_data = {}
        
        # Try to get data for yesterday (Storage Lens data is available the next day)
        today = datetime.datetime.now()
        yesterday = today - datetime.timedelta(days=1)
        
        # Try CloudWatch metrics in each GovCloud region
        govcloud_regions = utils.get_govcloud_regions()
        
        for region in govcloud_regions:
            try:
                cw_client = boto3.client('cloudwatch', region_name=region)
                
                # Get a list of all buckets
                s3_client = boto3.client('s3')
                buckets = [bucket['Name'] for bucket in s3_client.list_buckets()['Buckets']]
                
                for bucket_name in buckets:
                    # Skip if we already have data for this bucket
                    if bucket_name in latest_data:
                        continue
                        
                    try:
                        # Get BucketSizeBytes metric
                        size_response = cw_client.get_metric_statistics(
                            Namespace='AWS/S3',
                            MetricName='BucketSizeBytes',
                            Dimensions=[
                                {'Name': 'BucketName', 'Value': bucket_name},
                                {'Name': 'StorageType', 'Value': 'StandardStorage'}
                            ],
                            StartTime=yesterday - datetime.timedelta(days=1),
                            EndTime=today,
                            Period=86400,
                            Statistics=['Average']
                        )
                        
                        # Get NumberOfObjects metric
                        objects_response = cw_client.get_metric_statistics(
                            Namespace='AWS/S3',
                            MetricName='NumberOfObjects',
                            Dimensions=[
                                {'Name': 'BucketName', 'Value': bucket_name},
                                {'Name': 'StorageType', 'Value': 'AllStorageTypes'}
                            ],
                            StartTime=yesterday - datetime.timedelta(days=1),
                            EndTime=today,
                            Period=86400,
                            Statistics=['Average']
                        )
                        
                        # Process metrics if available
                        size_bytes = 0
                        obj_count = 0
                        
                        if 'Datapoints' in size_response and len(size_response['Datapoints']) > 0:
                            size_bytes = size_response['Datapoints'][0]['Average']
                            
                        if 'Datapoints' in objects_response and len(objects_response['Datapoints']) > 0:
                            obj_count = int(objects_response['Datapoints'][0]['Average'])
                        
                        latest_data[bucket_name] = {
                            'size_bytes': size_bytes,
                            'object_count': obj_count
                        }
                        
                    except Exception as e:
                        utils.log_warning(f"Error getting metrics for bucket {bucket_name} in region {region}: {e}")
                        # Skip this bucket and continue
                        continue
                        
            except Exception as e:
                utils.log_warning(f"Error getting CloudWatch metrics in region {region}: {e}")
                continue
        
        return latest_data
            
    except Exception as e:
        utils.log_error("Error retrieving Storage Lens data", e)
        return {}

def convert_to_mb(size_in_bytes):
    """
    Convert bytes to megabytes
    
    Args:
        size_in_bytes (int or str): Size in bytes or "Not Available"
        
    Returns:
        float or str: Size in MB with 2 decimal places or "0" if not available
    """
    if size_in_bytes == "Not Available" or size_in_bytes == 0:
        return "0"
        
    # Convert bytes to MB (1 MB = 1024 * 1024 bytes)
    try:
        size_in_mb = float(size_in_bytes) / (1024 * 1024)
        return f"{size_in_mb:.2f}"
    except (ValueError, TypeError):
        return "0"

def get_s3_buckets_info(use_storage_lens=False, target_region=None):
    """
    Collect information about S3 buckets across GovCloud regions or a specific GovCloud region
    
    Args:
        use_storage_lens (bool): Whether to try using Storage Lens for size metrics
        target_region (str): Specific GovCloud region to target or None for all GovCloud regions
        
    Returns:
        list: List of dictionaries containing bucket information
    """
    # Initialize global S3 client to list all buckets
    s3_client = boto3.client('s3')
    
    all_buckets_info = []
    storage_lens_data = {}
    
    # Get account ID
    account_id = boto3.client('sts').get_caller_identity()["Account"]
    
    # Validate target region if specified
    if target_region and not utils.validate_govcloud_region(target_region):
        utils.log_error(f"Invalid GovCloud region: {target_region}")
        return []
    
    # Try to get Storage Lens data if requested
    if use_storage_lens:
        storage_lens_data = get_latest_storage_lens_data(account_id)
    
    try:
        # Get the list of all buckets
        response = s3_client.list_buckets()
        
        # Filter the buckets based on the target GovCloud region
        buckets_to_process = []
        for bucket in response['Buckets']:
            bucket_name = bucket['Name']
            
            # Get the bucket's region if we need to filter
            if target_region:
                region = get_bucket_region(bucket_name)
                
                # Only include buckets in the specified GovCloud region
                if region == target_region:
                    buckets_to_process.append(bucket)
            else:
                # For all regions, check if bucket is in any GovCloud region
                region = get_bucket_region(bucket_name)
                if utils.is_govcloud_region(region):
                    buckets_to_process.append(bucket)
                
        total_buckets = len(buckets_to_process)
        utils.log_info(f"Found {total_buckets} S3 buckets" + 
              (f" in GovCloud region {target_region}" if target_region else " across all GovCloud regions") + 
              ". Gathering details for each bucket...")
        
        # Process each bucket
        for i, bucket in enumerate(buckets_to_process, 1):
            bucket_name = bucket['Name']
            creation_date = bucket['CreationDate']
            
            progress = (i / total_buckets) * 100
            utils.log_info(f"[{progress:.1f}%] Processing bucket {i}/{total_buckets}: {bucket_name}")
            
            # Get the bucket's region if we haven't already
            if target_region:
                region = target_region
            else:
                region = get_bucket_region(bucket_name)
            
            # Initialize size and object count
            size_bytes = 0
            object_count = 0
            
            # Try to get info from Storage Lens if available
            if bucket_name in storage_lens_data:
                size_bytes = storage_lens_data[bucket_name]['size_bytes']
                object_count = storage_lens_data[bucket_name]['object_count']
                size_source = "Storage Lens/CloudWatch"
            else:
                # Fall back to counting objects directly
                object_count = get_bucket_object_count(bucket_name, region)
                size_source = "Not Available"
            
            # Convert size to MB
            size_mb = convert_to_mb(size_bytes)
            
            # Get owner information
            owner_id = utils.get_account_name_formatted(account_id)
            
            # Add bucket info to our list
            bucket_info = {
                'Bucket Name': bucket_name,
                'Region': region,
                'Creation Date': creation_date,
                'Object Count': object_count,
                'Size (MB)': size_mb,
                'Size Source': size_source,
                'Owner': owner_id
            }
            
            all_buckets_info.append(bucket_info)

            # Small delay to avoid API throttling
            if i < total_buckets:  # Don't delay after the last bucket
                time.sleep(0.2)
            
    except Exception as e:
        utils.log_error("Error retrieving S3 bucket information", e)
    
    return all_buckets_info

def export_to_excel(buckets_info, account_name, target_region=None):
    """
    Export bucket information to an Excel file with GovCloud identifier
    
    Args:
        buckets_info (list): List of dictionaries with bucket information
        account_name (str): Name of the AWS account for file naming
        target_region (str): Specific GovCloud region being targeted (or None for all)
        
    Returns:
        str: Path to the created file
    """
    # Create a DataFrame from the bucket information
    df = pd.DataFrame(buckets_info)
    
    # Reorder columns for better readability
    column_order = [
        'Bucket Name', 
        'Region', 
        'Creation Date', 
        'Object Count',
        'Size (MB)',
        'Size Source',
        'Owner'
    ]
    
    # Reorder columns (only include columns that exist in the DataFrame)
    available_columns = [col for col in column_order if col in df.columns]
    df = df[available_columns]
    
    # Format the creation date to be more readable
    if 'Creation Date' in df.columns:
        df['Creation Date'] = df['Creation Date'].dt.strftime('%Y-%m-%d %H:%M:%S')
    
    # Generate filename with current date and GovCloud identifier
    current_date = datetime.datetime.now().strftime("%m.%d.%Y")
    
    # Create region indicator if applicable
    region_suffix = target_region if target_region else None
    
    # Use utils to create filename and save data with GovCloud identifier
    filename = utils.create_export_filename(
        account_name, 
        "s3-buckets", 
        region_suffix, 
        current_date
    )
    
    # Use utils to save DataFrame to Excel
    output_path = utils.save_dataframe_to_excel(df, filename)
    
    if output_path:
        utils.log_success("GovCloud S3 data exported successfully!")
        utils.log_info(f"File location: {output_path}")
        return output_path
    else:
        utils.log_error("Error creating Excel file. Attempting to save as CSV instead.")
        # Fallback to CSV if Excel fails
        return export_to_csv(buckets_info, account_name, target_region)

def export_to_csv(buckets_info, account_name, target_region=None):
    """
    Export bucket information to a CSV file with GovCloud identifier
    
    Args:
        buckets_info (list): List of dictionaries with bucket information
        account_name (str): Name of the AWS account for file naming
        target_region (str): Specific GovCloud region being targeted (or None for all)
        
    Returns:
        str: Path to the created file
    """
    # Create a DataFrame from the bucket information
    df = pd.DataFrame(buckets_info)
    
    # Reorder columns for better readability
    column_order = [
        'Bucket Name', 
        'Region', 
        'Creation Date', 
        'Object Count',
        'Size (MB)',
        'Size Source',
        'Owner'
    ]
    
    # Reorder columns (only include columns that exist in the DataFrame)
    available_columns = [col for col in column_order if col in df.columns]
    df = df[available_columns]
    
    # Format the creation date to be more readable
    if 'Creation Date' in df.columns:
        df['Creation Date'] = df['Creation Date'].dt.strftime('%Y-%m-%d %H:%M:%S')
    
    # Generate filename with current date
    current_date = datetime.datetime.now().strftime("%m.%d.%Y")
    
    # Create region indicator if applicable
    region_suffix = f"-{target_region}" if target_region else ""
    
    # Use utils to get output filepath
    csv_filename = f"{account_name}-govcloud-s3-buckets{region_suffix}-export-{current_date}.csv"
    csv_path = utils.get_output_filepath(csv_filename)
    
    # Write data to CSV
    df.to_csv(csv_path, index=False)
    
    utils.log_success(f"GovCloud S3 data successfully exported to: {csv_path}")
    return str(csv_path)

def main():
    """
    Main function to execute the script
    """
    # Print script title and get account information
    account_id, account_name = print_title()
    
    # Check if required dependencies are installed
    if not check_dependencies():
        return
    
    # Create argument parser
    parser = argparse.ArgumentParser(description='Export AWS GovCloud S3 bucket information')
    parser.add_argument('--format', choices=['xlsx', 'csv'], default='xlsx',
                        help='Output format (xlsx or csv)')
    parser.add_argument('--skip-size', action='store_true',
                        help='Skip retrieving bucket sizes (faster)')
    parser.add_argument('--non-interactive', action='store_true',
                        help='Run in non-interactive mode using environment variables')
    parser.add_argument('--region', type=str, default=None,
                        help='Specific GovCloud region to scan (default: all GovCloud regions)')
    
    # Parse arguments
    args = parser.parse_args()
    
    # Check for non-interactive mode
    if args.non_interactive:
        # Use environment variables for configuration
        region_input = os.environ.get('AWS_REGION', 'all')
    else:
        # Prompt user for GovCloud region selection
        print("\nGovCloud Region Selection:")
        print("Would you like the information for all GovCloud regions or a specific region?")
        print("Available GovCloud regions: us-gov-east-1, us-gov-west-1")
        region_input = input("If all, write \"all\", or specify a GovCloud region name: ").strip().lower()
    
    # Set target_region based on user input or command line argument
    if args.region:
        target_region = args.region if args.region.lower() != 'all' else None
    else:
        target_region = None if region_input.lower() == 'all' else region_input
    
    # Validate region if a specific one was provided
    if target_region:
        if not is_valid_govcloud_region(target_region):
            utils.log_warning(f"'{target_region}' is not a valid GovCloud region.")
            utils.log_info("Valid GovCloud regions: us-gov-east-1, us-gov-west-1")
            utils.log_info("Checking all GovCloud regions instead.")
            target_region = None
    
    # Validate GovCloud environment
    if not utils.is_govcloud_environment():
        proceed = input("\nWarning: Not detected as GovCloud environment. Continue anyway? (y/n): ").lower()
        if proceed != 'y':
            print("Exiting script...")
            sys.exit(0)
    
    utils.log_info("Checking for S3 Storage Lens availability in GovCloud...")
    use_storage_lens = check_storage_lens_availability()
    
    utils.log_info(f"Collecting S3 bucket information" + 
          (f" for GovCloud region: {target_region}" if target_region else " across all GovCloud regions") + 
          "...")
    utils.log_info("This may take some time depending on the number of buckets...")
    
    # Get information about S3 buckets in GovCloud
    buckets_info = get_s3_buckets_info(use_storage_lens=use_storage_lens, target_region=target_region)
    
    # Check if we found any buckets
    if not buckets_info:
        utils.log_warning("No S3 buckets found in GovCloud regions or unable to retrieve bucket information.")
        return
    
    utils.log_success(f"Found {len(buckets_info)} S3 buckets" + 
          (f" in GovCloud region {target_region}." if target_region else " across all GovCloud regions."))
    
    # Export the data to the selected format
    if args.format == 'xlsx':
        output_file = export_to_excel(buckets_info, account_name, target_region)
    else:
        output_file = export_to_csv(buckets_info, account_name, target_region)
    
    if output_file:
        utils.log_govcloud_info(f"Export contains data from GovCloud region(s)")
        utils.log_govcloud_info(f"Total S3 buckets exported: {len(buckets_info)}")
        print("\nScript execution completed successfully.")
    else:
        utils.log_error("Failed to export data. Please check the logs.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
        sys.exit(1)
    except Exception as e:
        utils.log_error("An unexpected error occurred", e)
        sys.exit(1)
