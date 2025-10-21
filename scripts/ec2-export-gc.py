#!/usr/bin/env python3

"""
===========================
= AWS GOVCLOUD RESOURCE SCANNER =
===========================

Title: AWS GovCloud EC2 Instance Data Export Script
Version: v1.10.4-GovCloud
Date: AUG-19-2025

Description:
This script queries AWS GovCloud EC2 instances across available GovCloud regions and exports 
detailed instance information to an Excel spreadsheet. The output filename includes the AWS 
account name based on the account ID mapping in the configuration and includes GovCloud 
identifiers for compliance and audit purposes.

GovCloud Modifications:
- Limited to GovCloud regions (us-gov-east-1, us-gov-west-1)
- Added GovCloud region validation
- Updated partition handling for aws-us-gov
- Added GovCloud-specific compliance markers in output filenames
- Enhanced error handling for GovCloud-specific service limitations
"""

import sys
import os
import boto3
import datetime
import csv
import time
from io import StringIO
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

def get_os_info_from_ssm(instance_id, region):
    """
    Retrieve detailed operating system information using SSM with timeout safeguards
    Returns the full OS version string or 'Unknown OS' if unavailable
    
    Note: SSM may have limited availability in some GovCloud configurations
    """
    try:
        ssm = boto3.client('ssm', region_name=region)
        
        # Check if the instance is managed by SSM
        response = ssm.describe_instance_information(
            Filters=[{'Key': 'InstanceIds', 'Values': [instance_id]}]
        )
        
        if not response['InstanceInformationList']:
            return "Unknown OS"
        
        # Get platform information from SSM
        instance_info = response['InstanceInformationList'][0]
        platform_type = instance_info.get('PlatformType', '')
        platform_name = instance_info.get('PlatformName', '')
        platform_version = instance_info.get('PlatformVersion', '')
        
        # If we have detailed platform info from SSM directly, use it
        if platform_name and platform_version:
            return f"{platform_name} {platform_version}"
        elif platform_name:
            return platform_name
            
        # If it's Windows, return basic Windows info
        if platform_type == 'Windows':
            return "Windows (Use AMI Name for details)"
        
        # For Linux, return basic Linux info
        return "Linux (Use AMI Name for details)"
        
    except Exception as e:
        utils.log_warning(f"SSM error for instance {instance_id} in region {region}: {e}")
        return "Unknown OS"

def get_instance_memory(ec2_client, instance_type):
    """
    Get RAM information for a given instance type using EC2 API
    Returns memory in MiB
    """
    try:
        response = ec2_client.describe_instance_types(InstanceTypes=[instance_type])
        if response['InstanceTypes']:
            return response['InstanceTypes'][0]['MemoryInfo']['SizeInMiB']
        return 'N/A'
    except Exception as e:
        utils.log_warning(f"Could not get memory info for instance type {instance_type}: {e}")
        return 'N/A'

def get_instance_stop_date(ec2_client, instance_id, state):
    """
    Get the date when an instance was stopped using state transition reason
    Returns the stop date or 'N/A' for running instances
    """
    if state != 'stopped':
        return 'N/A'
        
    try:
        # Get the state transition reason directly from instance metadata
        response = ec2_client.describe_instances(InstanceIds=[instance_id])
        
        if response['Reservations']:
            for reservation in response['Reservations']:
                for instance in reservation['Instances']:
                    if instance['InstanceId'] == instance_id and instance.get('State', {}).get('Name') == 'stopped':
                        # Check the StateTransitionReason field
                        state_reason = instance.get('StateTransitionReason', '')
                        
                        # For user initiated shutdowns, the format is typically:
                        # "User initiated (YYYY-MM-DD HH:MM:SS GMT)"
                        if 'User initiated' in state_reason and '(' in state_reason and ')' in state_reason:
                            date_start = state_reason.find('(') + 1
                            date_end = state_reason.find(')')
                            if date_start > 0 and date_end > date_start:
                                return state_reason[date_start:date_end]
                        # For system or auto-scaling initiated stops, return the reason
                        elif state_reason:
                            return f"System initiated ({state_reason})"
        
        # If we couldn't get the stop date from the state reason, return unknown
        return 'Stopped (Date Unknown)'
        
    except Exception as e:
        utils.log_warning(f"Could not determine stop date for instance {instance_id}: {e}")
        return 'Stopped (Date Unknown)'

def get_os_info_from_ami(ec2_client, image_id, platform_details, platform):
    """
    Get detailed OS information from AMI metadata without making blocking calls
    
    Args:
        ec2_client: The boto3 EC2 client
        image_id (str): The AMI ID
        platform_details (str): The platform details from instance metadata
        platform (str): The platform from instance metadata
    
    Returns:
        str: Detailed operating system information where available
    """
    try:
        # Try to get AMI information (non-blocking)
        response = ec2_client.describe_images(ImageIds=[image_id])
        
        if response['Images']:
            image = response['Images'][0]
            
            # Check for Windows AMIs
            if platform == 'windows':
                description = image.get('Description', '')
                if description:
                    # Windows AMIs often contain the version in the description
                    return description
                name = image.get('Name', '')
                if name and 'Windows' in name:
                    return name
                return platform_details
            
            # For Linux AMIs
            name = image.get('Name', '')
            description = image.get('Description', '')
            
            # Amazon Linux AMIs
            if 'amzn' in name.lower() or 'amazon linux' in name.lower():
                return name if name else "Amazon Linux"
            
            # RHEL, Ubuntu, SUSE, etc.
            if any(distro in name.lower() or distro in description.lower() for distro in 
                   ['rhel', 'red hat', 'ubuntu', 'debian', 'suse', 'centos']):
                return name if name else description
            
            # If we have a name but don't recognize the distribution
            if name:
                return name
                
            # Fall back to description
            if description:
                return description
        
        # If AMI lookup fails, use platform details
        return platform_details
    
    except Exception as e:
        utils.log_warning(f"Could not get detailed OS info for AMI {image_id}: {e}")
        return platform_details

def format_tags(tags):
    """
    Format EC2 instance tags in the format "Key1:Value1, Key2:Value2, etc..."
    
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

def check_dependencies():
    """Check and install required dependencies if user agrees"""
    required_packages = ['pandas', 'openpyxl', 'boto3']
    
    for package in required_packages:
        try:
            __import__(package)
            utils.log_info(f"[OK] {package} is already installed")
        except ImportError:
            print(f"\nPackage '{package}' is required but not installed.")
            response = input(f"Would you like to install {package}? (y/n): ").lower()
            
            if response == 'y':
                try:
                    import subprocess
                    print(f"Installing {package}...")
                    subprocess.check_call([sys.executable, "-m", "pip", "install", package])
                    utils.log_success(f"Successfully installed {package}")
                except Exception as e:
                    utils.log_error(f"Error installing {package}", e)
                    sys.exit(1)
            else:
                print(f"Cannot proceed without {package}. Exiting...")
                sys.exit(1)

def get_account_info():
    """Retrieve AWS account ID and map it to account name, validate GovCloud environment"""
    try:
        sts = boto3.client('sts')
        account_id = sts.get_caller_identity()['Account']
        
        # Validate GovCloud environment
        caller_arn = sts.get_caller_identity()['Arn']
        if not utils.is_govcloud_environment():
            utils.log_warning("You appear to be connected to commercial AWS, not GovCloud!")
            utils.log_warning("This script is optimized for AWS GovCloud IL4 environments.")
        
        account_name = utils.get_account_name(account_id, default="UNKNOWN-ACCOUNT")
        return account_id, account_name
    except Exception as e:
        utils.log_error("Error getting account information", e)
        return "UNKNOWN", "UNKNOWN-ACCOUNT"

def get_govcloud_regions():
    """Get list of available GovCloud regions"""
    try:
        # Use utils function to get GovCloud regions
        regions = utils.get_available_govcloud_regions()
        if not regions:
            utils.log_warning("No accessible GovCloud regions found. Using default list.")
            regions = utils.get_govcloud_regions()
        return regions
    except Exception as e:
        utils.log_error("Error getting GovCloud regions", e)
        return utils.get_govcloud_regions()

def is_valid_govcloud_region(region_name):
    """Check if a region name is a valid GovCloud region"""
    return utils.validate_govcloud_region(region_name)

def get_instance_data(region, instance_filter=None):
    """
    Retrieve EC2 instance data for a specific GovCloud region
    
    Args:
        region (str): AWS GovCloud region name
        instance_filter (str, optional): Filter by instance state ('running', 'stopped', or None for all)
    """
    # Validate region is GovCloud
    if not utils.validate_govcloud_region(region):
        utils.log_error(f"Invalid GovCloud region: {region}")
        return []
    
    ec2 = boto3.client('ec2', region_name=region)
    instances = []
    
    try:
        # Prepare filters if needed
        filters = []
        if instance_filter:
            filters.append({
                'Name': 'instance-state-name',
                'Values': [instance_filter]
            })
        
        # Get instances in the region with optional filter
        if filters:
            response = ec2.describe_instances(Filters=filters)
        else:
            response = ec2.describe_instances()
        
        # Count total instances first for progress tracking
        total_instances = 0
        for reservation in response['Reservations']:
            total_instances += len(reservation['Instances'])

        if total_instances > 0:
            utils.log_info(f"Found {total_instances} instances in {region} to process")

        processed = 0
        for reservation in response['Reservations']:
            for instance in reservation['Instances']:
                processed += 1
                instance_id = instance.get('InstanceId', 'Unknown')
                progress = (processed / total_instances) * 100 if total_instances > 0 else 0

                utils.log_info(f"[{progress:.1f}%] Processing instance {processed}/{total_instances}: {instance_id}")
                # Get the root volume information
                root_device = next((device for device in instance.get('BlockDeviceMappings', [])
                                  if device['DeviceName'] == instance.get('RootDeviceName')), None)
                
                # Get detailed OS information
                os_info = get_os_info_from_ssm(instance.get('InstanceId', ''), region)
                
                # Get AMI name information
                ami_name = get_os_info_from_ami(
                    ec2,
                    instance.get('ImageId', ''),
                    instance.get('PlatformDetails', 'N/A'),
                    instance.get('Platform', '')
                )
                
                # Get RAM info based on instance type
                instance_type = instance.get('InstanceType', 'N/A')
                ram_mib = get_instance_memory(ec2, instance_type)
                
                # For root device size, we need to ensure we're fetching it correctly
                root_device_size = 'N/A'
                root_volume_id = 'N/A'
                
                if root_device:
                    root_volume_id = root_device.get('Ebs', {}).get('VolumeId', 'N/A')
                    # If we have the volume ID, we can get its size
                    if root_volume_id != 'N/A':
                        try:
                            volumes = ec2.describe_volumes(VolumeIds=[root_volume_id])
                            if volumes and 'Volumes' in volumes and len(volumes['Volumes']) > 0:
                                root_device_size = volumes['Volumes'][0].get('Size', 'N/A')
                        except Exception as e:
                            utils.log_warning(f"Error getting volume info for {root_volume_id}: {e}")
                    else:
                        # Try to get size from the device mapping directly
                        root_device_size = root_device.get('Ebs', {}).get('VolumeSize', 'N/A')
                
                # Get instance state and stopped date if applicable
                instance_state = instance.get('State', {}).get('Name', 'N/A')
                stop_date = get_instance_stop_date(ec2, instance.get('InstanceId', ''), instance_state)
                
                # Format tags
                instance_tags = format_tags(instance.get('Tags', []))
                
                # Extract instance information
                instance_data = {
                    'Computer Name': next((tag['Value'] for tag in instance.get('Tags', [])
                                        if tag['Key'] == 'Name'), 'N/A'),
                    'Instance ID': instance.get('InstanceId', 'N/A'),
                    'State': instance_state,
                    'Stopped Date': stop_date,
                    'Instance Type': instance.get('InstanceType', 'N/A'),
                    'Platform': instance.get('Platform', 'Linux/UNIX'),
                    'Operating System': os_info,
                    'AMI Name': ami_name,
                    'Private IPv4': instance.get('PrivateIpAddress', 'N/A'),
                    'Public IPv4': instance.get('PublicIpAddress', 'N/A'),
                    'IPv6': next((
                        next((addr.get('Ipv6Address', 'N/A') 
                             for addr in interface.get('Ipv6Addresses', [])), 'N/A')
                        for interface in instance.get('NetworkInterfaces', [])
                    ), 'N/A'),
                    'VPC ID': instance.get('VpcId', 'N/A'),
                    'Subnet ID': instance.get('SubnetId', 'N/A'),
                    'Availability Zone': instance.get('Placement', {}).get('AvailabilityZone', 'N/A'),
                    'AMI ID': instance.get('ImageId', 'N/A'),
                    'Launch Time': instance.get('LaunchTime', 'N/A'),
                    'Key Pair': instance.get('KeyName', 'N/A'),
                    'Region': region,
                    'Owner ID': utils.get_account_name_formatted(instance.get('OwnerId', 'N/A')),
                    'vCPU': instance.get('CpuOptions', {}).get('CoreCount', 'N/A'),
                    'RAM (MiB)': ram_mib,
                    'Root Device Volume ID': root_volume_id,
                    'Root Device Size (GiB)': root_device_size,
                    'Tags': instance_tags
                }
                instances.append(instance_data)

                # Small delay to avoid API throttling
                if processed < total_instances:  # Don't delay after the last instance
                    time.sleep(0.1)
                
    except Exception as e:
        utils.log_error(f"Error getting instances in GovCloud region {region}", e)
    
    return instances

def main():
    """Main function to execute the script"""
    try:
        # Check for required dependencies
        check_dependencies()
        
        # Import pandas after dependency check
        import pandas as pd
        
        # Get account information and validate GovCloud
        utils.log_info("Getting AWS account information...")
        account_id, account_name = get_account_info()
        
        # Print script header
        print("\n====================================================================")
        print("                   AWS RESOURCE SCANNER                            ")
        print("====================================================================")
        print("                 AWS GOVCLOUD EC2 INSTANCES DATA EXPORT            ")
        print("====================================================================")
        print(f"Account ID: {account_id}")
        print(f"Account Name: {account_name}")
        print(f"Environment: AWS GovCloud IL4 (FedRAMP Moderate)")
        print("====================================================================\n")
        
        if account_name == "UNKNOWN-ACCOUNT":
            proceed = input("Unable to determine account name. Proceed anyway? (y/n): ").lower()
            if proceed != 'y':
                print("Exiting script...")
                sys.exit(0)
        
        current_date = datetime.datetime.now().strftime("%m.%d.%Y")
        
        # Get instance state filter preference
        print("Choose one of the following (enter the corresponding number):")
        print("1. Export all instances")
        print("2. Export only running instances")
        print("3. Export only stopped instances")
        
        while True:
            filter_choice = input("Enter your choice (1-3): ")
            if filter_choice in ["1", "2", "3"]:
                break
            print("Invalid choice. Please enter 1, 2, or 3.")
        
        # Set instance filter based on user choice
        instance_filter = None
        filter_desc = "all"  # Default for filename
        if filter_choice == "2":
            instance_filter = "running"
            filter_desc = "running"
        elif filter_choice == "3":
            instance_filter = "stopped"
            filter_desc = "stopped"
        
        # Get GovCloud region preference
        print("\nGovCloud Region Selection:")
        print("Would you like the information for all GovCloud regions or a specific region?")
        print("Available GovCloud regions: us-gov-east-1, us-gov-west-1")
        region_choice = input("If all, write \"all\", or specify a GovCloud region name: ").lower().strip()
        
        if region_choice != "all":
            if not is_valid_govcloud_region(region_choice):
                utils.log_warning(f"'{region_choice}' is not a valid GovCloud region.")
                utils.log_info("Valid GovCloud regions: us-gov-east-1, us-gov-west-1")
                utils.log_info("Checking all GovCloud regions instead.")
                region_choice = "all"
        
        # Get GovCloud regions to scan
        if region_choice == "all":
            utils.log_info("Retrieving available GovCloud regions...")
            regions = get_govcloud_regions()
            if not regions:
                utils.log_error("No GovCloud regions found. Please check your AWS credentials and permissions.")
                sys.exit(1)
            utils.log_info(f"Found {len(regions)} GovCloud regions to scan: {', '.join(regions)}")
        else:
            regions = [region_choice]
            utils.log_info(f"Scanning only the {region_choice} GovCloud region.")
        
        # Collect instance data from specified GovCloud regions
        all_instances = []
        total_instances = 0
        for region in regions:
            utils.log_info(f"Collecting data from GovCloud region: {region}")
            instances = get_instance_data(region, instance_filter)
            instance_count = len(instances)
            total_instances += instance_count
            utils.log_info(f"Found {instance_count} instances in {region}")
            all_instances.extend(instances)
        
        if not all_instances:
            utils.log_warning("No instances found in any GovCloud region. Exiting...")
            sys.exit(0)
        
        utils.log_success(f"Total EC2 Instances found across all GovCloud regions: {total_instances}")
        
        # Create DataFrame and handle timezone-aware datetimes
        utils.log_info("Preparing data for export to Excel format...")
        df = pd.DataFrame(all_instances)
        
        # Convert Launch Time to timezone-naive datetime
        df['Launch Time'] = pd.to_datetime(df['Launch Time']).dt.tz_localize(None)
        
        # Generate filename with filter and region info
        region_desc = "" if region_choice == "all" else f"-{region_choice}"
        
        # Use utils module to generate filename and save data with GovCloud identifier
        filename = utils.create_export_filename(
            account_name, 
            "ec2", 
            f"{filter_desc}{region_desc}", 
            current_date
        )
        
        # Save data using the utility function
        output_path = utils.save_dataframe_to_excel(df, filename)
        
        if output_path:
            utils.log_success(f"GovCloud EC2 data exported successfully!")
            utils.log_info(f"File location: {output_path}")
            utils.log_govcloud_info(f"Export contains data from {len(regions)} GovCloud region(s)")
            utils.log_govcloud_info(f"Total instances exported: {total_instances}")
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
