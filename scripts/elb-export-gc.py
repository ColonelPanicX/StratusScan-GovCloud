#!/usr/bin/env python3

"""
===========================
= AWS GOVCLOUD RESOURCE SCANNER =
===========================

Title: AWS GovCloud Elastic Load Balancer Data Export
Version: v1.1.0-GovCloud
Date: AUG-19-2025

Description:
This script queries for Load Balancers across available GovCloud regions or a specific 
GovCloud region and exports the list to a single Excel spreadsheet. Optimized for 
AWS GovCloud IL4 (FedRAMP Moderate) environment.

GovCloud Modifications:
- Limited to GovCloud regions (us-gov-east-1, us-gov-west-1)
- Added GovCloud region validation
- Updated partition handling for aws-us-gov
- Added GovCloud-specific compliance markers in output filenames
- Enhanced error handling for GovCloud-specific service limitations
"""

import boto3
import pandas as pd
import datetime
import os
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

def print_title_screen():
    """
    Prints a formatted title screen with script information and validates GovCloud environment
    
    Returns:
        str: The account name
    """
    # Get the AWS account ID using STS
    try:
        sts_client = boto3.client('sts')
        account_id = sts_client.get_caller_identity()['Account']
        
        # Validate GovCloud environment
        caller_arn = sts_client.get_caller_identity()['Arn']
        if not utils.is_govcloud_environment():
            utils.log_warning("You appear to be connected to commercial AWS, not GovCloud!")
            utils.log_warning("This script is optimized for AWS GovCloud IL4 environments.")
        
        # Get the corresponding account name from utils module
        account_name = utils.get_account_name(account_id, default="UNKNOWN-ACCOUNT")
    except Exception as e:
        utils.log_error("Unable to determine AWS account ID", e)
        account_id = "UNKNOWN"
        account_name = "UNKNOWN-ACCOUNT"
    
    # Print the title screen with account information
    print("====================================================================")
    print("                   AWS RESOURCE SCANNER                            ")    
    print("====================================================================")
    print("AWS GOVCLOUD ELB INVENTORY EXPORT SCRIPT")
    print("====================================================================")
    print("Version: v1.1.0-GovCloud                    Date: AUG-19-2025")
    print("Environment: AWS GovCloud IL4 (FedRAMP Moderate)")
    print("====================================================================")
    print(f"Account ID: {account_id}")
    print(f"Account Name: {account_name}")
    print("====================================================================")
    
    return account_name

def check_dependencies():
    """
    Checks if required dependencies are installed and offers to install them
    
    Returns:
        bool: True if all dependencies are installed or successfully installed,
              False otherwise
    """
    required_packages = ['pandas', 'openpyxl', 'boto3']
    missing_packages = []
    
    # Check which required packages are missing
    for package in required_packages:
        try:
            __import__(package)
            utils.log_info(f"[OK] {package} is already installed")
        except ImportError:
            missing_packages.append(package)
    
    # If there are missing packages, prompt the user to install them
    if missing_packages:
        utils.log_warning(f"Missing dependencies: {', '.join(missing_packages)}")
        install_choice = input("Do you want to install the missing dependencies? (y/n): ").lower().strip()
        
        if install_choice == 'y':
            import subprocess
            for package in missing_packages:
                utils.log_info(f"Installing {package}...")
                try:
                    subprocess.check_call([sys.executable, "-m", "pip", "install", package])
                    utils.log_success(f"{package} installed successfully.")
                except Exception as e:
                    utils.log_error(f"Error installing {package}", e)
                    print("Please install it manually with: pip install " + package)
                    return False
            return True
        else:
            print("Script cannot continue without required dependencies. Exiting.")
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
        region_name (str): The region name to check
        
    Returns:
        bool: True if valid, False otherwise
    """
    return utils.validate_govcloud_region(region_name)

def get_security_group_names(security_group_ids, region):
    """
    Get security group names for the given IDs
    
    Args:
        security_group_ids (list): List of security group IDs
        region (str): AWS GovCloud region
        
    Returns:
        dict: Mapping of security group IDs to names
    """
    if not security_group_ids:
        return {}
    
    # Validate region is GovCloud
    if not utils.validate_govcloud_region(region):
        utils.log_error(f"Invalid GovCloud region: {region}")
        return {}
        
    ec2 = boto3.client('ec2', region_name=region)
    sg_mapping = {}
    
    try:
        # Fetch security group information
        response = ec2.describe_security_groups(GroupIds=security_group_ids)
        
        # Create a mapping of security group IDs to names
        for sg in response['SecurityGroups']:
            sg_mapping[sg['GroupId']] = sg['GroupName']
            
    except Exception as e:
        utils.log_warning(f"Unable to fetch security group names in {region}: {str(e)}")
    
    return sg_mapping

def get_classic_load_balancers(region):
    """
    Get information about Classic Load Balancers in the specified GovCloud region
    
    Args:
        region (str): AWS GovCloud region
        
    Returns:
        list: List of dictionaries containing Classic Load Balancer information
    """
    # Validate region is GovCloud
    if not utils.validate_govcloud_region(region):
        utils.log_error(f"Invalid GovCloud region: {region}")
        return []
    
    elb_data = []
    
    try:
        # Create an ELB client for the specified region
        elb = boto3.client('elb', region_name=region)
        
        # Describe all Classic Load Balancers
        response = elb.describe_load_balancers()
        
        for lb in response.get('LoadBalancerDescriptions', []):
            # Get security group names for the security group IDs
            sg_ids = lb.get('SecurityGroups', [])
            sg_mapping = get_security_group_names(sg_ids, region)
            
            # Format security groups as "sg-name (sg-id), ..."
            security_groups = []
            for sg_id in sg_ids:
                sg_name = sg_mapping.get(sg_id, "Unknown")
                security_groups.append(f"{sg_name} ({sg_id})")
            
            # Format availability zones as "subnet-id (az), ..."
            availability_zones = []
            for az in lb.get('AvailabilityZones', []):
                availability_zones.append(f"{az}")
            
            # Add subnets if available (VPC Classic ELB)
            for subnet_id in lb.get('Subnets', []):
                # For VPC Classic ELBs, we need to get the AZ for each subnet
                try:
                    ec2 = boto3.client('ec2', region_name=region)
                    subnet_response = ec2.describe_subnets(SubnetIds=[subnet_id])
                    subnet_az = subnet_response['Subnets'][0]['AvailabilityZone']
                    availability_zones.append(f"{subnet_id} ({subnet_az})")
                except Exception as e:
                    utils.log_warning(f"Could not get AZ for subnet {subnet_id}: {e}")
                    availability_zones.append(f"{subnet_id} (Unknown AZ)")
            
            # Get creation time
            created_time = lb.get('CreatedTime', datetime.datetime.now())
            
            # Get owner information
            owner_id = lb.get('OwnerId', 'N/A')
            owner_name = utils.get_account_name_formatted(owner_id)
            
            # Add load balancer data to the list
            elb_data.append({
                'Region': region,
                'Name': lb.get('LoadBalancerName', ''),
                'DNS Name': lb.get('DNSName', ''),
                'VPC ID': lb.get('VPCId', 'N/A'),
                'Availability Zones': ', '.join(availability_zones),
                'Type': 'Classic',
                'Date Created': created_time.strftime('%Y-%m-%d'),
                'Security Groups': ', '.join(security_groups) if security_groups else 'N/A',
                'Owner': owner_name
            })
            
    except Exception as e:
        utils.log_warning(f"Unable to fetch Classic Load Balancers in GovCloud region {region}: {str(e)}")
    
    return elb_data

def get_application_network_load_balancers(region):
    """
    Get information about Application and Network Load Balancers in the specified GovCloud region
    
    Args:
        region (str): AWS GovCloud region
        
    Returns:
        list: List of dictionaries containing ALB/NLB information
    """
    # Validate region is GovCloud
    if not utils.validate_govcloud_region(region):
        utils.log_error(f"Invalid GovCloud region: {region}")
        return []
    
    elb_data = []
    
    try:
        # Create an ELBv2 client for the specified region
        elbv2 = boto3.client('elbv2', region_name=region)
        
        # Describe all ALBs and NLBs
        response = elbv2.describe_load_balancers()
        
        for lb in response.get('LoadBalancers', []):
            # Get load balancer type
            lb_type = lb.get('Type', 'Unknown')
            
            # Get security group names for ALBs (NLBs don't have security groups)
            sg_ids = lb.get('SecurityGroups', [])
            security_groups = []
            
            if sg_ids:
                sg_mapping = get_security_group_names(sg_ids, region)
                for sg_id in sg_ids:
                    sg_name = sg_mapping.get(sg_id, "Unknown")
                    security_groups.append(f"{sg_name} ({sg_id})")
            
            # Get subnet information
            availability_zones = []
            for az_info in lb.get('AvailabilityZones', []):
                subnet_id = az_info.get('SubnetId', '')
                zone_name = az_info.get('ZoneName', '')
                availability_zones.append(f"{subnet_id} ({zone_name})")
            
            # Get creation time
            created_time = lb.get('CreatedTime', datetime.datetime.now())
            
            # Get owner information from the ARN
            lb_arn = lb.get('LoadBalancerArn', '')
            if lb_arn:
                # Parse owner from ARN
                try:
                    arn_parts = lb_arn.split(':')
                    if len(arn_parts) >= 5:
                        owner_id = arn_parts[4]
                        owner_name = utils.get_account_name_formatted(owner_id)
                    else:
                        owner_name = 'N/A'
                except Exception:
                    owner_name = 'N/A'
            else:
                owner_name = 'N/A'
            
            # Add load balancer data to the list
            elb_data.append({
                'Region': region,
                'Name': lb.get('LoadBalancerName', ''),
                'DNS Name': lb.get('DNSName', ''),
                'VPC ID': lb.get('VpcId', 'N/A'),
                'Availability Zones': ', '.join(availability_zones),
                'Type': lb_type,
                'Date Created': created_time.strftime('%Y-%m-%d'),
                'Security Groups': ', '.join(security_groups) if security_groups else 'N/A',
                'Owner': owner_name
            })
            
    except Exception as e:
        utils.log_warning(f"Unable to fetch ALBs/NLBs in GovCloud region {region}: {str(e)}")
    
    return elb_data

def main():
    """
    Main function to run the script
    """
    # Print the title screen and get the account name
    account_name = print_title_screen()
    
    # Check for required dependencies
    if not check_dependencies():
        sys.exit(1)
    
    # Get GovCloud region preference from user
    print("\nGovCloud Region Selection:")
    print("Would you like the information for all GovCloud regions or a specific region?")
    print("Available GovCloud regions: us-gov-east-1, us-gov-west-1")
    region_choice = input("If all, write \"all\", or specify a GovCloud region name: ").lower().strip()
    
    # Determine regions to scan
    if region_choice == "all":
        utils.log_info("Retrieving all available GovCloud regions...")
        regions = get_govcloud_regions()
        region_suffix = ""
        if not regions:
            utils.log_error("No GovCloud regions found. Please check your AWS credentials and permissions.")
            sys.exit(1)
        utils.log_info(f"Found {len(regions)} GovCloud regions to scan: {', '.join(regions)}")
    else:
        if not is_valid_govcloud_region(region_choice):
            utils.log_warning(f"'{region_choice}' is not a valid GovCloud region.")
            utils.log_info("Valid GovCloud regions: us-gov-east-1, us-gov-west-1")
            utils.log_info("Checking all GovCloud regions instead.")
            regions = get_govcloud_regions()
            region_suffix = ""
        else:
            regions = [region_choice]
            region_suffix = f"-{region_choice}"
            utils.log_info(f"Scanning only the {region_choice} GovCloud region.")
    
    # Initialize a list to store all ELB data
    all_elb_data = []
    total_classic_elbs = 0
    total_elbv2s = 0
    
    # Iterate through each GovCloud region
    for region in regions:
        utils.log_info(f"Processing GovCloud region: {region}")
        
        # Get Classic Load Balancers
        utils.log_info(f"  Fetching Classic Load Balancers...")
        classic_elbs = get_classic_load_balancers(region)
        classic_count = len(classic_elbs)
        total_classic_elbs += classic_count
        utils.log_info(f"  Found {classic_count} Classic Load Balancers.")
        all_elb_data.extend(classic_elbs)
        
        # Get Application and Network Load Balancers
        utils.log_info(f"  Fetching Application and Network Load Balancers...")
        elbv2s = get_application_network_load_balancers(region)
        elbv2_count = len(elbv2s)
        total_elbv2s += elbv2_count
        utils.log_info(f"  Found {elbv2_count} Application and Network Load Balancers.")
        all_elb_data.extend(elbv2s)
    
    # If no ELBs found, exit
    if not all_elb_data:
        utils.log_warning("No Elastic Load Balancers found in any GovCloud region.")
        return
    
    # Convert to DataFrame
    df = pd.DataFrame(all_elb_data)
    
    # Sort by Region, Type, and Name
    df = df.sort_values(by=['Region', 'Type', 'Name'])
    
    # Generate filename with current date
    current_date = datetime.datetime.now().strftime('%m.%d.%Y')
    
    # Use utils to create filename with GovCloud identifier
    filename = utils.create_export_filename(
        account_name, 
        "elb", 
        region_suffix, 
        current_date
    )
    
    # Export to Excel using utils
    output_path = utils.save_dataframe_to_excel(df, filename)
    
    if output_path:
        utils.log_success("GovCloud ELB data exported successfully!")
        utils.log_info(f"File location: {output_path}")
        utils.log_govcloud_info(f"Export contains data from {len(regions)} GovCloud region(s)")
        utils.log_info(f"Total Classic ELBs: {total_classic_elbs}")
        utils.log_info(f"Total ALB/NLB: {total_elbv2s}")
        utils.log_info(f"Total Load Balancers: {len(all_elb_data)}")
        print("\nScript execution completed.")
    else:
        utils.log_error("Failed to save the Excel file.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
        sys.exit(1)
    except Exception as e:
        utils.log_error("An unexpected error occurred", e)
        sys.exit(1)