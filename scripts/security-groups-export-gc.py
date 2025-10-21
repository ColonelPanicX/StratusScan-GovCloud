#!/usr/bin/env python3

"""
===========================
= AWS GOVCLOUD RESOURCE SCANNER =
===========================

Title: AWS GovCloud Security Groups Export Script
Version: v1.4.0-GovCloud
Date: AUG-26-2025

Description:
This script exports security group information from AWS GovCloud regions including group name, ID, 
VPC, inbound rules, outbound rules, and associated resources. Each security group rule is listed 
on its own line for better analysis and filtering. The data is exported to an Excel file with 
GovCloud-specific naming convention and compliance markers.

GovCloud Modifications:
- Limited to GovCloud regions (us-gov-east-1, us-gov-west-1)
- Added GovCloud region validation
- Updated partition handling for aws-us-gov
- Added GovCloud-specific compliance markers in output filenames
- Enhanced error handling for GovCloud-specific service limitations
"""

import boto3
import sys
import os
import datetime
import time
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
    Check and install dependencies if necessary.
    
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
        utils.log_warning(f"Missing required packages: {', '.join(missing_packages)}")
        install = input("Would you like to install them now? (y/n): ").lower()
        
        if install == 'y':
            import subprocess
            for package in missing_packages:
                try:
                    utils.log_info(f"Installing {package}...")
                    subprocess.check_call([sys.executable, "-m", "pip", "install", package])
                    utils.log_success(f"Successfully installed {package}")
                except subprocess.CalledProcessError as e:
                    utils.log_error(f"Failed to install {package}", e)
                    print("Please install the package manually and try again.")
                    return False
            return True
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
        # Get the account ID
        sts = boto3.client('sts')
        account_id = sts.get_caller_identity()['Account']
        
        # Validate GovCloud environment
        caller_arn = sts.get_caller_identity()['Arn']
        if not utils.is_govcloud_environment():
            utils.log_warning("You appear to be connected to commercial AWS, not GovCloud!")
            utils.log_warning("This script is optimized for AWS GovCloud IL4 environments.")
        
        # Map the account ID to a name using the utils module
        account_name = utils.get_account_name(account_id, default=f"UNKNOWN-{account_id}")
        
        return account_id, account_name
    except Exception as e:
        utils.log_error("Error getting account information", e)
        return "Unknown", "Unknown-Account"

def print_title():
    """
    Print the script title and account information.
    
    Returns:
        tuple: (account_id, account_name)
    """
    print("====================================================================")
    print("                   AWS RESOURCE SCANNER                            ")
    print("====================================================================")
    print("AWS GOVCLOUD SECURITY GROUPS EXPORT")
    print("====================================================================")
    print("Version: v1.4.0-GovCloud                       Date: AUG-26-2025")
    print("Environment: AWS GovCloud IL4 (FedRAMP Moderate)")
    print("====================================================================")
    
    # Get account information
    account_id, account_name = get_account_info()
    print(f"Account ID: {account_id}")
    print(f"Account Name: {account_name}")
    print("====================================================================")
    
    return account_id, account_name

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

def get_vpc_name(ec2_client, vpc_id):
    """
    Get the name of a VPC from its ID.
    
    Args:
        ec2_client: The boto3 EC2 client
        vpc_id: The VPC ID
        
    Returns:
        str: The VPC name and ID or default value
    """
    if not vpc_id:
        return "No VPC (EC2-Classic)"
    
    try:
        response = ec2_client.describe_vpcs(VpcIds=[vpc_id])
        
        if not response['Vpcs']:
            return vpc_id  # Return the ID if no VPC found
        
        # Look for the Name tag
        for tag in response['Vpcs'][0].get('Tags', []):
            if tag['Key'] == 'Name':
                return f"{tag['Value']} ({vpc_id})"
        
        # If no Name tag, just return the ID
        return vpc_id
    except Exception as e:
        return vpc_id  # Return the ID on error

def format_ip_range(ip_range, protocol, from_port, to_port, is_inbound=True):
    """
    Format IP range rule details.
    
    Args:
        ip_range: The IP range dictionary
        protocol: The protocol
        from_port: The from port
        to_port: The to port
        is_inbound: Whether this is an inbound rule
        
    Returns:
        str: Formatted rule string
    """
    if protocol == '-1':
        protocol = 'All'
    
    # Format port range
    port_range = ''
    if from_port is not None and to_port is not None:
        if from_port == to_port:
            port_range = str(from_port)
        else:
            port_range = f"{from_port}-{to_port}"
    else:
        port_range = 'All'
    
    # Format CIDR
    cidr = ip_range.get('CidrIp', ip_range.get('CidrIpv6', 'Unknown'))
    
    if is_inbound:
        return f"{cidr} → {protocol}:{port_range}"
    else:
        return f"{protocol}:{port_range} → {cidr}"

def format_security_group_reference(sg_ref, protocol, from_port, to_port, is_inbound=True):
    """
    Format security group reference rule details.
    
    Args:
        sg_ref: The security group reference dictionary
        protocol: The protocol
        from_port: The from port
        to_port: The to port
        is_inbound: Whether this is an inbound rule
        
    Returns:
        str: Formatted rule string
    """
    if protocol == '-1':
        protocol = 'All'
    
    # Format port range
    port_range = ''
    if from_port is not None and to_port is not None:
        if from_port == to_port:
            port_range = str(from_port)
        else:
            port_range = f"{from_port}-{to_port}"
    else:
        port_range = 'All'
    
    # Format security group reference
    sg_identifier = ""
    if 'GroupId' in sg_ref:
        sg_identifier = f"sg:{sg_ref['GroupId']}"
    elif 'GroupName' in sg_ref:
        sg_identifier = f"sg:{sg_ref['GroupName']}"
    else:
        sg_identifier = "sg:Unknown"
    
    if is_inbound:
        return f"{sg_identifier} → {protocol}:{port_range}"
    else:
        return f"{protocol}:{port_range} → {sg_identifier}"

def get_security_group_resources(ec2_client, sg_id):
    """
    Find EC2 instances, RDS instances, and other resources using this security group.
    
    Args:
        ec2_client: The boto3 EC2 client
        sg_id: The security group ID
        
    Returns:
        list: List of resources using this security group
    """
    resources = []
    
    # Check EC2 instances
    try:
        response = ec2_client.describe_instances(
            Filters=[{'Name': 'instance.group-id', 'Values': [sg_id]}]
        )
        
        for reservation in response.get('Reservations', []):
            for instance in reservation.get('Instances', []):
                # Get instance name from tags
                instance_name = 'Unnamed'
                for tag in instance.get('Tags', []):
                    if tag['Key'] == 'Name':
                        instance_name = tag['Value']
                        break
                
                resources.append(f"EC2:{instance_name} ({instance['InstanceId']})")
    except Exception as e:
        pass  # Silently continue if we can't get EC2 instances
    
    # Try to check RDS instances
    try:
        rds_client = boto3.client('rds', region_name=ec2_client.meta.region_name)
        response = rds_client.describe_db_instances()
        
        for instance in response.get('DBInstances', []):
            for sg in instance.get('VpcSecurityGroups', []):
                if sg.get('VpcSecurityGroupId') == sg_id:
                    resources.append(f"RDS:{instance['DBInstanceIdentifier']}")
                    break
    except Exception as e:
        pass  # Silently continue if we can't get RDS instances
    
    # Try to check ELBs (Classic Load Balancers)
    try:
        elb_client = boto3.client('elb', region_name=ec2_client.meta.region_name)
        response = elb_client.describe_load_balancers()
        
        for lb in response.get('LoadBalancerDescriptions', []):
            if sg_id in lb.get('SecurityGroups', []):
                resources.append(f"ELB:{lb['LoadBalancerName']}")
    except Exception as e:
        pass  # Silently continue if we can't get ELBs
    
    # Try to check ELBv2 (Application and Network Load Balancers)
    try:
        elbv2_client = boto3.client('elbv2', region_name=ec2_client.meta.region_name)
        response = elbv2_client.describe_load_balancers()
        
        for lb in response.get('LoadBalancers', []):
            if sg_id in lb.get('SecurityGroups', []):
                resources.append(f"ALB/NLB:{lb['LoadBalancerName']}")
    except Exception as e:
        pass  # Silently continue if we can't get ALBs/NLBs
    
    # Try to check Lambda functions
    try:
        lambda_client = boto3.client('lambda', region_name=ec2_client.meta.region_name)
        response = lambda_client.list_functions()
        
        for function in response.get('Functions', []):
            if 'VpcConfig' in function and sg_id in function['VpcConfig'].get('SecurityGroupIds', []):
                resources.append(f"Lambda:{function['FunctionName']}")
    except Exception as e:
        pass  # Silently continue if we can't get Lambda functions
    
    return resources

def get_security_group_rules(region):
    """
    Get all security groups and their rules from a specific GovCloud region.
    
    Args:
        region: AWS GovCloud region name
        
    Returns:
        list: List of dictionaries with security group rule information
    """
    # Validate region is GovCloud
    if not utils.validate_govcloud_region(region):
        utils.log_error(f"Invalid GovCloud region: {region}")
        return []
    
    security_group_rules = []
    
    try:
        # Create EC2 client for this GovCloud region
        ec2_client = boto3.client('ec2', region_name=region)
        
        # Get all security groups
        response = ec2_client.describe_security_groups()
        
        # First, get all security group rules in this region to have the actual rule IDs
        try:
            all_rules_response = ec2_client.describe_security_group_rules()
            all_rules = all_rules_response.get('SecurityGroupRules', [])
        except Exception as e:
            utils.log_warning(f"Could not retrieve security group rules in {region}: {e}")
            all_rules = []
        
        # Create a map of security group rules for faster lookup
        rules_map = {}
        for rule in all_rules:
            sg_id = rule.get('GroupId', '')
            if sg_id not in rules_map:
                rules_map[sg_id] = []
            rules_map[sg_id].append(rule)
        
        security_groups = response.get('SecurityGroups', [])
        total_sgs = len(security_groups)

        if total_sgs > 0:
            utils.log_info(f"Found {total_sgs} security groups in {region} to process")

        for sg_index, sg in enumerate(security_groups, 1):
            sg_id = sg['GroupId']
            sg_name = sg.get('GroupName', 'Unnamed')
            progress = (sg_index / total_sgs) * 100 if total_sgs > 0 else 0

            utils.log_info(f"[{progress:.1f}%] Processing security group {sg_index}/{total_sgs}: {sg_id} ({sg_name})")
            
            # Get VPC name if available
            vpc_id = sg.get('VpcId', '')
            vpc_name = get_vpc_name(ec2_client, vpc_id) if vpc_id else "No VPC (EC2-Classic)"
            
            # Get resources using this security group
            resources = get_security_group_resources(ec2_client, sg_id)
            resources_str = '; '.join(resources) if resources else 'None'
            
            # Get description
            description = sg.get('Description', '')
            
            # Get owner information
            owner_id = sg.get('OwnerId', 'N/A')
            owner_formatted = utils.get_account_name_formatted(owner_id)
            
            # Process inbound rules (IpPermissions)
            for permission in sg.get('IpPermissions', []):
                protocol = permission.get('IpProtocol', 'All')
                from_port = permission.get('FromPort', None)
                to_port = permission.get('ToPort', None)
                
                # Process IPv4 ranges
                for ip_range in permission.get('IpRanges', []):
                    # Find matching rule in the rules map
                    rule_id = sg_id  # Default to using the security group ID
                    if sg_id in rules_map:
                        for rule in rules_map[sg_id]:
                            if (rule.get('IpProtocol') == protocol and
                                rule.get('FromPort', None) == from_port and
                                rule.get('ToPort', None) == to_port and
                                rule.get('CidrIpv4', '') == ip_range.get('CidrIp', '') and
                                not rule.get('IsEgress', True)):
                                rule_id = rule.get('SecurityGroupRuleId', sg_id)
                                break
                    
                    rule_desc = ip_range.get('Description', '')
                    rule_text = format_ip_range(ip_range, protocol, from_port, to_port, is_inbound=True)
                    
                    security_group_rules.append({
                        'Rule ID': rule_id,
                        'SG Name': sg_name,
                        'SG ID': sg_id,
                        'VPC': vpc_name,
                        'SG Description': description,
                        'Direction': 'Inbound',
                        'Rule': rule_text,
                        'Rule Description': rule_desc,
                        'Protocol': protocol if protocol != '-1' else 'All',
                        'From Port': from_port if from_port is not None else 'All',
                        'To Port': to_port if to_port is not None else 'All',
                        'CIDR': ip_range.get('CidrIp', ''),
                        'Owner ID': owner_formatted,
                        'Used By': resources_str,
                        'Region': region
                    })
                
                # Process IPv6 ranges
                for ip_range in permission.get('Ipv6Ranges', []):
                    # Find matching rule in the rules map
                    rule_id = sg_id  # Default to using the security group ID
                    if sg_id in rules_map:
                        for rule in rules_map[sg_id]:
                            if (rule.get('IpProtocol') == protocol and
                                rule.get('FromPort', None) == from_port and
                                rule.get('ToPort', None) == to_port and
                                rule.get('CidrIpv6', '') == ip_range.get('CidrIpv6', '') and
                                not rule.get('IsEgress', True)):
                                rule_id = rule.get('SecurityGroupRuleId', sg_id)
                                break
                    
                    rule_desc = ip_range.get('Description', '')
                    rule_text = format_ip_range(ip_range, protocol, from_port, to_port, is_inbound=True)
                    
                    security_group_rules.append({
                        'Rule ID': rule_id,
                        'SG Name': sg_name,
                        'SG ID': sg_id,
                        'VPC': vpc_name,
                        'SG Description': description,
                        'Direction': 'Inbound',
                        'Rule': rule_text,
                        'Rule Description': rule_desc,
                        'Protocol': protocol if protocol != '-1' else 'All',
                        'From Port': from_port if from_port is not None else 'All',
                        'To Port': to_port if to_port is not None else 'All',
                        'CIDR': ip_range.get('CidrIpv6', ''),
                        'Owner ID': owner_formatted,
                        'Used By': resources_str,
                        'Region': region
                    })
                
                # Process security group references
                for sg_ref in permission.get('UserIdGroupPairs', []):
                    # Find matching rule in the rules map
                    rule_id = sg_id  # Default to using the security group ID
                    ref_group_id = sg_ref.get('GroupId', '')
                    if sg_id in rules_map:
                        for rule in rules_map[sg_id]:
                            referenced_group = rule.get('ReferencedGroupInfo', {}).get('GroupId', '')
                            if (rule.get('IpProtocol') == protocol and
                                rule.get('FromPort', None) == from_port and
                                rule.get('ToPort', None) == to_port and
                                referenced_group == ref_group_id and
                                not rule.get('IsEgress', True)):
                                rule_id = rule.get('SecurityGroupRuleId', sg_id)
                                break
                    
                    rule_desc = sg_ref.get('Description', '')
                    rule_text = format_security_group_reference(sg_ref, protocol, from_port, to_port, is_inbound=True)
                    
                    security_group_rules.append({
                        'Rule ID': rule_id,
                        'SG Name': sg_name,
                        'SG ID': sg_id,
                        'VPC': vpc_name,
                        'SG Description': description,
                        'Direction': 'Inbound',
                        'Rule': rule_text,
                        'Rule Description': rule_desc,
                        'Protocol': protocol if protocol != '-1' else 'All',
                        'From Port': from_port if from_port is not None else 'All',
                        'To Port': to_port if to_port is not None else 'All',
                        'Referenced SG': sg_ref.get('GroupId', ''),
                        'Owner ID': owner_formatted,
                        'Used By': resources_str,
                        'Region': region
                    })
            
            # Process outbound rules (IpPermissionsEgress)
            for permission in sg.get('IpPermissionsEgress', []):
                protocol = permission.get('IpProtocol', 'All')
                from_port = permission.get('FromPort', None)
                to_port = permission.get('ToPort', None)
                
                # Process IPv4 ranges
                for ip_range in permission.get('IpRanges', []):
                    # Find matching rule in the rules map
                    rule_id = sg_id  # Default to using the security group ID
                    if sg_id in rules_map:
                        for rule in rules_map[sg_id]:
                            if (rule.get('IpProtocol') == protocol and
                                rule.get('FromPort', None) == from_port and
                                rule.get('ToPort', None) == to_port and
                                rule.get('CidrIpv4', '') == ip_range.get('CidrIp', '') and
                                rule.get('IsEgress', False)):
                                rule_id = rule.get('SecurityGroupRuleId', sg_id)
                                break
                    
                    rule_desc = ip_range.get('Description', '')
                    rule_text = format_ip_range(ip_range, protocol, from_port, to_port, is_inbound=False)
                    
                    security_group_rules.append({
                        'Rule ID': rule_id,
                        'SG Name': sg_name,
                        'SG ID': sg_id,
                        'VPC': vpc_name,
                        'SG Description': description,
                        'Direction': 'Outbound',
                        'Rule': rule_text,
                        'Rule Description': rule_desc,
                        'Protocol': protocol if protocol != '-1' else 'All',
                        'From Port': from_port if from_port is not None else 'All',
                        'To Port': to_port if to_port is not None else 'All',
                        'CIDR': ip_range.get('CidrIp', ''),
                        'Owner ID': owner_formatted,
                        'Used By': resources_str,
                        'Region': region
                    })
                
                # Process IPv6 ranges
                for ip_range in permission.get('Ipv6Ranges', []):
                    # Find matching rule in the rules map
                    rule_id = sg_id  # Default to using the security group ID
                    if sg_id in rules_map:
                        for rule in rules_map[sg_id]:
                            if (rule.get('IpProtocol') == protocol and
                                rule.get('FromPort', None) == from_port and
                                rule.get('ToPort', None) == to_port and
                                rule.get('CidrIpv6', '') == ip_range.get('CidrIpv6', '') and
                                rule.get('IsEgress', False)):
                                rule_id = rule.get('SecurityGroupRuleId', sg_id)
                                break
                    
                    rule_desc = ip_range.get('Description', '')
                    rule_text = format_ip_range(ip_range, protocol, from_port, to_port, is_inbound=False)
                    
                    security_group_rules.append({
                        'Rule ID': rule_id,
                        'SG Name': sg_name,
                        'SG ID': sg_id,
                        'VPC': vpc_name,
                        'SG Description': description,
                        'Direction': 'Outbound',
                        'Rule': rule_text,
                        'Rule Description': rule_desc,
                        'Protocol': protocol if protocol != '-1' else 'All',
                        'From Port': from_port if from_port is not None else 'All',
                        'To Port': to_port if to_port is not None else 'All',
                        'CIDR': ip_range.get('CidrIpv6', ''),
                        'Owner ID': owner_formatted,
                        'Used By': resources_str,
                        'Region': region
                    })
                
                # Process security group references
                for sg_ref in permission.get('UserIdGroupPairs', []):
                    # Find matching rule in the rules map
                    rule_id = sg_id  # Default to using the security group ID
                    ref_group_id = sg_ref.get('GroupId', '')
                    if sg_id in rules_map:
                        for rule in rules_map[sg_id]:
                            referenced_group = rule.get('ReferencedGroupInfo', {}).get('GroupId', '')
                            if (rule.get('IpProtocol') == protocol and
                                rule.get('FromPort', None) == from_port and
                                rule.get('ToPort', None) == to_port and
                                referenced_group == ref_group_id and
                                rule.get('IsEgress', False)):
                                rule_id = rule.get('SecurityGroupRuleId', sg_id)
                                break
                    
                    rule_desc = sg_ref.get('Description', '')
                    rule_text = format_security_group_reference(sg_ref, protocol, from_port, to_port, is_inbound=False)
                    
                    security_group_rules.append({
                        'Rule ID': rule_id,
                        'SG Name': sg_name,
                        'SG ID': sg_id,
                        'VPC': vpc_name,
                        'SG Description': description,
                        'Direction': 'Outbound',
                        'Rule': rule_text,
                        'Rule Description': rule_desc,
                        'Protocol': protocol if protocol != '-1' else 'All',
                        'From Port': from_port if from_port is not None else 'All',
                        'To Port': to_port if to_port is not None else 'All',
                        'Referenced SG': sg_ref.get('GroupId', ''),
                        'Owner ID': owner_formatted,
                        'Used By': resources_str,
                        'Region': region
                    })
            
            # If no rules found, add a placeholder entry
            if not sg.get('IpPermissions', []) and not sg.get('IpPermissionsEgress', []):
                security_group_rules.append({
                    'Rule ID': sg_id,
                    'SG Name': sg_name,
                    'SG ID': sg_id,
                    'VPC': vpc_name,
                    'SG Description': description,
                    'Direction': 'N/A',
                    'Rule': 'No rules defined',
                    'Rule Description': '',
                    'Protocol': 'N/A',
                    'From Port': 'N/A',
                    'To Port': 'N/A',
                    'CIDR': '',
                    'Owner ID': owner_formatted,
                    'Used By': resources_str,
                    'Region': region
                })
        
        return security_group_rules
    except Exception as e:
        utils.log_error(f"Error getting security groups in GovCloud region {region}", e)
        return []

def export_to_excel(security_group_rules, account_name, region_suffix=""):
    """
    Export security group rules data to Excel with GovCloud identifier.
    
    Args:
        security_group_rules: List of security group rules
        account_name: AWS account name
        region_suffix: Region suffix for filename
        
    Returns:
        str: Path to the exported file or None if failed
    """
    import pandas as pd
    
    if not security_group_rules:
        utils.log_warning("No security group rules found to export.")
        return None
    
    # Create a DataFrame
    df = pd.DataFrame(security_group_rules)
    
    # Get current date for filename
    current_date = datetime.datetime.now().strftime("%m.%d.%Y")
    
    # Use utils to create output filename with GovCloud identifier
    filename = utils.create_export_filename(
        account_name, 
        "sg-rules", 
        region_suffix, 
        current_date
    )
    
    # Save using utils function
    output_path = utils.save_dataframe_to_excel(df, filename, sheet_name='Security Group Rules')
    
    if output_path:
        utils.log_success("GovCloud Security Group data exported successfully!")
        utils.log_info(f"File location: {output_path}")
        return output_path
    else:
        utils.log_error("Error exporting data. Please check the logs.")
        return None

def main():
    """
    Main function to run the script.
    """
    try:
        # Print title and get account information
        account_id, account_name = print_title()
        
        # Check dependencies
        if not check_dependencies():
            sys.exit(1)
        
        # Import pandas after dependency check
        import pandas as pd
        
        if account_name.startswith("UNKNOWN"):
            proceed = utils.prompt_for_confirmation("Unable to determine account name. Proceed anyway?", default=False)
            if not proceed:
                utils.log_info("Exiting script...")
                sys.exit(0)
        
        # Get GovCloud regions
        utils.log_info("Getting list of AWS GovCloud regions...")
        all_regions = get_govcloud_regions()
        utils.log_info(f"Found {len(all_regions)} GovCloud regions: {', '.join(all_regions)}")
        
        # Ask user for GovCloud region selection
        print("\nGovCloud Region Selection:")
        print("Would you like the information for all GovCloud regions or a specific region?")
        print("Available GovCloud regions: us-gov-east-1, us-gov-west-1")
        region_choice = input("If all, write \"all\", or specify a GovCloud region name: ").strip().lower()
        
        # Determine which regions to process
        if region_choice == "all":
            regions = all_regions
            region_suffix = ""
            utils.log_info(f"Processing all {len(regions)} GovCloud regions...")
        else:
            # Validate the provided region is a GovCloud region
            if is_valid_govcloud_region(region_choice):
                regions = [region_choice]
                region_suffix = region_choice
                utils.log_info(f"Processing GovCloud region: {region_choice}")
            else:
                utils.log_warning(f"'{region_choice}' is not a valid GovCloud region.")
                utils.log_info("Valid GovCloud regions: us-gov-east-1, us-gov-west-1")
                utils.log_info("Defaulting to all GovCloud regions...")
                regions = all_regions
                region_suffix = ""
                utils.log_info(f"Processing all {len(regions)} GovCloud regions...")
        
        # Collect security group rules from selected GovCloud regions
        all_security_group_rules = []
        total_regions = len(regions)
        
        utils.log_info("This may take some time depending on the number of regions and security groups.")
        
        for i, region in enumerate(regions, 1):
            progress = (i / total_regions) * 100
            utils.log_info(f"[{progress:.1f}%] Processing GovCloud region: {region} ({i}/{total_regions})")
            
            # Get security group rules from this region
            region_rules = get_security_group_rules(region)
            all_security_group_rules.extend(region_rules)
            
            utils.log_info(f"Found {len(region_rules)} security group rules in {region}")
            
            # Add a small delay to avoid throttling
            time.sleep(0.5)
        
        # Print summary
        total_rules = len(all_security_group_rules)
        utils.log_success(f"Total security group rules found across all GovCloud regions: {total_rules}")
        
        if total_rules > 0:
            # Export to Excel
            utils.log_info("Exporting security group rules to Excel format...")
            output_file = export_to_excel(all_security_group_rules, account_name, region_suffix)
            
            if output_file:
                utils.log_govcloud_info(f"Export contains data from {len(regions)} GovCloud region(s)")
                utils.log_govcloud_info(f"Total security group rules exported: {total_rules}")
                print("\nScript execution completed.")
            else:
                utils.log_error("Failed to export data. Please check the logs.")
                sys.exit(1)
        else:
            utils.log_warning("No security group rules found. Nothing to export.")
    
    except KeyboardInterrupt:
        print("\n\nScript interrupted by user. Exiting...")
        sys.exit(0)
    except Exception as e:
        utils.log_error("An unexpected error occurred", e)
        sys.exit(1)

if __name__ == "__main__":
    main()