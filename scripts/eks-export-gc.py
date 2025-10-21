#!/usr/bin/env python3

"""
===========================
= AWS GOVCLOUD RESOURCE SCANNER =
===========================

Title: AWS GovCloud EKS Cluster Information Collection Script
Version: v1.0.0-GovCloud
Date: SEP-25-2025

Description:
This script collects comprehensive Amazon Elastic Kubernetes Service (EKS) cluster
information from AWS GovCloud environments including cluster details, node groups,
add-ons, networking configuration, and security settings. The data is exported to
an Excel spreadsheet with GovCloud-specific naming convention for infrastructure
auditing and compliance reporting.

GovCloud Modifications:
- Added GovCloud environment validation
- Updated partition handling for aws-us-gov
- Added GovCloud-specific compliance markers in output filenames
- Enhanced error handling for GovCloud-specific service limitations
- Integration with StratusScan GovCloud utils module

Collected information includes:
- Cluster configuration (name, version, status, endpoints)
- Networking details (VPC, subnets, security groups, CIDR)
- Security configuration (encryption, RBAC, OIDC)
- Node groups (capacity, instance types, scaling)
- Add-ons (VPC-CNI, CoreDNS, kube-proxy)
- Logging and monitoring configuration
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
    print("AWS GOVCLOUD EKS CLUSTER INFORMATION COLLECTION")
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

def get_available_regions():
    """
    Get available regions for EKS in GovCloud.

    Returns:
        list: List of available regions where EKS is supported
    """
    # EKS is available in both GovCloud regions
    govcloud_regions = ['us-gov-east-1', 'us-gov-west-1']
    available_regions = []

    for region in govcloud_regions:
        try:
            # Test EKS availability by listing clusters
            client = boto3.client('eks', region_name=region)
            client.list_clusters(maxResults=1)
            available_regions.append(region)
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code in ['UnauthorizedOperation', 'AccessDenied']:
                # Service exists but we don't have permissions
                available_regions.append(region)
            # Skip regions where EKS is not available
        except Exception:
            # Skip regions where EKS is not available
            continue

    return available_regions if available_regions else govcloud_regions  # Fallback to all GovCloud regions

def collect_cluster_details(client, cluster_name, region):
    """
    Collect detailed information about an EKS cluster.

    Args:
        client: boto3 EKS client
        cluster_name: Name of the EKS cluster
        region: AWS region

    Returns:
        dict: Dictionary containing cluster details
    """
    try:
        # Get cluster details
        response = client.describe_cluster(name=cluster_name)
        cluster = response['cluster']

        # Extract networking configuration
        vpc_config = cluster.get('resourcesVpcConfig', {})

        # Extract logging configuration
        logging_config = cluster.get('logging', {})
        log_types = logging_config.get('clusterLogging', [])

        # Create log status dictionary
        log_status = {
            'api': 'Disabled',
            'audit': 'Disabled',
            'authenticator': 'Disabled',
            'controllerManager': 'Disabled',
            'scheduler': 'Disabled'
        }

        for log_setup in log_types:
            if log_setup.get('enabled', False):
                for log_type in log_setup.get('types', []):
                    log_status[log_type] = 'Enabled'

        # Extract encryption configuration
        encryption_config = cluster.get('encryptionConfig', [])
        kms_key_arn = 'Not Configured'
        if encryption_config:
            kms_key_arn = encryption_config[0].get('provider', {}).get('keyArn', 'Not Configured')

        # Extract OIDC issuer URL
        identity = cluster.get('identity', {})
        oidc_issuer = identity.get('oidc', {}).get('issuer', 'Not Available')

        # Format tags
        tags = cluster.get('tags', {})
        tag_string = ', '.join([f"{k}={v}" for k, v in tags.items()]) if tags else 'No Tags'

        cluster_info = {
            'Region': region,
            'Cluster Name': cluster.get('name', 'N/A'),
            'Cluster ARN': cluster.get('arn', 'N/A'),
            'Status': cluster.get('status', 'N/A'),
            'Kubernetes Version': cluster.get('version', 'N/A'),
            'Platform Version': cluster.get('platformVersion', 'N/A'),
            'Created At': format_timestamp(cluster.get('createdAt')),
            'Endpoint URL': cluster.get('endpoint', 'N/A'),
            'Certificate Authority': 'Available' if cluster.get('certificateAuthority', {}).get('data') else 'Not Available',
            'Cluster Role ARN': cluster.get('roleArn', 'N/A'),
            'VPC ID': vpc_config.get('vpcId', 'N/A'),
            'Subnet IDs': ', '.join(vpc_config.get('subnetIds', [])) or 'None',
            'Security Group IDs': ', '.join(vpc_config.get('securityGroupIds', [])) or 'None',
            'Cluster Security Group': vpc_config.get('clusterSecurityGroupId', 'N/A'),
            'Public Access': 'Yes' if vpc_config.get('endpointConfigPublicAccess', False) else 'No',
            'Private Access': 'Yes' if vpc_config.get('endpointConfigPrivateAccess', False) else 'No',
            'Public Access CIDRs': ', '.join(vpc_config.get('publicAccessCidrs', [])) or 'None',
            'Service IPv4 CIDR': cluster.get('kubernetesNetworkConfig', {}).get('serviceIpv4Cidr', 'N/A'),
            'Service IPv6 CIDR': cluster.get('kubernetesNetworkConfig', {}).get('serviceIpv6Cidr', 'N/A'),
            'API Server Logging': log_status.get('api', 'N/A'),
            'Audit Logging': log_status.get('audit', 'N/A'),
            'Authenticator Logging': log_status.get('authenticator', 'N/A'),
            'Controller Manager Logging': log_status.get('controllerManager', 'N/A'),
            'Scheduler Logging': log_status.get('scheduler', 'N/A'),
            'Encryption KMS Key ARN': kms_key_arn,
            'OIDC Issuer URL': oidc_issuer,
            'Tags': tag_string[:500]  # Limit tag length for Excel
        }

        return cluster_info

    except Exception as e:
        utils.log_error(f"Error collecting details for cluster {cluster_name}", e)
        return None

def collect_node_groups(client, cluster_name, region):
    """
    Collect information about all node groups for a cluster.

    Args:
        client: boto3 EKS client
        cluster_name: Name of the EKS cluster
        region: AWS region

    Returns:
        list: List of dictionaries containing node group details
    """
    node_groups_data = []

    try:
        # List all node groups for the cluster
        response = client.list_nodegroups(clusterName=cluster_name)
        nodegroup_names = response.get('nodegroups', [])

        if not nodegroup_names:
            utils.log_info(f"No node groups found for cluster {cluster_name}")
            return []

        utils.log_info(f"Found {len(nodegroup_names)} node groups for cluster {cluster_name}")

        for nodegroup_name in nodegroup_names:
            try:
                # Get detailed information for each node group
                ng_response = client.describe_nodegroup(
                    clusterName=cluster_name,
                    nodegroupName=nodegroup_name
                )
                nodegroup = ng_response['nodegroup']

                # Extract scaling configuration
                scaling_config = nodegroup.get('scalingConfig', {})

                # Extract instance types
                instance_types = nodegroup.get('instanceTypes', [])
                instance_types_str = ', '.join(instance_types) if instance_types else 'N/A'

                # Extract launch template details
                launch_template = nodegroup.get('launchTemplate', {})
                lt_info = 'Not Used'
                if launch_template:
                    lt_name = launch_template.get('name', 'N/A')
                    lt_version = launch_template.get('version', 'N/A')
                    lt_id = launch_template.get('id', 'N/A')
                    lt_info = f"Name: {lt_name}, Version: {lt_version}, ID: {lt_id}"

                # Extract remote access configuration
                remote_access = nodegroup.get('remoteAccess', {})
                remote_access_info = 'Not Configured'
                if remote_access:
                    ec2_key = remote_access.get('ec2SshKey', 'N/A')
                    source_sgs = remote_access.get('sourceSecurityGroups', [])
                    remote_access_info = f"Key: {ec2_key}, Security Groups: {', '.join(source_sgs) if source_sgs else 'None'}"

                # Extract update configuration
                update_config = nodegroup.get('updateConfig', {})
                update_strategy = 'N/A'
                if update_config:
                    max_unavailable = update_config.get('maxUnavailable', 'N/A')
                    max_unavailable_percentage = update_config.get('maxUnavailablePercentage', 'N/A')
                    update_strategy = f"Max Unavailable: {max_unavailable}, Max Unavailable %: {max_unavailable_percentage}"

                # Format tags
                tags = nodegroup.get('tags', {})
                tag_string = ', '.join([f"{k}={v}" for k, v in tags.items()]) if tags else 'No Tags'

                nodegroup_info = {
                    'Region': region,
                    'Cluster Name': cluster_name,
                    'Node Group Name': nodegroup.get('nodegroupName', 'N/A'),
                    'Node Group ARN': nodegroup.get('nodegroupArn', 'N/A'),
                    'Status': nodegroup.get('status', 'N/A'),
                    'Capacity Type': nodegroup.get('capacityType', 'N/A'),
                    'AMI Type': nodegroup.get('amiType', 'N/A'),
                    'Release Version': nodegroup.get('releaseVersion', 'N/A'),
                    'Kubernetes Version': nodegroup.get('version', 'N/A'),
                    'Instance Types': instance_types_str,
                    'Desired Size': scaling_config.get('desiredSize', 'N/A'),
                    'Min Size': scaling_config.get('minSize', 'N/A'),
                    'Max Size': scaling_config.get('maxSize', 'N/A'),
                    'Disk Size (GB)': nodegroup.get('diskSize', 'N/A'),
                    'Node Role ARN': nodegroup.get('nodeRole', 'N/A'),
                    'Subnets': ', '.join(nodegroup.get('subnets', [])) or 'None',
                    'Launch Template': lt_info[:300],  # Limit length
                    'Remote Access': remote_access_info[:300],  # Limit length
                    'Update Strategy': update_strategy[:200],  # Limit length
                    'Created At': format_timestamp(nodegroup.get('createdAt')),
                    'Modified At': format_timestamp(nodegroup.get('modifiedAt')),
                    'Tags': tag_string[:500]  # Limit tag length
                }

                node_groups_data.append(nodegroup_info)

            except Exception as e:
                utils.log_warning(f"Error collecting details for node group {nodegroup_name}: {e}")
                continue

    except Exception as e:
        utils.log_error(f"Error collecting node groups for cluster {cluster_name}", e)

    return node_groups_data

def collect_cluster_addons(client, cluster_name, region):
    """
    Collect information about EKS add-ons for a cluster.

    Args:
        client: boto3 EKS client
        cluster_name: Name of the EKS cluster
        region: AWS region

    Returns:
        list: List of dictionaries containing add-on details
    """
    addons_data = []

    try:
        # List all add-ons for the cluster
        response = client.list_addons(clusterName=cluster_name)
        addon_names = response.get('addons', [])

        if not addon_names:
            utils.log_info(f"No add-ons found for cluster {cluster_name}")
            return []

        utils.log_info(f"Found {len(addon_names)} add-ons for cluster {cluster_name}")

        for addon_name in addon_names:
            try:
                # Get detailed information for each add-on
                addon_response = client.describe_addon(
                    clusterName=cluster_name,
                    addonName=addon_name
                )
                addon = addon_response['addon']

                # Extract configuration values (if any)
                config_values = addon.get('configurationValues', 'Default Configuration')

                # Format tags
                tags = addon.get('tags', {})
                tag_string = ', '.join([f"{k}={v}" for k, v in tags.items()]) if tags else 'No Tags'

                addon_info = {
                    'Region': region,
                    'Cluster Name': cluster_name,
                    'Add-on Name': addon.get('addonName', 'N/A'),
                    'Add-on ARN': addon.get('addonArn', 'N/A'),
                    'Status': addon.get('status', 'N/A'),
                    'Version': addon.get('addonVersion', 'N/A'),
                    'Service Account Role ARN': addon.get('serviceAccountRoleArn', 'Not Configured'),
                    'Configuration Values': str(config_values)[:300] if config_values != 'Default Configuration' else config_values,
                    'Resolve Conflicts': addon.get('resolveConflicts', 'N/A'),
                    'Health Issues': len(addon.get('health', {}).get('issues', [])),
                    'Created At': format_timestamp(addon.get('createdAt')),
                    'Modified At': format_timestamp(addon.get('modifiedAt')),
                    'Tags': tag_string[:300]
                }

                addons_data.append(addon_info)

            except Exception as e:
                utils.log_warning(f"Error collecting details for add-on {addon_name}: {e}")
                continue

    except Exception as e:
        utils.log_error(f"Error collecting add-ons for cluster {cluster_name}", e)

    return addons_data

def collect_eks_clusters(region):
    """
    Collect EKS cluster information from a specific region.

    Args:
        region: AWS region to collect clusters from

    Returns:
        tuple: (clusters_data, node_groups_data, addons_data)
    """
    clusters_data = []
    node_groups_data = []
    addons_data = []

    try:
        client = boto3.client('eks', region_name=region)

        # List all EKS clusters in the region
        response = client.list_clusters()
        cluster_names = response.get('clusters', [])

        if not cluster_names:
            utils.log_info(f"No EKS clusters found in {region}")
            return clusters_data, node_groups_data, addons_data

        utils.log_info(f"Found {len(cluster_names)} EKS clusters in {region} to process")

        for i, cluster_name in enumerate(cluster_names, 1):
            progress = (i / len(cluster_names)) * 100
            utils.log_info(f"[{progress:.1f}%] Processing cluster {i}/{len(cluster_names)}: {cluster_name}")

            # Collect cluster details
            cluster_info = collect_cluster_details(client, cluster_name, region)
            if cluster_info:
                clusters_data.append(cluster_info)

            # Collect node groups for this cluster
            cluster_node_groups = collect_node_groups(client, cluster_name, region)
            node_groups_data.extend(cluster_node_groups)

            # Collect add-ons for this cluster
            cluster_addons = collect_cluster_addons(client, cluster_name, region)
            addons_data.extend(cluster_addons)

            # Small delay to avoid API throttling
            time.sleep(0.1)

    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == 'UnauthorizedOperation':
            utils.log_warning(f"Access denied to EKS in {region}. Check permissions.")
        else:
            utils.log_error(f"Error accessing EKS in {region}: {e}")
    except Exception as e:
        utils.log_error(f"Error collecting EKS clusters from {region}", e)

    return clusters_data, node_groups_data, addons_data

def format_timestamp(timestamp):
    """
    Format datetime timestamp for display.

    Args:
        timestamp: datetime object or None

    Returns:
        str: Formatted timestamp string
    """
    if timestamp is None:
        return 'N/A'

    try:
        if hasattr(timestamp, 'strftime'):
            return timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')
        else:
            return str(timestamp)
    except Exception:
        return 'N/A'

def export_to_excel(all_clusters_data, all_node_groups_data, all_addons_data, account_id, account_name):
    """
    Export EKS data to Excel file with GovCloud naming convention.

    Args:
        all_clusters_data: List of cluster information dictionaries from all regions
        all_node_groups_data: List of node group information dictionaries from all regions
        all_addons_data: List of add-on information dictionaries from all regions
        account_id: AWS account ID
        account_name: AWS account name

    Returns:
        str: Filename of exported file or None if failed
    """
    if not all_clusters_data and not all_node_groups_data and not all_addons_data:
        utils.log_warning("No EKS data to export.")
        return None

    try:
        # Import pandas after dependency check
        import pandas as pd

        # Generate filename with GovCloud identifier
        current_date = datetime.datetime.now().strftime("%m.%d.%Y")

        # Use utils module to generate filename and save data with GovCloud identifier
        filename = utils.create_export_filename(
            account_name,
            "eks",
            "",
            current_date
        )

        # Create data frames for multi-sheet export
        data_frames = {}

        # EKS Clusters sheet
        if all_clusters_data:
            clusters_df = pd.DataFrame(all_clusters_data)
            data_frames['EKS Clusters'] = clusters_df

        # Node Groups sheet
        if all_node_groups_data:
            node_groups_df = pd.DataFrame(all_node_groups_data)
            data_frames['Node Groups'] = node_groups_df

        # Add-ons sheet
        if all_addons_data:
            addons_df = pd.DataFrame(all_addons_data)
            data_frames['Cluster Add-ons'] = addons_df

        # Create overall summary data
        summary_data = {
            'Metric': [
                'Total Clusters',
                'Active Clusters',
                'Failed Clusters',
                'Total Node Groups',
                'Total Add-ons',
                'Clusters with Public Access',
                'Clusters with Private Access',
                'Clusters with Encryption',
                'Clusters with Logging Enabled',
                'Average Kubernetes Version'
            ],
            'Count': [
                len(all_clusters_data),
                len([c for c in all_clusters_data if c.get('Status') == 'ACTIVE']),
                len([c for c in all_clusters_data if c.get('Status') in ['FAILED', 'DELETING']]),
                len(all_node_groups_data),
                len(all_addons_data),
                len([c for c in all_clusters_data if c.get('Public Access') == 'Yes']),
                len([c for c in all_clusters_data if c.get('Private Access') == 'Yes']),
                len([c for c in all_clusters_data if c.get('Encryption KMS Key ARN', 'Not Configured') != 'Not Configured']),
                len([c for c in all_clusters_data if any([
                    c.get('API Server Logging') == 'Enabled',
                    c.get('Audit Logging') == 'Enabled',
                    c.get('Authenticator Logging') == 'Enabled',
                    c.get('Controller Manager Logging') == 'Enabled',
                    c.get('Scheduler Logging') == 'Enabled'
                ])]),
                get_average_k8s_version(all_clusters_data)
            ]
        }

        summary_df = pd.DataFrame(summary_data)
        data_frames['Summary'] = summary_df

        # Save using utils function for multi-sheet Excel
        output_path = utils.save_multiple_dataframes_to_excel(data_frames, filename)

        if output_path:
            utils.log_success("GovCloud EKS data exported successfully!")
            utils.log_info(f"File location: {output_path}")

            # Log summary statistics
            total_clusters = len(all_clusters_data)
            total_node_groups = len(all_node_groups_data)
            total_addons = len(all_addons_data)
            utils.log_govcloud_info(f"Export contains {total_clusters} clusters, {total_node_groups} node groups, and {total_addons} add-ons")

            return str(output_path)
        else:
            utils.log_error("Error exporting to Excel. Please check the logs.")
            return None

    except Exception as e:
        utils.log_error("Error exporting to Excel", e)
        return None

def get_average_k8s_version(clusters_data):
    """
    Calculate average Kubernetes version across clusters.

    Args:
        clusters_data: List of cluster data dictionaries

    Returns:
        str: Average version or 'N/A'
    """
    try:
        versions = []
        for cluster in clusters_data:
            k8s_version = cluster.get('Kubernetes Version', 'N/A')
            if k8s_version != 'N/A' and k8s_version:
                # Extract version number (e.g., "1.24" from "1.24.x")
                try:
                    version_parts = k8s_version.split('.')
                    if len(version_parts) >= 2:
                        major_minor = f"{version_parts[0]}.{version_parts[1]}"
                        versions.append(major_minor)
                except Exception:
                    continue

        if versions:
            # Return most common version
            from collections import Counter
            most_common = Counter(versions).most_common(1)
            return most_common[0][0] if most_common else 'N/A'
        else:
            return 'N/A'
    except Exception:
        return 'N/A'

def main():
    """
    Main function to orchestrate the EKS information collection.
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

        utils.log_info("Starting EKS cluster information collection from GovCloud...")
        print("====================================================================")

        # Get available regions
        available_regions = get_available_regions()

        if not available_regions:
            utils.log_error("No regions available for EKS. Exiting.")
            return

        utils.log_info(f"Will scan EKS clusters in regions: {', '.join(available_regions)}")

        # Collect EKS data from all available regions
        all_clusters_data = []
        all_node_groups_data = []
        all_addons_data = []

        for region in available_regions:
            utils.log_info(f"Collecting EKS information from {region}...")

            clusters_data, node_groups_data, addons_data = collect_eks_clusters(region)

            all_clusters_data.extend(clusters_data)
            all_node_groups_data.extend(node_groups_data)
            all_addons_data.extend(addons_data)

            if clusters_data:
                utils.log_success(f"Collected {len(clusters_data)} clusters from {region}")
            else:
                utils.log_info(f"No EKS clusters found in {region}")

        if not all_clusters_data and not all_node_groups_data and not all_addons_data:
            utils.log_warning("No EKS data collected from any region. Exiting.")
            return

        print("\n====================================================================")
        print("COLLECTION COMPLETE")
        print("====================================================================")

        # Export to Excel
        filename = export_to_excel(all_clusters_data, all_node_groups_data, all_addons_data, account_id, account_name)

        if filename:
            utils.log_govcloud_info(f"Results exported with GovCloud compliance markers")
            utils.log_info(f"Total clusters processed: {len(all_clusters_data)}")
            utils.log_info(f"Total node groups processed: {len(all_node_groups_data)}")
            utils.log_info(f"Total add-ons processed: {len(all_addons_data)}")

            # Display summary statistics
            if all_clusters_data:
                active_clusters = len([c for c in all_clusters_data if c.get('Status') == 'ACTIVE'])
                utils.log_info(f"Active clusters: {active_clusters}")

                encrypted_clusters = len([c for c in all_clusters_data if c.get('Encryption KMS Key ARN', 'Not Configured') != 'Not Configured'])
                utils.log_info(f"Clusters with encryption: {encrypted_clusters}")

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