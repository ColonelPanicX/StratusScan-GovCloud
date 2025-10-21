#!/usr/bin/env python3

"""
===========================
= AWS GOVCLOUD RESOURCE SCANNER =
===========================

Title: AWS GovCloud Network Resources All-in-One Export Script
Version: v1.0.0-GovCloud
Date: SEP-25-2025

Description:
This script performs a comprehensive export of all network resources from AWS GovCloud
environments including VPC/Subnet data, Elastic Load Balancers, Network ACLs, and
Security Groups. Each resource type is exported to a separate Excel file, and all files
are automatically archived into a single zip file for easy distribution and storage.

GovCloud Modifications:
- Added GovCloud environment validation
- Updated partition handling for aws-us-gov
- Added GovCloud-specific compliance markers in output filenames
- Enhanced error handling for GovCloud-specific service limitations
- Integration with StratusScan GovCloud utils module

Collected information includes:
- VPC and Subnet configurations with routing and availability zone details
- Elastic Load Balancers (Classic, Application, Network) with health checks and targets
- Network ACLs with rules, associations, and traffic flow analysis
- Security Groups with inbound/outbound rules and resource associations
- Automatic archiving of all exports into a single zip file
"""

import os
import sys
import boto3
import datetime
import time
import json
import zipfile
import subprocess
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
    print("AWS GOVCLOUD NETWORK RESOURCES ALL-IN-ONE COLLECTION")
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

def get_region_selection():
    """
    Get region selection from user for network resources scanning.

    Returns:
        list: List of selected regions to scan
    """
    print("\nRegion Selection:")
    print("1. All GovCloud regions (us-gov-east-1, us-gov-west-1)")
    print("2. us-gov-east-1 only")
    print("3. us-gov-west-1 only")

    while True:
        try:
            choice = input("\nSelect regions to scan (1-3): ").strip()

            if choice == '1':
                return ['us-gov-east-1', 'us-gov-west-1']
            elif choice == '2':
                return ['us-gov-east-1']
            elif choice == '3':
                return ['us-gov-west-1']
            else:
                print("Invalid choice. Please select 1, 2, or 3.")
        except KeyboardInterrupt:
            print("\nOperation cancelled by user.")
            sys.exit(0)

def run_individual_script(script_path, script_name, regions):
    """
    Run an individual export script and capture its output file.

    Args:
        script_path: Path to the script to run
        script_name: Human-readable name of the script
        regions: List of regions to process

    Returns:
        str: Path to generated output file or None if failed
    """
    try:
        utils.log_info(f"Starting {script_name} export...")
        print(f"\n{'='*70}")
        print(f"EXECUTING {script_name.upper()} EXPORT")
        print(f"{'='*70}")

        # Check if script exists
        if not script_path.exists():
            utils.log_error(f"Script not found: {script_path}")
            return None

        # Run the script
        env = os.environ.copy()

        # Set environment variables to indicate automated run if needed
        env['STRATUSSCAN_AUTO_RUN'] = '1'
        env['STRATUSSCAN_REGIONS'] = ','.join(regions)

        result = subprocess.run(
            [sys.executable, str(script_path)],
            capture_output=False,  # Allow real-time output
            text=True,
            env=env,
            timeout=2400  # 40-minute timeout (network resources can be extensive)
        )

        if result.returncode == 0:
            utils.log_success(f"{script_name} export completed successfully")

            # Try to find the most recent output file
            output_dir = script_path.parent.parent / "output"
            if output_dir.exists():
                # Look for recent files that match the script pattern
                pattern_map = {
                    'VPC/Subnet': '*vpc*export*.xlsx',
                    'ELB': '*elb*export*.xlsx',
                    'Network ACLs': '*nacl*export*.xlsx',
                    'Security Groups': '*security*group*export*.xlsx'
                }

                pattern = pattern_map.get(script_name, f'*{script_name.lower().replace(" ", "*").replace("/", "*")}*.xlsx')

                # Find the most recent matching file
                matching_files = list(output_dir.glob(pattern))
                if matching_files:
                    # Sort by modification time, get most recent
                    most_recent = max(matching_files, key=lambda f: f.stat().st_mtime)
                    utils.log_info(f"Found output file: {most_recent.name}")
                    return str(most_recent)
                else:
                    utils.log_warning(f"Could not find output file for {script_name} with pattern: {pattern}")

                    # Fallback: try broader pattern matching
                    all_xlsx_files = list(output_dir.glob('*.xlsx'))
                    if all_xlsx_files:
                        # Get the most recent xlsx file
                        most_recent = max(all_xlsx_files, key=lambda f: f.stat().st_mtime)

                        # Check if it might be from our script based on timestamp
                        file_time = most_recent.stat().st_mtime
                        current_time = time.time()

                        # If file was created in the last 10 minutes, assume it's ours
                        if (current_time - file_time) < 600:
                            utils.log_info(f"Found recent output file (fallback): {most_recent.name}")
                            return str(most_recent)

                    utils.log_warning(f"No suitable output file found for {script_name}")
                    return None
            else:
                utils.log_warning("Output directory not found")
                return None
        else:
            utils.log_error(f"{script_name} export failed with return code {result.returncode}")
            return None

    except subprocess.TimeoutExpired:
        utils.log_error(f"{script_name} export timed out after 40 minutes")
        return None
    except Exception as e:
        utils.log_error(f"Error running {script_name} export", e)
        return None

def create_network_archive(output_files, account_name):
    """
    Create a zip archive containing all network resource exports.

    Args:
        output_files: List of output file paths
        account_name: AWS account name for filename

    Returns:
        str: Path to created archive or None if failed
    """
    try:
        # Filter out None values (failed exports)
        valid_files = [f for f in output_files if f and Path(f).exists()]

        if not valid_files:
            utils.log_error("No valid output files to archive")
            return None

        # Generate archive filename
        current_date = datetime.datetime.now().strftime("%m.%d.%Y")
        archive_filename = utils.create_export_filename(
            account_name,
            "network-resources-all",
            "",
            current_date,
            extension=".zip"
        )

        utils.log_info(f"Creating archive: {archive_filename}")
        print(f"\n{'='*70}")
        print(f"CREATING NETWORK RESOURCES ARCHIVE")
        print(f"{'='*70}")

        # Create the zip file
        with zipfile.ZipFile(archive_filename, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for file_path in valid_files:
                file_path_obj = Path(file_path)
                if file_path_obj.exists():
                    # Add file to zip with just the filename (no path)
                    zipf.write(file_path_obj, file_path_obj.name)
                    utils.log_info(f"Added to archive: {file_path_obj.name}")

        if Path(archive_filename).exists():
            archive_size = Path(archive_filename).stat().st_size / (1024 * 1024)  # MB
            utils.log_success(f"Archive created successfully: {archive_filename}")
            utils.log_info(f"Archive size: {archive_size:.2f} MB")
            utils.log_info(f"Files included: {len(valid_files)}")
            return archive_filename
        else:
            utils.log_error("Archive creation failed")
            return None

    except Exception as e:
        utils.log_error("Error creating archive", e)
        return None

def cleanup_individual_files(output_files, keep_originals=False):
    """
    Optionally clean up individual export files after archiving.

    Args:
        output_files: List of output file paths
        keep_originals: Whether to keep the original files
    """
    if keep_originals:
        utils.log_info("Keeping original export files as requested")
        return

    try:
        valid_files = [f for f in output_files if f and Path(f).exists()]

        if not valid_files:
            return

        # Ask user if they want to keep individual files
        print(f"\nCleanup Options:")
        print(f"Archive created with {len(valid_files)} files.")
        response = input("Keep individual export files? (y/n): ").lower().strip()

        if response == 'n':
            utils.log_info("Removing individual export files...")
            removed_count = 0
            for file_path in valid_files:
                try:
                    Path(file_path).unlink()
                    utils.log_info(f"Removed: {Path(file_path).name}")
                    removed_count += 1
                except Exception as e:
                    utils.log_warning(f"Could not remove {Path(file_path).name}: {e}")

            utils.log_success(f"Removed {removed_count} individual files")
        else:
            utils.log_info("Keeping individual export files")

    except Exception as e:
        utils.log_error("Error during cleanup", e)

def estimate_network_complexity():
    """
    Provide a rough estimate of network complexity to set user expectations.

    Returns:
        dict: Estimated complexity information
    """
    try:
        complexity_info = {
            'estimated_time': '5-15 minutes',
            'resource_count': 'Unknown',
            'warning': None
        }

        # Try to get a rough count of network resources
        ec2_client = boto3.client('ec2', region_name='us-gov-west-1')

        try:
            # Quick count of VPCs to estimate complexity
            vpcs = ec2_client.describe_vpcs()['Vpcs']
            vpc_count = len(vpcs)

            if vpc_count > 5:
                complexity_info['estimated_time'] = '10-25 minutes'
                complexity_info['resource_count'] = f'~{vpc_count} VPCs detected'
                complexity_info['warning'] = 'Complex network environment detected - this may take longer'
            elif vpc_count > 0:
                complexity_info['estimated_time'] = '5-15 minutes'
                complexity_info['resource_count'] = f'~{vpc_count} VPCs detected'
        except Exception:
            # If we can't get counts, use defaults
            pass

        return complexity_info

    except Exception as e:
        return {
            'estimated_time': '5-20 minutes',
            'resource_count': 'Unable to estimate',
            'warning': 'Cannot access AWS to estimate complexity'
        }

def main():
    """
    Main function to orchestrate the all-in-one network resources collection.
    """
    try:
        # Check dependencies first
        if not check_dependencies():
            return

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

        # Get region selection
        selected_regions = get_region_selection()

        # Estimate complexity
        complexity = estimate_network_complexity()

        print(f"\n{'='*70}")
        print(f"NETWORK COMPLEXITY ASSESSMENT")
        print(f"{'='*70}")
        print(f"Estimated execution time: {complexity['estimated_time']}")
        print(f"Network resources: {complexity['resource_count']}")
        if complexity['warning']:
            utils.log_warning(complexity['warning'])

        utils.log_info(f"Starting comprehensive network resources collection from GovCloud...")
        utils.log_info(f"Selected regions: {', '.join(selected_regions)}")
        print(f"\n{'='*70}")
        print(f"NETWORK RESOURCES ALL-IN-ONE EXPORT")
        print(f"Regions: {', '.join(selected_regions)}")
        print(f"{'='*70}")

        # Define network resource scripts to run
        scripts_dir = Path(__file__).parent
        network_scripts = [
            {
                'name': 'VPC/Subnet',
                'script': scripts_dir / 'vpc-data-export-gc.py',
                'description': 'VPC configurations, subnets, and routing tables'
            },
            {
                'name': 'ELB',
                'script': scripts_dir / 'elb-export-gc.py',
                'description': 'Elastic Load Balancers (Classic, Application, Network)'
            },
            {
                'name': 'Network ACLs',
                'script': scripts_dir / 'nacl-export-gc.py',
                'description': 'Network ACL rules and subnet associations'
            },
            {
                'name': 'Security Groups',
                'script': scripts_dir / 'security-groups-export-gc.py',
                'description': 'Security group rules and resource associations'
            }
        ]

        # Track output files and execution results
        output_files = []
        execution_results = {}
        start_time = datetime.datetime.now()

        print(f"\nPlanned exports (estimated {complexity['estimated_time']}):")
        for i, script_info in enumerate(network_scripts, 1):
            print(f"  {i}. {script_info['name']}: {script_info['description']}")

        print(f"\nStarting exports... (This may take some time for complex networks)\n")

        # Execute each script
        for i, script_info in enumerate(network_scripts, 1):
            script_start = datetime.datetime.now()

            utils.log_info(f"[{i}/{len(network_scripts)}] Processing {script_info['name']}...")

            output_file = run_individual_script(
                script_info['script'],
                script_info['name'],
                selected_regions
            )

            script_end = datetime.datetime.now()
            execution_time = (script_end - script_start).total_seconds()

            if output_file:
                output_files.append(output_file)
                execution_results[script_info['name']] = {
                    'status': 'SUCCESS',
                    'file': output_file,
                    'duration': execution_time
                }
                utils.log_success(f"{script_info['name']} completed in {execution_time:.1f} seconds")
            else:
                execution_results[script_info['name']] = {
                    'status': 'FAILED',
                    'file': None,
                    'duration': execution_time
                }
                utils.log_error(f"{script_info['name']} failed after {execution_time:.1f} seconds")

            # Small delay between scripts
            time.sleep(2)

        # Summary of individual exports
        total_time = (datetime.datetime.now() - start_time).total_seconds()

        print(f"\n{'='*70}")
        print(f"INDIVIDUAL EXPORTS SUMMARY")
        print(f"{'='*70}")

        successful_exports = []
        failed_exports = []

        for script_name, result in execution_results.items():
            status_symbol = "✓" if result['status'] == 'SUCCESS' else "✗"
            duration = result['duration']

            print(f"{status_symbol} {script_name:<15} {result['status']:<10} ({duration:.1f}s)")

            if result['status'] == 'SUCCESS':
                successful_exports.append(script_name)
                if result['file']:
                    print(f"    Output: {Path(result['file']).name}")
            else:
                failed_exports.append(script_name)

        print(f"\nExecution Summary:")
        print(f"  Total time: {total_time:.1f} seconds ({total_time/60:.1f} minutes)")
        print(f"  Successful: {len(successful_exports)}/{len(network_scripts)}")
        print(f"  Failed: {len(failed_exports)}")

        if failed_exports:
            utils.log_warning(f"Failed exports: {', '.join(failed_exports)}")

        # Create archive if we have any successful exports
        if output_files:
            utils.log_info(f"Creating comprehensive archive with {len(output_files)} files...")
            archive_path = create_network_archive(output_files, account_name)

            if archive_path:
                print(f"\n{'='*70}")
                print(f"ALL-IN-ONE EXPORT COMPLETED SUCCESSFULLY")
                print(f"{'='*70}")

                utils.log_govcloud_info(f"Network resources archive created with GovCloud compliance markers")
                utils.log_info(f"Archive location: {archive_path}")
                utils.log_info(f"Total execution time: {total_time:.1f} seconds ({total_time/60:.1f} minutes)")

                # Cleanup individual files
                cleanup_individual_files(output_files)

                print(f"\nNetwork Resources All-in-One Export Summary:")
                print(f"  ✓ Archive: {Path(archive_path).name}")
                print(f"  ✓ Resources: {', '.join(successful_exports)}")
                print(f"  ✓ Regions: {', '.join(selected_regions)}")
                print(f"  ✓ Execution time: {total_time/60:.1f} minutes")
                if failed_exports:
                    print(f"  ! Failed: {', '.join(failed_exports)}")
            else:
                utils.log_error("Failed to create archive")
        else:
            utils.log_error("No successful exports to archive")
            print(f"\nAll exports failed. Please check the logs and try individual scripts.")

        print(f"\nScript execution completed.")

    except KeyboardInterrupt:
        print("\n\nOperation cancelled by user.")
        sys.exit(0)
    except Exception as e:
        utils.log_error("Unexpected error occurred", e)
        sys.exit(1)

if __name__ == "__main__":
    main()