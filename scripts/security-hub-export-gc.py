#!/usr/bin/env python3

"""
===========================
= AWS GOVCLOUD RESOURCE SCANNER =
===========================

Title: AWS GovCloud Security Hub Information Collection Script
Version: v1.0.0-GovCloud
Date: SEP-25-2025

Description:
This script collects comprehensive Security Hub findings information from AWS GovCloud
environments including severity levels, compliance status, remediation guidance, and
affected resources. The data is exported to an Excel spreadsheet with GovCloud-specific
naming convention for security monitoring and compliance reporting.

GovCloud Modifications:
- Added GovCloud environment validation
- Updated partition handling for aws-us-gov
- Added GovCloud-specific compliance markers in output filenames
- Enhanced error handling for GovCloud-specific service limitations
- Integration with StratusScan GovCloud utils module

Collected information includes: Security findings, severity levels, compliance standards,
remediation steps, affected resources, and finding history for comprehensive security analysis.
"""

import os
import sys
import boto3
import datetime
import time
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
    print("AWS GOVCLOUD SECURITY HUB INFORMATION COLLECTION")
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
    Get available regions for Security Hub in GovCloud.

    Returns:
        list: List of available regions
    """
    # Security Hub is available in both GovCloud regions
    govcloud_regions = ['us-gov-east-1', 'us-gov-west-1']
    available_regions = []

    for region in govcloud_regions:
        try:
            # Test Security Hub availability
            client = boto3.client('securityhub', region_name=region)
            client.describe_hub()
            available_regions.append(region)
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code != 'InvalidAccessException':  # Hub might not be enabled but service is available
                available_regions.append(region)
        except Exception:
            # Skip regions where Security Hub is not available
            continue

    return available_regions if available_regions else govcloud_regions  # Fallback to all GovCloud regions

def collect_security_hub_findings(region):
    """
    Collect Security Hub findings from a specific region.

    Args:
        region: AWS region to collect findings from

    Returns:
        list: List of finding information dictionaries
    """
    findings_data = []

    try:
        client = boto3.client('securityhub', region_name=region)

        # Check if Security Hub is enabled
        try:
            hub_info = client.describe_hub()
            utils.log_success(f"Security Hub is enabled in {region}")
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == 'InvalidAccessException':
                utils.log_warning(f"Security Hub is not enabled in {region}. Skipping this region.")
                return []
            else:
                utils.log_error(f"Error accessing Security Hub in {region}: {e}")
                return []

        # Get findings using pagination
        paginator = client.get_paginator('get_findings')

        # Define filters to get active findings
        filters = {
            'WorkflowStatus': [
                {
                    'Value': 'NEW',
                    'Comparison': 'EQUALS'
                },
                {
                    'Value': 'NOTIFIED',
                    'Comparison': 'EQUALS'
                }
            ],
            'RecordState': [
                {
                    'Value': 'ACTIVE',
                    'Comparison': 'EQUALS'
                }
            ]
        }

        # Count total findings first for progress tracking
        total_findings = 0
        try:
            for page in paginator.paginate(Filters=filters, MaxResults=100):
                total_findings += len(page.get('Findings', []))
        except Exception as e:
            utils.log_warning(f"Could not count findings in {region}: {e}")

        if total_findings > 0:
            utils.log_info(f"Found {total_findings} active Security Hub findings in {region} to process")
        else:
            utils.log_info(f"No active Security Hub findings found in {region}")
            return []

        # Reset paginator and process findings
        paginator = client.get_paginator('get_findings')
        processed = 0

        for page in paginator.paginate(Filters=filters, MaxResults=100):
            findings = page.get('Findings', [])

            for finding in findings:
                processed += 1
                progress = (processed / total_findings) * 100 if total_findings > 0 else 0
                finding_title = finding.get('Title', 'Unknown Finding')[:50]

                utils.log_info(f"[{progress:.1f}%] Processing finding {processed}/{total_findings}: {finding_title}")

                # Extract remediation information
                remediation = extract_remediation_info(finding)

                # Extract resource information
                resources = extract_resource_info(finding)

                # Extract compliance information
                compliance = extract_compliance_info(finding)

                finding_info = {
                    'Region': region,
                    'Finding ID': finding.get('Id', 'N/A'),
                    'Product ARN': finding.get('ProductArn', 'N/A'),
                    'Product Name': extract_product_name(finding.get('ProductArn', '')),
                    'Company Name': finding.get('CompanyName', 'N/A'),
                    'Title': finding.get('Title', 'N/A'),
                    'Description': finding.get('Description', 'N/A'),
                    'Severity Label': finding.get('Severity', {}).get('Label', 'N/A'),
                    'Severity Score': finding.get('Severity', {}).get('Normalized', 'N/A'),
                    'Confidence': finding.get('Confidence', 'N/A'),
                    'Criticality': finding.get('Criticality', 'N/A'),
                    'Workflow Status': finding.get('Workflow', {}).get('Status', 'N/A'),
                    'Record State': finding.get('RecordState', 'N/A'),
                    'Compliance Status': compliance['status'],
                    'Compliance Standards': compliance['standards'],
                    'Affected Resources': resources['summary'],
                    'Resource Types': resources['types'],
                    'Remediation Available': 'Yes' if remediation['available'] else 'No',
                    'Remediation URL': remediation['url'],
                    'Remediation Text': remediation['text'],
                    'Source URL': finding.get('SourceUrl', 'N/A'),
                    'First Observed': finding.get('FirstObservedAt', 'N/A'),
                    'Last Observed': finding.get('LastObservedAt', 'N/A'),
                    'Created At': finding.get('CreatedAt', 'N/A'),
                    'Updated At': finding.get('UpdatedAt', 'N/A'),
                    'Note': extract_note_info(finding)
                }

                findings_data.append(finding_info)

                # Small delay to avoid API throttling
                time.sleep(0.05)

    except Exception as e:
        utils.log_error(f"Error collecting Security Hub findings from {region}", e)

    return findings_data

def extract_product_name(product_arn):
    """Extract readable product name from product ARN."""
    if not product_arn or product_arn == 'N/A':
        return 'N/A'

    try:
        # Extract product name from ARN
        # ARN format: arn:aws-us-gov:securityhub:region::product/company/product-name
        parts = product_arn.split('/')
        if len(parts) >= 3:
            company = parts[-2]
            product = parts[-1]
            return f"{company}/{product}"
        else:
            return product_arn.split('/')[-1]
    except Exception:
        return 'Unknown'

def extract_remediation_info(finding):
    """Extract remediation information from finding."""
    remediation_info = {
        'available': False,
        'url': 'N/A',
        'text': 'N/A'
    }

    try:
        remediation = finding.get('Remediation', {})
        if remediation:
            remediation_info['available'] = True

            # Get remediation URL
            recommendation = remediation.get('Recommendation', {})
            if recommendation.get('Url'):
                remediation_info['url'] = recommendation['Url']

            # Get remediation text
            if recommendation.get('Text'):
                remediation_info['text'] = recommendation['Text'][:500]  # Limit length

    except Exception:
        pass

    return remediation_info

def extract_resource_info(finding):
    """Extract resource information from finding."""
    resource_info = {
        'summary': 'N/A',
        'types': 'N/A'
    }

    try:
        resources = finding.get('Resources', [])
        if resources:
            resource_list = []
            resource_types = set()

            for resource in resources[:10]:  # Limit to first 10 resources
                resource_id = resource.get('Id', 'Unknown')
                resource_type = resource.get('Type', 'Unknown')
                resource_types.add(resource_type)

                # Shorten resource ID for display
                if len(resource_id) > 40:
                    resource_id = resource_id[:37] + '...'

                resource_list.append(f"{resource_type}: {resource_id}")

            resource_info['summary'] = '; '.join(resource_list)
            resource_info['types'] = ', '.join(sorted(resource_types))

            if len(resources) > 10:
                resource_info['summary'] += f" (and {len(resources) - 10} more)"

    except Exception:
        pass

    return resource_info

def extract_compliance_info(finding):
    """Extract compliance information from finding."""
    compliance_info = {
        'status': 'N/A',
        'standards': 'N/A'
    }

    try:
        compliance = finding.get('Compliance', {})
        if compliance:
            # Get compliance status
            status = compliance.get('Status')
            if status:
                compliance_info['status'] = status

            # Get associated standards
            associated_standards = compliance.get('AssociatedStandards', [])
            if associated_standards:
                standards_list = []
                for standard in associated_standards[:5]:  # Limit to first 5
                    standard_id = standard.get('StandardsId', 'Unknown')
                    standards_list.append(standard_id)

                compliance_info['standards'] = ', '.join(standards_list)

                if len(associated_standards) > 5:
                    compliance_info['standards'] += f" (and {len(associated_standards) - 5} more)"

    except Exception:
        pass

    return compliance_info

def extract_note_info(finding):
    """Extract note information from finding."""
    try:
        note = finding.get('Note', {})
        if note and note.get('Text'):
            note_text = note['Text']
            updated_by = note.get('UpdatedBy', 'Unknown')
            updated_at = note.get('UpdatedAt', 'Unknown')
            return f"Note by {updated_by} at {updated_at}: {note_text[:200]}"
        return 'N/A'
    except Exception:
        return 'N/A'

def export_to_excel(all_findings_data, account_id, account_name):
    """
    Export Security Hub findings data to Excel file with GovCloud naming convention.

    Args:
        all_findings_data: List of finding information dictionaries from all regions
        account_id: AWS account ID
        account_name: AWS account name

    Returns:
        str: Filename of exported file or None if failed
    """
    if not all_findings_data:
        utils.log_warning("No Security Hub findings data to export.")
        return None

    try:
        # Import pandas after dependency check
        import pandas as pd

        # Generate filename with GovCloud identifier
        current_date = datetime.datetime.now().strftime("%m.%d.%Y")

        # Use utils module to generate filename and save data with GovCloud identifier
        filename = utils.create_export_filename(
            account_name,
            "security-hub",
            "",
            current_date
        )

        # Create data frames for multi-sheet export
        data_frames = {}

        # Main findings sheet
        findings_df = pd.DataFrame(all_findings_data)
        data_frames['Security Hub Findings'] = findings_df

        # Summary by severity
        if all_findings_data:
            severity_counts = findings_df['Severity Label'].value_counts().reset_index()
            severity_counts.columns = ['Severity Level', 'Count']
            data_frames['Summary by Severity'] = severity_counts

            # Summary by compliance status
            compliance_counts = findings_df['Compliance Status'].value_counts().reset_index()
            compliance_counts.columns = ['Compliance Status', 'Count']
            data_frames['Summary by Compliance'] = compliance_counts

            # Summary by product
            product_counts = findings_df['Product Name'].value_counts().reset_index()
            product_counts.columns = ['Product Name', 'Count']
            data_frames['Summary by Product'] = product_counts

            # High/Critical findings
            high_critical_df = findings_df[
                findings_df['Severity Label'].isin(['HIGH', 'CRITICAL'])
            ].copy()
            if not high_critical_df.empty:
                data_frames['High & Critical Findings'] = high_critical_df

        # Create overall summary data
        summary_data = {
            'Metric': [
                'Total Findings',
                'Critical Findings',
                'High Findings',
                'Medium Findings',
                'Low Findings',
                'Informational Findings',
                'Failed Compliance',
                'Passed Compliance',
                'Unique Products',
                'Findings with Remediation'
            ],
            'Count': [
                len(all_findings_data),
                len([f for f in all_findings_data if f.get('Severity Label') == 'CRITICAL']),
                len([f for f in all_findings_data if f.get('Severity Label') == 'HIGH']),
                len([f for f in all_findings_data if f.get('Severity Label') == 'MEDIUM']),
                len([f for f in all_findings_data if f.get('Severity Label') == 'LOW']),
                len([f for f in all_findings_data if f.get('Severity Label') == 'INFORMATIONAL']),
                len([f for f in all_findings_data if f.get('Compliance Status') == 'FAILED']),
                len([f for f in all_findings_data if f.get('Compliance Status') == 'PASSED']),
                len(set([f.get('Product Name') for f in all_findings_data if f.get('Product Name', 'N/A') != 'N/A'])),
                len([f for f in all_findings_data if f.get('Remediation Available') == 'Yes'])
            ]
        }

        summary_df = pd.DataFrame(summary_data)
        data_frames['Overall Summary'] = summary_df

        # Save using utils function for multi-sheet Excel
        output_path = utils.save_multiple_dataframes_to_excel(data_frames, filename)

        if output_path:
            utils.log_success("GovCloud Security Hub data exported successfully!")
            utils.log_info(f"File location: {output_path}")

            # Log summary statistics
            total_findings = len(all_findings_data)
            critical_high = len([f for f in all_findings_data if f.get('Severity Label') in ['CRITICAL', 'HIGH']])
            utils.log_govcloud_info(f"Export contains {total_findings} total findings ({critical_high} critical/high severity)")

            return str(output_path)
        else:
            utils.log_error("Error exporting to Excel. Please check the logs.")
            return None

    except Exception as e:
        utils.log_error("Error exporting to Excel", e)
        return None

def main():
    """
    Main function to orchestrate the Security Hub information collection.
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

        utils.log_info("Starting Security Hub information collection from GovCloud...")
        print("====================================================================")

        # Get available regions
        available_regions = get_available_regions()

        if not available_regions:
            utils.log_error("No regions available for Security Hub. Exiting.")
            return

        utils.log_info(f"Will scan Security Hub in regions: {', '.join(available_regions)}")

        # Collect findings from all available regions
        all_findings_data = []

        for region in available_regions:
            utils.log_info(f"Collecting Security Hub findings from {region}...")
            region_findings = collect_security_hub_findings(region)
            all_findings_data.extend(region_findings)

            if region_findings:
                utils.log_success(f"Collected {len(region_findings)} findings from {region}")
            else:
                utils.log_info(f"No active findings found in {region}")

        if not all_findings_data:
            utils.log_warning("No Security Hub findings collected from any region. Exiting.")
            return

        print("\n====================================================================")
        print("COLLECTION COMPLETE")
        print("====================================================================")

        # Export to Excel
        filename = export_to_excel(all_findings_data, account_id, account_name)

        if filename:
            utils.log_govcloud_info(f"Results exported with GovCloud compliance markers")
            utils.log_info(f"Total findings processed: {len(all_findings_data)}")

            # Display summary statistics
            critical_high = len([f for f in all_findings_data if f.get('Severity Label') in ['CRITICAL', 'HIGH']])
            failed_compliance = len([f for f in all_findings_data if f.get('Compliance Status') == 'FAILED'])
            with_remediation = len([f for f in all_findings_data if f.get('Remediation Available') == 'Yes'])

            utils.log_info(f"Critical/High severity findings: {critical_high}")
            utils.log_info(f"Failed compliance findings: {failed_compliance}")
            utils.log_info(f"Findings with remediation guidance: {with_remediation}")

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