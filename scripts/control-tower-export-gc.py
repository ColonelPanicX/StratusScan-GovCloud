#!/usr/bin/env python3

"""
===========================
= AWS GOVCLOUD RESOURCE SCANNER =
===========================

Title: AWS GovCloud Control Tower Export Script
Version: v1.0.0-GovCloud
Date: OCT-09-2025

Description:
This script exports AWS Control Tower enabled controls across all organizational units
in AWS GovCloud. It queries the AWS Organizations and Control Tower services to retrieve
all OUs and their associated enabled controls, then exports the data to an Excel spreadsheet.
The output filename includes the AWS account name based on the account ID mapping in the
configuration and includes GovCloud identifiers for compliance and audit purposes.

GovCloud Modifications:
- Added GovCloud region validation
- Updated partition handling for aws-us-gov
- Excel export instead of CSV for consistency with other scripts
- Integration with utils_govcloud for standardized logging and file handling
- Support for account name mapping from configuration
"""

import sys
import os
import boto3
import datetime
import pandas as pd
from pathlib import Path
from botocore.exceptions import ClientError

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

def convert_datetime_to_string(dt_obj):
    """
    Convert datetime object to timezone-unaware string for Excel compatibility.

    Args:
        dt_obj: datetime object (can be timezone-aware or unaware)

    Returns:
        str: Formatted datetime string or 'N/A' if None/invalid
    """
    if dt_obj is None:
        return 'N/A'

    try:
        if hasattr(dt_obj, 'strftime'):
            # If timezone-aware, convert to UTC and make timezone-naive
            if hasattr(dt_obj, 'tzinfo') and dt_obj.tzinfo is not None:
                # Convert to UTC and remove timezone info
                utc_dt = dt_obj.utctimetuple()
                dt_obj = datetime.datetime(*utc_dt[:6])

            return dt_obj.strftime('%Y-%m-%d %H:%M:%S UTC')
        else:
            return str(dt_obj)
    except Exception:
        return 'N/A'

def clean_dataframe_datetimes(df):
    """Clean timezone-aware datetimes in a pandas DataFrame for Excel compatibility."""
    try:
        for col in df.columns:
            if df[col].dtype == 'datetime64[ns, UTC]' or any(isinstance(val, datetime.datetime) for val in df[col].dropna()):
                df[col] = df[col].apply(lambda x: convert_datetime_to_string(x) if pd.notna(x) else 'N/A')
        return df
    except Exception as e:
        utils.log_warning(f"Error cleaning datetime objects in dataframe: {e}")
        return df

def get_all_ous(org_client):
    """Get all organizational units in the organization"""
    ous = []

    try:
        # Get root
        roots = org_client.list_roots()
        root_id = roots['Roots'][0]['Id']
        
        # Get all OUs under root
        paginator = org_client.get_paginator('list_organizational_units_for_parent')
        
        def get_ous_recursive(parent_id, parent_name="Root"):
            for page in paginator.paginate(ParentId=parent_id):
                for ou in page['OrganizationalUnits']:
                    ou_info = {
                        'Id': ou['Id'],
                        'Name': ou['Name'],
                        'Arn': ou['Arn']
                    }
                    ous.append(ou_info)
                    utils.log_info(f"Found OU: {ou['Name']} ({ou['Id']})")

                    # Recursively get child OUs
                    get_ous_recursive(ou['Id'], ou['Name'])

        # Start with root
        get_ous_recursive(root_id)

    except ClientError as e:
        utils.log_error(f"Error retrieving OUs", e)

    return ous

def get_enabled_controls(ct_client, ou_arn):
    """Get all enabled controls for a specific OU"""
    controls = []

    try:
        paginator = ct_client.get_paginator('list_enabled_controls')

        for page in paginator.paginate(targetIdentifier=ou_arn):
            for control in page['enabledControls']:
                controls.append(control)

    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == 'ResourceNotFoundException':
            # No controls enabled for this OU
            pass
        else:
            utils.log_warning(f"Error retrieving controls for {ou_arn}: {e}")

    return controls

def get_control_details(ct_client, control_identifier):
    """Get detailed information about a specific control"""
    try:
        response = ct_client.get_control_operation(
            OperationIdentifier=control_identifier
        )
        return response
    except ClientError:
        # If we can't get details, return None
        return None

def main():
    # Setup logging for this script
    start_time = datetime.datetime.now()
    utils.setup_logging("control-tower-export-gc")
    utils.log_script_start("control-tower-export-gc.py",
                          "Export AWS Control Tower enabled controls from GovCloud")

    utils.log_info("=" * 80)
    utils.log_info("AWS GOVCLOUD CONTROL TOWER EXPORT")
    utils.log_info("=" * 80)

    # Validate AWS credentials and check for GovCloud environment
    utils.log_section("Validating AWS Credentials")
    is_valid, account_id, error_msg, is_govcloud = utils.validate_aws_credentials()

    if not is_valid:
        utils.log_error("AWS credentials validation failed", error_msg)
        utils.log_error("Make sure AWS credentials are configured properly for GovCloud")
        return

    utils.log_success(f"Successfully connected to AWS Account: {account_id}")

    if not is_govcloud:
        utils.log_warning("Connected to commercial AWS, not GovCloud")
        utils.log_warning("This script is optimized for AWS GovCloud environments")

    # Get account name from configuration
    account_name = utils.get_account_name(account_id, "UNKNOWN-ACCOUNT")
    utils.log_info(f"Account Name: {account_name}")

    # Initialize AWS clients (Organizations and Control Tower are global services)
    utils.log_section("Initializing AWS Clients")
    try:
        # Organizations and Control Tower use us-gov-west-1 for GovCloud
        region = 'us-gov-west-1' if is_govcloud else 'us-east-1'
        org_client = boto3.client('organizations', region_name=region)
        ct_client = boto3.client('controltower', region_name=region)
        utils.log_success(f"AWS clients initialized in region: {region}")
    except Exception as e:
        utils.log_error("Error initializing AWS clients", e)
        utils.log_error("Make sure your account has access to Organizations and Control Tower")
        return

    # Get organization info
    utils.log_section("Retrieving Organization Information")
    try:
        org = org_client.describe_organization()
        org_id = org['Organization']['Id']
        org_arn = org['Organization']['Arn']
        master_account = org['Organization']['MasterAccountId']

        utils.log_info(f"Organization ID: {org_id}")
        utils.log_info(f"Master Account: {master_account}")
        utils.log_info(f"Organization ARN: {org_arn}")
    except ClientError as e:
        utils.log_error("Error accessing organization", e)
        utils.log_error("Ensure your account has proper Organizations permissions")
        return

    # Get all OUs
    utils.log_section("Retrieving Organizational Units")
    utils.log_info("Scanning organization structure...")
    ous = get_all_ous(org_client)
    utils.log_success(f"Found {len(ous)} organizational unit(s)")

    # Get enabled controls for each OU
    utils.log_section("Retrieving Enabled Controls")
    utils.log_info("Querying Control Tower for enabled controls...")
    all_controls = []

    for ou in ous:
        utils.log_info(f"Checking OU: {ou['Name']}")
        controls = get_enabled_controls(ct_client, ou['Arn'])

        for control in controls:
            control_data = {
                'OU_Name': ou['Name'],
                'OU_ID': ou['Id'],
                'OU_ARN': ou['Arn'],
                'Control_ARN': control.get('controlIdentifier', ''),
                'Status_Summary': control.get('statusSummary', {}).get('status', ''),
                'Drift_Status': control.get('driftStatusSummary', {}).get('driftStatus', 'N/A')
            }
            all_controls.append(control_data)
            utils.log_info(f"  - {control.get('controlIdentifier', 'Unknown')}")

    utils.log_success(f"Total enabled controls found: {len(all_controls)}")

    # Export to Excel
    if all_controls:
        utils.log_section("Exporting Data to Excel")

        try:
            # Create DataFrame
            df = pd.DataFrame(all_controls)

            # Clean any datetime fields
            df = clean_dataframe_datetimes(df)

            # Create filename using utils function
            current_date = datetime.datetime.now().strftime("%m.%d.%Y")
            filename = utils.create_export_filename(account_name, "control-tower", "enabled-controls", current_date)

            # Save to Excel using utils function
            output_path = utils.save_dataframe_to_excel(
                df,
                filename,
                sheet_name="Enabled Controls",
                auto_adjust_columns=True
            )

            if output_path:
                utils.log_success(f"Successfully exported {len(all_controls)} controls to:")
                utils.log_info(f"  {output_path}")
                utils.log_export_summary("Control Tower Enabled Controls", len(all_controls), output_path)
            else:
                utils.log_error("Failed to export data to Excel")

        except Exception as e:
            utils.log_error("Error creating Excel export", e)
    else:
        utils.log_warning("No enabled controls found to export.")
        utils.log_info("This may be normal if Control Tower is not fully configured")

    # Log script completion
    utils.log_script_end("control-tower-export-gc.py", start_time)

if __name__ == "__main__":
    main()
