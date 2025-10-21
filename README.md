# StratusScan - AWS GovCloud Resource Exporter

> **Important**: It is recommended to run the `configure_govcloud.py` script before running the main script to set up your configuration, but it is not necessary.

StratusScan is a collection of Python scripts designed to scan and export AWS GovCloud resource information across multiple accounts and regions. This version is specifically optimized for AWS GovCloud IL4 (FedRAMP Moderate) environments and provides a unified interface for gathering detailed information about various AWS resources and exporting the data into standardized Excel spreadsheets.

## GovCloud-Specific Features

- **GovCloud Optimized**: Configured specifically for AWS GovCloud IL4 (FedRAMP Moderate) environment
- **Region Validation**: Ensures only valid GovCloud regions (us-gov-east-1, us-gov-west-1) are used
- **Service Availability**: Automatically handles services not available in GovCloud (e.g., Trusted Advisor)
- **Partition Handling**: Properly handles aws-us-gov partition for ARNs and resource identifiers
- **Compliance Ready**: Designed with government compliance requirements in mind

## Features

- **Centralized Menu Interface**: Easy-to-use menu for executing various export tools
- **Multi-Region Support**: Scan resources across a specific GovCloud region or all GovCloud regions
- **Account Mapping**: Translate AWS account IDs to friendly agency names
- **Consistent Output**: Standardized Excel exports with timestamp-based filenames and GovCloud identifiers
- **Export Archive**: Built-in functionality to zip all exports into a single file
- **Dependency Management**: Automatic checking and installation of required Python packages

## Supported AWS Resources in GovCloud

StratusScan can export information about the following AWS resources available in GovCloud IL4:

- **EBS Volumes**: Volume IDs, size, state, and attachment information
- **EBS Snapshots**: Snapshot IDs, size, encryption status, and creation dates
- **EC2 Instances**: Detailed instance information including OS, size, and network config
- **EKS Clusters**: Kubernetes cluster information, node groups, and configurations
- **Elastic Load Balancers**: Classic, Application, and Network load balancers
- **IAM Comprehensive**: Complete IAM analysis including users, roles, policies, and permissions
- **IAM Basic**: Basic IAM user and role information
- **IAM Identity Center**: AWS SSO/Identity Center users and assignments
- **IAM Identity Center Groups**: Identity Center group memberships and assignments
- **IAM Identity Center Comprehensive**: Complete Identity Center analysis with users, groups, permission sets, and assignments
- **IAM Policies**: Detailed policy analysis including managed and inline policies
- **IAM Roles**: Role details, trust policies, and attached permissions
- **Network ACLs**: NACL rules, subnet associations, and configurations
- **Organizations**: AWS Organizations structure, accounts, and organizational units
- **RDS Instances**: Database engine, size, storage, and connection information
- **S3 Buckets**: Bucket information including size, object count, and region
- **Security Groups**: Group details, inbound/outbound rules, and resource associations
- **Security Hub**: Security findings, compliance status, and remediation guidance
- **Services in Use**: Analysis of AWS services currently being used in your environment
- **VPC Resources**: VPCs, subnets, NAT gateways, peering connections, and Elastic IPs
- **All-in-One Reports**: Comprehensive resource exports by category (Storage, Compute, Network)

## Services Not Available in GovCloud

The following services are **not available** in AWS GovCloud and have been removed from this version:

- **Trusted Advisor**: Not available in GovCloud - use AWS Config Rules for compliance monitoring
- **Billing and Cost Management**: Limited availability in GovCloud compared to commercial AWS
- **Compute Optimizer**: Limited regional availability in GovCloud

## Requirements

- Python 3.6+
- AWS GovCloud credentials configured (via AWS CLI, environment variables, or instance profile)
- Access to AWS GovCloud IL4 (FedRAMP Moderate) environment
- Required Python packages:
  - boto3
  - pandas
  - openpyxl

## Installation

1. Clone or download the StratusScan GovCloud repository
2. Ensure Python 3.6+ is installed
3. While the scripts will check for missing dependencies and prompt to have them installed, you can preemptively install the required packages by running the following command:
   ```
   pip install boto3 pandas openpyxl
   ```
4. Set up your AWS GovCloud credentials using one of the [standard AWS methods](https://docs.aws.amazon.com/govcloud-us/latest/UserGuide/getting-set-up.html)

## GovCloud Authentication

To authenticate with AWS GovCloud, ensure your credentials are configured for the GovCloud environment:

### Using AWS CLI
```bash
aws configure --profile govcloud
AWS Access Key ID: [Your GovCloud Access Key]
AWS Secret Access Key: [Your GovCloud Secret Key]
Default region name: us-gov-east-1
Default output format: json
```

### Using Environment Variables
```bash
export AWS_ACCESS_KEY_ID="your-govcloud-access-key"
export AWS_SECRET_ACCESS_KEY="your-govcloud-secret-key"
export AWS_DEFAULT_REGION="us-gov-east-1"
```

### Using Instance Profile
If running on an EC2 instance in GovCloud, the instance profile will automatically provide credentials.

## Directory Structure

The repository is organized as follows:

```
StratusScan-GovCloud/
├── stratusscan-govcloud.py                          (Main menu script)
├── configure_govcloud.py                            (Configuration setup script)
├── utils_govcloud.py                                (GovCloud utilities)
├── config_govcloud.json                             (GovCloud configuration file)
├── scripts/                                         (Directory for all export scripts)
│   ├── compute-resources-gc.py                      (All compute resources in one report)
│   ├── ebs-snapshots-gc.py
│   ├── ebs-volumes-gc.py
│   ├── ec2-export-gc.py
│   ├── eks-export-gc.py
│   ├── elb-export-gc.py
│   ├── iam-comprehensive-export-gc.py
│   ├── iam-export-gc.py
│   ├── iam-identity-center-comprehensive-export-gc.py
│   ├── iam-identity-center-export-gc.py
│   ├── iam-identity-center-groups-export-gc.py
│   ├── iam-policies-export-gc.py
│   ├── iam-roles-export-gc.py
│   ├── nacl-export-gc.py
│   ├── network-resources-gc.py                      (All network resources in one report)
│   ├── organizations-export-gc.py
│   ├── rds-export-gc.py
│   ├── s3-export-gc.py
│   ├── security-groups-export-gc.py
│   ├── security-hub-export-gc.py
│   ├── services-in-use-export-gc.py
│   ├── storage-resources-gc.py                      (All storage resources in one report)
│   └── vpc-data-export-gc.py
└── output/                                          (Directory for all exported files)
    └── ... (Export files will be saved here)
```

## GovCloud Configuration

StratusScan uses a configuration file (`config_govcloud.json`) to store account mappings and GovCloud-specific settings. You can either:

1. **Recommended**: Run the configuration setup script first:
   ```
   python configure_govcloud.py
   ```
   This interactive script will help you set up your configuration properly.

2. **Manual**: Create and customize the configuration file manually using the template below:

```json
{
  "account_mappings": {
    "123456789012": "PROD-GOVCLOUD",
    "234567890123": "DEV-GOVCLOUD",
    "345678901234": "TEST-GOVCLOUD"
  },
  "agency_name": "YOUR-AGENCY",
  "govcloud_environment": "IL4",
  "default_regions": ["us-gov-east-1", "us-gov-west-1"],
  "resource_preferences": {
    "ec2": {
      "default_region": "us-gov-east-1"
    }
  },
  "disabled_services": {
    "trusted_advisor": {
      "reason": "Not available in AWS GovCloud",
      "enabled": false
    }
  }
}
```

## Usage

1. **Recommended**: First run the configuration setup script (optional but recommended):
   ```
   python configure_govcloud.py
   ```

2. Run the main menu script:
   ```
   python stratusscan-govcloud.py
   ```

3. The script will automatically detect if you're connected to GovCloud and display a warning if not

4. Select the resource type you want to export from the menu

5. Choose your GovCloud region preference:
   - All GovCloud regions (us-gov-east-1, us-gov-west-1)
   - Specific region (us-gov-east-1 or us-gov-west-1)

6. Follow the prompts to configure the export

7. Find the exported file in the `output` directory with GovCloud identifier in filename

8. Optionally, use the archive feature to create a zip file of all exports

## GovCloud Region Selection

When prompted for regions, you have the following options:

- **All GovCloud regions**: Scans both us-gov-east-1 and us-gov-west-1
- **us-gov-east-1**: Primary GovCloud region (Virginia)
- **us-gov-west-1**: Secondary GovCloud region (Oregon)

The script will validate that you're selecting valid GovCloud regions and provide helpful error messages if invalid regions are specified.

## Individual Export Scripts

While the main menu is the recommended way to run the export tools, you can also run individual scripts directly:

```
python scripts/ec2-export-gc.py
```

Each script will prompt for any required information and save its output to the `output` directory with GovCloud-specific naming conventions.

## AWS GovCloud Permissions

The scripts require read-only access to the AWS GovCloud resources they're exporting. At a minimum, you'll need the following AWS permission policies:

- **ReadOnlyAccess**: For general resource access
- **IAMReadOnlyAccess**: For IAM-related exports
- **ViewBilling**: For billing data access (if available in your GovCloud region)
- **ComputeOptimizerReadOnlyAccess**: For Compute Optimizer recommendations (if available in your region)

### Recommended IAM Policy for GovCloud

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "ec2:Describe*",
                "s3:GetBucketLocation",
                "s3:GetBucketVersioning",
                "s3:ListBucket",
                "s3:GetBucketAcl",
                "s3:GetBucketPolicy",
                "rds:Describe*",
                "ecs:Describe*",
                "ecs:List*",
                "elasticloadbalancing:Describe*",
                "iam:Get*",
                "iam:List*",
                "iam:GenerateCredentialReport",
                "iam:GenerateServiceLastAccessedDetails",
                "identitystore:Describe*",
                "identitystore:List*",
                "sso:Describe*",
                "sso:List*",
                "sso-admin:Describe*",
                "sso-admin:List*",
                "ce:GetCostAndUsage",
                "ce:GetUsageReport",
                "compute-optimizer:GetRecommendations*",
                "sts:GetCallerIdentity"
            ],
            "Resource": "*"
        }
    ]
}
```

## GovCloud-Specific Considerations

### Service Availability
- **Trusted Advisor**: Not available in GovCloud. Use AWS Config Rules for compliance monitoring.
- **Billing and Cost Management**: Limited availability in GovCloud compared to commercial AWS.
- **Compute Optimizer**: Limited regional availability. May not be available in all GovCloud regions.
- **IAM Identity Center (AWS SSO)**: Available in GovCloud with some feature limitations.
- **Some AWS Services**: Verify service availability in your specific GovCloud regions before use.

### Compliance and Security
- All exports include GovCloud identifiers in filenames for audit purposes
- ARN handling properly uses the `aws-us-gov` partition
- Account mappings support agency-specific naming conventions
- Designed to work within FedRAMP Moderate compliance boundaries

### Networking
- Ensure your GovCloud environment has appropriate internet connectivity for any external dependencies
- If running in isolated environments, pre-install Python packages as needed

## Troubleshooting

### Common Issues

**Connection to Commercial AWS Instead of GovCloud**
- Verify your AWS credentials are configured for GovCloud
- Check that your default region is set to a GovCloud region (us-gov-east-1 or us-gov-west-1)
- The script will warn you if it detects a commercial AWS connection

**Missing Dependencies**
- Run `pip install boto3 pandas openpyxl` or let the script install them automatically when prompted
- In isolated environments, you may need to install packages offline

**Invalid Region Errors**
- Ensure you're using valid GovCloud regions: us-gov-east-1 or us-gov-west-1
- The script validates regions and provides helpful error messages

**Service Not Available Errors**
- Some services have limited availability in GovCloud
- Check the service availability in your specific GovCloud regions
- Trusted Advisor is not available in GovCloud and has been disabled

**Permissions Issues**
- Ensure your IAM user/role has the necessary read permissions
- GovCloud may have additional restrictions - work with your security team to ensure proper access

### Getting Help

1. Check the script output for specific error messages
2. Verify your GovCloud credentials and permissions
3. Ensure you're using valid GovCloud regions
4. Review the configuration file for any service-specific settings

## File Naming Conventions

All exported files include GovCloud identifiers:

- Single resource: `ACCOUNT-NAME-govcloud-RESOURCE-TYPE-export-MM.DD.YYYY.xlsx`
- With suffix: `ACCOUNT-NAME-govcloud-RESOURCE-TYPE-SUFFIX-export-MM.DD.YYYY.xlsx`
- Archive: `ACCOUNT-NAME-govcloud-export-MM.DD.YYYY.zip`

This naming convention helps maintain audit trails and clearly identifies GovCloud exports.

## Support and Compliance

This tool is designed to work within AWS GovCloud IL4 (FedRAMP Moderate) compliance requirements. However, always verify that your use of this tool complies with your organization's security policies and any applicable regulations.

For questions about GovCloud-specific features or compliance considerations, consult with your organization's cloud security team.