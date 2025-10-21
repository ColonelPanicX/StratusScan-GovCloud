#!/usr/bin/env python3
# StratusScan.py - Main menu script for AWS GovCloud resource export tools

"""
===========================
= AWS GOVCLOUD RESOURCE SCANNER =
===========================

Title: StratusScan - AWS GovCloud Resource Exporter Main Menu
Version: v2.1.4-GovCloud
Date: AUG-19-2025

Description:
This script provides a centralized interface for executing various AWS GovCloud resource
export tools within the StratusScan package. It allows users to select which resource 
type to export (EC2 instances, VPC resources, etc.) and calls the appropriate script 
to perform the selected operation.

GovCloud Modifications:
- Updated for AWS GovCloud IL4 (FedRAMP Moderate) environment
- Disabled Trusted Advisor (not available in GovCloud)
- Default regions set to us-gov-east-1 and us-gov-west-1
- Compute Optimizer limited to supported GovCloud regions
- Updated partition handling for aws-us-gov

Deployment Structure:
- The main menu script should be located in the root directory of the StratusScan package
- Individual export scripts should be located in the 'scripts' subdirectory
- Exported files will be saved to the 'output' subdirectory
- Account mappings and configuration are stored in config.json
"""

import os
import sys
import subprocess
import zipfile
import datetime
from pathlib import Path

# Add the current directory to the path to ensure we can import utils
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Import the utility module
try:
    import utils_govcloud as utils
except ImportError:
    try:
        import utils
    except ImportError:
        print("ERROR: Could not import the utils module. Make sure utils_govcloud.py or utils.py is in the same directory as this script.")
        sys.exit(1)

# Initialize logging for main menu
SCRIPT_START_TIME = datetime.datetime.now()
utils.setup_logging("main-menu", log_to_file=True)
utils.log_script_start("stratusscan-govcloud.py", "AWS GovCloud Resource Scanner Main Menu")
utils.log_system_info()

def clear_screen():
    """
    Clear the terminal screen based on the operating system.
    """
    # Check if we're on Windows or Unix/Linux/MacOS
    if os.name == 'nt':  # Windows
        os.system('cls')
    else:  # Unix/Linux/MacOS
        os.system('clear')

def print_header():
    """
    Print the main menu header with version information.
    
    Returns:
        tuple: (account_id, account_name) - The AWS account information
    """
    clear_screen()
    print("====================================================================")
    print("              AWS GOVCLOUD RESOURCE SCANNER                         ")
    print("====================================================================")
    print("                         STRATUSSCAN                                ")
    print("                AWS GOVCLOUD RESOURCE EXPORTER MENU                 ")
    print("====================================================================")
    print("Version: v2.1.4-GovCloud                       Date: AUG-19-2025")
    print("Environment: AWS GovCloud IL4 (FedRAMP Moderate)")
    print("====================================================================")
    
    # Get the current AWS account ID and map to account name
    try:
        # Create a boto3 STS client
        import boto3
        sts = boto3.client('sts')
        account_id = sts.get_caller_identity()["Account"]
        account_name = utils.get_account_name(account_id, default=account_id)
        
        # Validate we're in GovCloud
        try:
            caller_arn = sts.get_caller_identity()["Arn"]
            if "aws-us-gov" not in caller_arn:
                print("WARNING: You appear to be connected to commercial AWS, not GovCloud!")
                print("This tool is optimized for AWS GovCloud environments.")
        except Exception:
            pass  # Continue if we can't validate the partition
        
        print(f"Account ID: {account_id}")
        print(f"Account Name: {account_name}")
    except Exception as e:
        print(f"Error getting account information: {e}")
        account_id = "UNKNOWN"
        account_name = "UNKNOWN-ACCOUNT"
    
    print("====================================================================")
    return account_id, account_name

def check_dependency(dependency):
    """
    Check if a Python dependency is installed.
    
    Args:
        dependency: Name of the Python package to check
        
    Returns:
        bool: True if installed, False otherwise
    """
    try:
        __import__(dependency)
        return True
    except ImportError:
        return False

def install_dependency(dependency):
    """
    Install a Python dependency after user confirmation.
    
    Args:
        dependency: Name of the Python package to install
        
    Returns:
        bool: True if installed successfully, False otherwise
    """
    print(f"\nPackage '{dependency}' is required but not installed.")
    response = input(f"Would you like to install {dependency}? (y/n): ").lower()
    
    if response == 'y':
        try:
            import subprocess
            print(f"Installing {dependency}...")
            subprocess.check_call([sys.executable, "-m", "pip", "install", dependency])
            print(f"[SUCCESS] Successfully installed {dependency}")
            return True
        except Exception as e:
            print(f"Error installing {dependency}: {e}")
            return False
    else:
        print(f"Cannot proceed without {dependency}.")
        return False

def check_dependencies():
    """
    Check and install common required dependencies.
    
    Returns:
        bool: True if all dependencies are satisfied, False otherwise
    """
    print("Checking required dependencies...")
    required_packages = ['boto3', 'pandas', 'openpyxl']
    
    for package in required_packages:
        if check_dependency(package):
            print(f"[OK] {package} is already installed")
        else:
            if not install_dependency(package):
                return False
    
    return True

def ensure_directory_structure():
    """
    Ensure the required directory structure exists.
    Creates the scripts and output directories if they don't exist.
    
    Returns:
        tuple: (scripts_dir, output_dir) - Paths to the scripts and output directories
    """
    # Get the base directory (where this script is located)
    base_dir = Path(__file__).parent.absolute()
    
    # Create scripts directory if it doesn't exist
    scripts_dir = base_dir / "scripts"
    if not scripts_dir.exists():
        print(f"Creating scripts directory: {scripts_dir}")
        scripts_dir.mkdir(exist_ok=True)
    
    # Create output directory if it doesn't exist
    output_dir = base_dir / "output"
    if not output_dir.exists():
        print(f"Creating output directory: {output_dir}")
        output_dir.mkdir(exist_ok=True)
    
    # Check if config_govcloud.json exists, create default if it doesn't
    config_path = base_dir / "config_govcloud.json"
    
    if not config_path.exists():
        print(f"No configuration file found. The config_govcloud.json file should exist.")
        print(f"Please ensure config_govcloud.json is present in the StratusScan directory.")
        print(f"You may want to edit this file to add your account mappings.")
    
    return scripts_dir, output_dir

def execute_script(script_path):
    """
    Execute the selected export script.

    Args:
        script_path (Path): Path to the script to execute

    Returns:
        bool: True if the script executed successfully, False otherwise
    """
    start_time = datetime.datetime.now()
    script_name = script_path.name

    try:
        # Log script execution start
        utils.log_section(f"EXECUTING SCRIPT: {script_name}")
        utils.log_info(f"Script path: {script_path}")
        utils.log_info(f"Execution start time: {start_time}")

        # Clear the screen before executing the script
        clear_screen()

        print(f"Executing: {script_path}")
        print("=" * 60)

        # Execute the script as a subprocess
        result = subprocess.run([sys.executable, str(script_path)],
                              check=True)

        if result.returncode == 0:
            print("\nScript execution completed successfully.")
            utils.log_success(f"Script executed successfully: {script_name}")
            return True
        else:
            print(f"\nScript execution failed with return code: {result.returncode}")
            utils.log_error(f"Script execution failed: {script_name} (return code: {result.returncode})")
            return False

    except subprocess.CalledProcessError as e:
        print(f"Error executing script: {e}")
        utils.log_error(f"Script execution error: {script_name}", e)
        return False
    except Exception as e:
        print(f"Unexpected error during script execution: {e}")
        utils.log_error(f"Unexpected error executing script: {script_name}", e)
        return False
    finally:
        # Log execution completion
        end_time = datetime.datetime.now()
        duration = end_time - start_time
        utils.log_info(f"Script execution completed: {script_name}")
        utils.log_info(f"Execution duration: {duration}")

def create_output_archive(account_name):
    """
    Create a zip archive of the output directory.
    
    Args:
        account_name: The AWS account name to use in the filename
        
    Returns:
        bool: True if archive was created successfully, False otherwise
    """
    try:
        # Clear the screen
        clear_screen()
        
        print("====================================================================")
        print("CREATING OUTPUT ARCHIVE")
        print("====================================================================")
        
        # Get the output directory path
        output_dir = Path(__file__).parent / "output"
        
        # Check if output directory exists and has files
        if not output_dir.exists():
            print(f"Output directory not found: {output_dir}")
            return False
        
        files = list(output_dir.glob("*.*"))
        if not files:
            print("No files found in the output directory to archive.")
            return False
        
        print(f"Found {len(files)} files to archive.")
        
        # Create filename with current date
        current_date = datetime.datetime.now().strftime("%m.%d.%Y")
        zip_filename = f"{account_name}-govcloud-export-{current_date}.zip"
        zip_path = Path(__file__).parent / zip_filename
        
        # Create the zip file
        print(f"Creating archive: {zip_filename}")
        print("Please wait...")
        
        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for file in files:
                # Archive file with relative path inside the zip
                zipf.write(file, arcname=file.name)
                print(f"  Added: {file.name}")
        
        print("\nArchive creation completed successfully!")
        print(f"Archive saved to: {zip_path}")
        
        return True
    
    except Exception as e:
        print(f"Error creating archive: {e}")
        return False

def get_menu_structure():
    """
    Create a hierarchical menu structure with main categories and submenus.
    Updated for GovCloud IL4 environment - removes unavailable services.
    
    Returns:
        dict: Dictionary with main menu options and their corresponding submenus
    """
    scripts_dir, _ = ensure_directory_structure()
    
    # Define the menu structure with categories and script mappings
    # Updated to match actual GovCloud scripts available
    menu_structure = {
        "1": {
            "name": "Storage Resources",
            "submenu": {
                "1": {
                    "name": "EBS Volumes (GovCloud)",
                    "file": scripts_dir / "ebs-volumes-gc.py",
                    "description": "Export EBS volume information from GovCloud"
                },
                "2": {
                    "name": "EBS Snapshots (GovCloud)",
                    "file": scripts_dir / "ebs-snapshots-gc.py",
                    "description": "Export EBS snapshot information from GovCloud"
                },
                "3": {
                    "name": "S3 (GovCloud)",
                    "file": scripts_dir / "s3-export-gc.py",
                    "description": "Export S3 bucket information from GovCloud"
                },
                "4": {
                    "name": "All Storage Resources (GovCloud)",
                    "file": scripts_dir / "storage-resources-gc.py",
                    "description": "Export all storage resources (EBS, S3) in one comprehensive report"
                },
                "5": {
                    "name": "Return to Main Menu",
                    "file": None,
                    "description": "Return to the main menu"
                }
            }
        },
        "2": {
            "name": "Compute Resources",
            "submenu": {
                "1": {
                    "name": "EC2 (GovCloud)",
                    "file": scripts_dir / "ec2-export-gc.py",
                    "description": "Export EC2 instance data from GovCloud"
                },
                "2": {
                    "name": "RDS (GovCloud)",
                    "file": scripts_dir / "rds-export-gc.py",
                    "description": "Export RDS instance information from GovCloud"
                },
                "3": {
                    "name": "EKS (GovCloud)",
                    "file": scripts_dir / "eks-export-gc.py",
                    "description": "Export EKS cluster information from GovCloud"
                },
                "4": {
                    "name": "All Compute Resources (GovCloud)",
                    "file": scripts_dir / "compute-resources-gc.py",
                    "description": "Export all compute resources (EC2, RDS, EKS) in one comprehensive report"
                },
                "5": {
                    "name": "Return to Main Menu",
                    "file": None,
                    "description": "Return to the main menu"
                }
            }
        },
        "3": {
            "name": "Network Resources",
            "submenu": {
                "1": {
                    "name": "VPC/Subnet (GovCloud)",
                    "file": scripts_dir / "vpc-data-export-gc.py",
                    "description": "Export VPC and subnet information from GovCloud"
                },
                "2": {
                    "name": "ELB (GovCloud)",
                    "file": scripts_dir / "elb-export-gc.py",
                    "description": "Export load balancer information from GovCloud"
                },
                "3": {
                    "name": "Network ACLs (GovCloud)",
                    "file": scripts_dir / "nacl-export-gc.py",
                    "description": "Export Network ACL information from GovCloud"
                },
                "4": {
                    "name": "Security Groups (GovCloud)",
                    "file": scripts_dir / "security-groups-export-gc.py",
                    "description": "Export security group rules and associations from GovCloud"
                },
                "5": {
                    "name": "All Network Resources (GovCloud)",
                    "file": scripts_dir / "network-resources-gc.py",
                    "description": "Export all network resources (VPC, ELB, NACLs, Security Groups) in one comprehensive report"
                },
                "6": {
                    "name": "Return to Main Menu",
                    "file": None,
                    "description": "Return to the main menu"
                }
            }
        },
        "4": {
            "name": "Identity and Access Management Resources",
            "submenu": {
                "1": {
                    "name": "IAM",
                    "description": "Traditional IAM resources (users, roles, policies)",
                    "submenu": {
                        "1": {
                            "name": "IAM Users (GovCloud)",
                            "file": scripts_dir / "iam-export-gc.py",
                            "description": "Export IAM user information, permissions, and security details from GovCloud"
                        },
                        "2": {
                            "name": "IAM Roles (GovCloud)",
                            "file": scripts_dir / "iam-roles-export-gc.py",
                            "description": "Export IAM role information, trust relationships, and usage patterns from GovCloud"
                        },
                        "3": {
                            "name": "IAM Policies (GovCloud)",
                            "file": scripts_dir / "iam-policies-export-gc.py",
                            "description": "Export IAM policy information, risk assessment, and compliance analysis from GovCloud"
                        },
                        "4": {
                            "name": "All the above",
                            "file": scripts_dir / "iam-comprehensive-export-gc.py",
                            "description": "Export all IAM resources (users, roles, policies) in one comprehensive report"
                        },
                        "5": {
                            "name": "Return to Previous Menu",
                            "file": None,
                            "description": "Return to the previous menu"
                        }
                    }
                },
                "2": {
                    "name": "IAM Identity Center",
                    "description": "IAM Identity Center (formerly AWS SSO) resources",
                    "submenu": {
                        "1": {
                            "name": "IAM Identity Center (GovCloud)",
                            "file": scripts_dir / "iam-identity-center-export-gc.py",
                            "description": "Export IAM Identity Center users, groups, and permission sets from GovCloud"
                        },
                        "2": {
                            "name": "IAM Identity Center Groups (GovCloud)",
                            "file": scripts_dir / "iam-identity-center-groups-export-gc.py",
                            "description": "Export IAM Identity Center groups with detailed member information from GovCloud"
                        },
                        "3": {
                            "name": "IAM Identity Center Comprehensive (GovCloud)",
                            "file": scripts_dir / "iam-identity-center-comprehensive-export-gc.py",
                            "description": "Export comprehensive IAM Identity Center data (users, groups, permission sets, assignments) in one report"
                        },
                        "4": {
                            "name": "Return to Previous Menu",
                            "file": None,
                            "description": "Return to the previous menu"
                        }
                    }
                },
                "3": {
                    "name": "Return to Main Menu",
                    "file": None,
                    "description": "Return to the main menu"
                }
            }
        },
        "5": {
            "name": "Output Management",
            "submenu": {
                "1": {
                    "name": "Create Output Archive",
                    "file": None,
                    "description": "Create a zip archive of all exported files",
                    "action": "create_archive"
                },
                "2": {
                    "name": "Return to Main Menu",
                    "file": None,
                    "description": "Return to the main menu"
                }
            }
        },
        "6": {
            "name": "Security Resources",
            "submenu": {
                "1": {
                    "name": "Security Hub (GovCloud)",
                    "file": scripts_dir / "security-hub-export-gc.py",
                    "description": "Export Security Hub findings with severity, compliance status, and remediation guidance from GovCloud"
                },
                "2": {
                    "name": "Return to Main Menu",
                    "file": None,
                    "description": "Return to the main menu"
                }
            }
        },
        "7": {
            "name": "Service Discovery",
            "file": scripts_dir / "services-in-use-export-gc.py",
            "description": "Discover all AWS services in use (both billing and non-billing services)"
        },
        "8": {
            "name": "Organizations",
            "file": scripts_dir / "organizations-export-gc.py",
            "description": "Export AWS Organizations structure, accounts, and organizational units"
        },
        "9": {
            "name": "Configure StratusScan",
            "file": Path(__file__).parent / "configure_govcloud.py",
            "description": "Interactive configuration tool for account mappings and GovCloud settings"
        }
    }
    
    # Verify the script files exist (only for actual scripts)
    for main_option, main_info in menu_structure.items():
        if "submenu" in main_info:
            for sub_option, sub_info in main_info["submenu"].items():
                if sub_info.get("file") and not sub_info["file"].exists():
                    print(f"Warning: Script file {sub_info['file']} for submenu option {main_option}.{sub_option} ({sub_info['name']}) not found!")
        elif main_info.get("file") and main_info["file"] is not None and not main_info["file"].exists():
            print(f"Warning: Script file {main_info['file']} for main menu option {main_option} ({main_info['name']}) not found!")
    
    return menu_structure

def display_main_menu():
    """
    Display the main menu with categories.
    
    Returns:
        tuple: (menu_structure, exit_option) - The menu structure and exit option
    """
    # Get the menu structure
    menu_structure = get_menu_structure()
    
    # Display the main menu options
    print("\nMAIN MENU:")
    print("====================================================================")
    
    for option, info in menu_structure.items():
        print(f"{option}. {info['name']}")
    
    # Add exit option
    exit_option = str(len(menu_structure) + 1)
    print(f"{exit_option}. Exit")
    
    return menu_structure, exit_option

def display_submenu(submenu, category_name):
    """
    Display a submenu for a specific category.
    
    Args:
        submenu (dict): The submenu options
        category_name (str): The name of the category
        
    Returns:
        dict: The submenu structure
    """
    # Clear the screen
    clear_screen()
    
    print(f"====================================================================")
    print(f"                  {category_name.upper()}")
    print(f"====================================================================")
    
    # Display the submenu options
    print("\nSelect an option:")
    for option, info in submenu.items():
        print(f"{option}. {info['name']} - {info['description']}")
    
    return submenu


def handle_submenu(category_option, account_name):
    """
    Handle the submenu navigation and script execution.
    
    Args:
        category_option (dict): The selected main menu option with submenu
        account_name (str): The AWS account name for archive creation
    """
    while True:
        # Display submenu for this category
        submenu = display_submenu(category_option["submenu"], category_option["name"])
        
        # Get user choice
        print("\nSelect an option:")
        user_choice = input("> ")
        
        # Handle return to main menu
        if user_choice in submenu:
            selected_option = submenu[user_choice]

            # Log submenu selection
            submenu_path = f"{category_option.get('name', 'Unknown')}.{user_choice}"
            utils.log_menu_selection(submenu_path, selected_option['name'])

            # Check if this is the "Return to Main Menu" or "Return to Previous Menu" option
            if selected_option["name"] in ["Return to Main Menu", "Return to Previous Menu"]:
                utils.log_info(f"User selected: {selected_option['name']}")
                return

            # Check if this option has its own submenu (nested submenu)
            if "submenu" in selected_option:
                handle_submenu(selected_option, account_name)
                continue

            # Check if this is a special action (like Create Output Archive)
            if selected_option.get("action") == "create_archive":
                print(f"\nYou selected: {selected_option['name']} - {selected_option['description']}")
                
                # Confirm execution
                confirm = input("Do you want to continue? (y/n): ").lower()
                if confirm == 'y':
                    create_output_archive(account_name)
                    # Ask if user wants to perform another action from this submenu
                    another = input("\nWould you like to perform another action from this menu? (y/n): ").lower()
                    if another != 'y':
                        return  # Return to main menu
                continue
            
            # Handle regular script execution
            print(f"\nYou selected: {selected_option['name']} - {selected_option['description']}")
            
            # Special handling for Compute Optimizer in GovCloud
            if "Compute Optimizer" in selected_option["name"]:
                print("\nNOTE: AWS Compute Optimizer has limited availability in GovCloud.")
                print("Some recommendations may not be available in your region.")
            
            # Confirm execution
            confirm = input("Do you want to continue? (y/n): ").lower()
            if confirm == 'y':
                # Execute the script
                if selected_option["file"]:
                    success = execute_script(selected_option["file"])
                    
                    # Ask if user wants to run another tool from this submenu
                    another = input("\nWould you like to run another tool from this menu? (y/n): ").lower()
                    if another != 'y':
                        return  # Return to main menu
                
            # If user didn't confirm, stay in the submenu
        
        else:
            print("Invalid selection. Please try again.")

def navigate_menus():
    """
    Display the main menu and handle user navigation through nested menus.
    """
    try:
        # Print header and get account information
        account_id, account_name = print_header()
        
        # Check dependencies
        if not check_dependencies():
            print("Required dependencies are missing. Please install them to continue.")
            sys.exit(1)
        
        # Ensure directory structure
        ensure_directory_structure()
        
        # Main menu loop
        while True:
            # Get menu structure
            menu_structure, exit_option = display_main_menu()
            
            if not menu_structure:
                print("\nNo scripts found in the mapping. Please ensure script files exist in the scripts directory.")
                sys.exit(1)
            
            print("\nSelect an option:")
            user_choice = input("> ")
            
            # Exit option
            if user_choice == exit_option:
                clear_screen()
                print("Exiting StratusScan GovCloud. Thank you for using the tool.")
                break
            
            # Main menu option
            elif user_choice in menu_structure:
                selected_option = menu_structure[user_choice]

                # Log menu selection
                utils.log_menu_selection(user_choice, selected_option['name'])

                # If it's a direct script (like Create Output Archive or Configure StratusScan)
                if "file" in selected_option and "submenu" not in selected_option:
                    print(f"\nYou selected: {selected_option['name']} - {selected_option['description']}")

                    # Confirm execution
                    confirm = input("Do you want to continue? (y/n): ").lower()
                    if confirm == 'y':
                        utils.log_info(f"User confirmed execution of: {selected_option['name']}")
                        # Handle special case for creating output archive
                        if selected_option["name"] == "Create Output Archive":
                            create_output_archive(account_name)
                        # Handle Configure StratusScan
                        elif selected_option["name"] == "Configure StratusScan":
                            if selected_option["file"]:
                                success = execute_script(selected_option["file"])
                                if success:
                                    print("\nConfiguration completed successfully!")
                                    print("You may need to restart StratusScan for changes to take effect.")
                                else:
                                    print("\nConfiguration may not have completed successfully.")
                        # Handle other direct scripts
                        elif selected_option.get("file"):
                            execute_script(selected_option["file"])
                
                # If it's a submenu
                elif "submenu" in selected_option:
                    # Display the submenu and handle selection
                    handle_submenu(selected_option, account_name)
            
            else:
                print("Invalid selection. Please try again.")
    
    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

def main():
    """
    Main function to display the menu and handle script execution.
    """
    try:
        utils.log_section("STARTING MAIN MENU NAVIGATION")
        navigate_menus()
    except KeyboardInterrupt:
        utils.log_info("User cancelled operation with Ctrl+C")
        print("\nOperation cancelled by user.")
        sys.exit(0)
    except Exception as e:
        print(f"Error in main function: {e}")
        utils.log_error("Error in main function", e)
        sys.exit(1)
    finally:
        # Log script completion
        utils.log_script_end("stratusscan-govcloud.py", SCRIPT_START_TIME)

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        utils.log_error("Fatal error in main execution", e)
        sys.exit(1)