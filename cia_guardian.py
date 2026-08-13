#!/usr/bin/env python3
"""
CIA-Guardian v2.3 - Windows Security Hardening Tool
Main CLI Entrypoint

v2.3 Features:
  - 10 new enterprise security controls (100 total):
    * INTG-21: Windows Exploit Protection
    * INTG-22: Controlled Folder Access (Ransomware Protection)
    * INTG-23: Early Launch Anti-Malware (ELAM)
    * CONF-20: Windows LAPS (Native)
    * CONF-21: Kerberos Armoring (FAST)
    * NETW-14: SMB 3.0 Encryption
    * NETW-15: Windows Firewall Advanced Logging
    * AVBL-18: Backup Configuration
    * APPS-12: PowerShell Constrained Language Mode
    * SRVC-11: RD Gateway Requirement

v2.2 Features:
  - 5 new enterprise security controls (90 total):
    * INTG-19: Attack Surface Reduction (ASR) Rules
    * INTG-20: VBS/HVCI Memory Integrity
    * NETW-13: DNS over HTTPS (DoH)
    * APPS-11: WDAC/AppLocker Application Whitelisting
    * CONF-19: Windows Hello for Business

v2.1 Features:
  - Parallel execution for 5-6x speedup (default mode)
  - Background SFC execution with configurable timeout
  - Enhanced progress reporting with category-based progress bars

Usage:
    python cia_guardian.py [--interactive] [--dry-run] [--report-only] [--output DIR]

Options:
    --interactive   Launch interactive menu mode
    --dry-run       Audit only, no remediation
    --report-only   Skip hardening, generate report from existing state
    --output DIR    Report destination (default: ./reports/)
    --formats       Report formats: html,pdf,json,csv (default: html,pdf)
    --categories    Categories to audit (confidentiality,integrity,availability,network,application,services)
    --sequential    Disable parallel execution (use sequential mode)
    --workers N     Number of parallel worker threads (default: 8)
    --sfc-timeout N SFC timeout in seconds (default: 2700 = 45 min)
    --skip-sfc      Skip SFC scan (INTG-05) entirely for faster audits
    --no-sfc-background  Run SFC synchronously instead of in background
    --progress-style STYLE  Progress display style: box, simple, minimal, ascii, auto
    --verbose       Enable verbose output
    --help          Show this help message
"""

import argparse
import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def check_requirements():
    """Check if required dependencies are installed."""
    missing = []
    
    try:
        import jinja2
    except ImportError:
        missing.append('jinja2')
    
    try:
        import fpdf
    except ImportError:
        missing.append('fpdf2')
    
    try:
        import colorama
    except ImportError:
        missing.append('colorama')
    
    try:
        import tabulate
    except ImportError:
        missing.append('tabulate')
    
    if missing:
        print(f"[!] Missing dependencies: {', '.join(missing)}")
        print(f"    Install with: pip install {' '.join(missing)}")
        return False
    return True


def check_admin():
    """Check for administrator privileges on Windows."""
    if sys.platform != 'win32':
        print("[!] CIA-Guardian is designed for Windows systems only.")
        return False
    
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def clear_screen():
    """Clear the console screen."""
    os.system('cls' if os.name == 'nt' else 'clear')


def print_banner():
    """Print the CIA-Guardian banner."""
    banner = """
    ╔═══════════════════════════════════════════════════════════════════╗
    ║                                                                   ║
    ║      ██████╗██╗ █████╗        ██████╗ ██╗   ██╗ █████╗ ██████╗    ║
    ║     ██╔════╝██║██╔══██╗      ██╔════╝ ██║   ██║██╔══██╗██╔══██╗   ║
    ║     ██║     ██║███████║█████╗██║  ███╗██║   ██║███████║██████╔╝   ║
    ║     ██║     ██║██╔══██║╚════╝██║   ██║██║   ██║██╔══██║██╔══██╗   ║
    ║     ╚██████╗██║██║  ██║      ╚██████╔╝╚██████╔╝██║  ██║██║  ██║   ║
    ║      ╚═════╝╚═╝╚═╝  ╚═╝       ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝   ║
    ║                                                                   ║
    ║              Windows Security Hardening Tool v2.3                 ║
    ║         100 Controls | Parallel Execution | Background SFC       ║
    ║     Confidentiality | Integrity | Availability | Network        ║
    ║              Application Security | Service Hardening            ║
    ║                                                                   ║
    ║         Developed by: https://github.com/razzsecdev              ║
    ║                                                                   ║
    ╚═══════════════════════════════════════════════════════════════════╝
    """
    print(banner)


def print_menu_header(title):
    """Print a formatted menu header."""
    print("\n" + "=" * 65)
    print(f"  {title}")
    print("=" * 65)


def print_option(number, title, description):
    """Print a formatted menu option with description."""
    print(f"\n  [{number}] {title}")
    print(f"      {description}")


def get_user_choice(prompt, valid_options, default=None):
    """
    Get and validate user input.
    
    Args:
        prompt: Input prompt to display
        valid_options: List of valid input values
        default: Default value if user presses Enter (optional)
    """
    while True:
        try:
            choice = input(f"\n{prompt}").strip()
            if choice.lower() == 'q':
                return 'q'
            # Handle empty input with default
            if choice == '' and default is not None:
                return default
            if choice in valid_options or choice.lower() in [v.lower() for v in valid_options]:
                return choice
            print(f"  [!] Invalid choice. Please enter one of: {', '.join(valid_options)}")
        except KeyboardInterrupt:
            return 'q'


def interactive_mode():
    """Run CIA-Guardian in interactive menu mode."""
    clear_screen()
    print_banner()
    
    # Check admin status
    is_admin = check_admin()
    admin_status = "[ADMIN]" if is_admin else "[USER]"
    print(f"\n  Status: {admin_status} Running as {'Administrator' if is_admin else 'Standard User'}")
    
    if not is_admin:
        print("\n  [!] WARNING: Some features require Administrator privileges.")
        print("      For full functionality, run as Administrator.")
    
    # Main menu loop
    while True:
        print_menu_header("MAIN MENU - Select Operation Mode")
        
        print_option("1", "Full Security Audit + Auto-Remediation",
                    "Scan all security controls and automatically fix non-compliant items.")
        
        print_option("2", "Audit Only (Dry Run)",
                    "Scan and report security status without making any changes to the system.")
        
        print_option("3", "Report Only (Quick Scan)",
                    "Generate reports from current system state with minimal scanning.")
        
        print_option("4", "Custom Audit",
                    "Choose specific categories and options for a customized audit.")
        
        print_option("5", "Individual Control Selection",
                    "Select specific controls (e.g., CONF-01, INTG-02) to audit.")
        
        print_option("6", "View Security Controls",
                    "Display all available security controls with descriptions.")
        
        print_option("7", "Rollback Changes",
                    "Revert previous remediation changes (if backups available).")
        
        print_option("Q", "Quit",
                    "Exit CIA-Guardian.")
        
        print("\n" + "-" * 65)
        choice = get_user_choice("  Enter your choice [1-7, Q]: ", ['1', '2', '3', '4', '5', '6', '7', 'q', 'Q'])
        
        if choice.lower() == 'q':
            print("\n  [*] Thank you for using CIA-Guardian. Stay secure!\n")
            return None
        
        if choice == '1':
            return run_full_audit_menu()
        elif choice == '2':
            return run_dry_run_menu()
        elif choice == '3':
            return run_report_only_menu()
        elif choice == '4':
            return run_custom_audit_menu()
        elif choice == '5':
            return run_individual_control_menu()
        elif choice == '6':
            show_controls_info()
        elif choice == '7':
            run_rollback_menu()


def run_full_audit_menu():
    """Menu for full audit with remediation."""
    clear_screen()
    print_banner()
    print_menu_header("FULL SECURITY AUDIT + AUTO-REMEDIATION")
    
    print("""
  This mode will:
    - Scan all 90 security controls across 6 categories
    - Automatically remediate (fix) any non-compliant controls
    - Verify fixes were applied successfully
    - Generate comprehensive reports (HTML + PDF)

  Categories included (90 controls total):
    [C] Confidentiality (19) - BitLocker, SMB1, Admin Shares, Credentials, Hello...
    [I] Integrity (20)       - Defender, UAC, PowerShell, LSA, ASR, VBS/HVCI...
    [A] Availability (17)    - Firewall, VSS, Password Policy, Windows Update...
    [N] Network (13)         - RDP Settings, NetBIOS, IPv6, WinRM, DoH...
    [P] Application (11)     - Office Macros, TLS/SSL, Browser, WDAC/AppLocker...
    [S] Services (10)        - Print Spooler, Remote Desktop, Telnet, Bluetooth...

  [!] WARNING: This mode WILL make changes to your system configuration.
  [!] Ensure you have proper authorization before proceeding.
    """)
    
    choice = get_user_choice("  Proceed with Full Audit? [Y/N]: ", ['y', 'Y', 'n', 'N'])
    
    if choice.lower() == 'y':
        formats = select_report_formats()
        output_dir = select_output_directory()
        
        # v2.1: Execution options (sequential only for remediation, but can skip SFC)
        exec_options = select_execution_options(allow_parallel=False, total_controls=90)
        
        return {
            'mode': 'full',
            'dry_run': False,
            'categories': ['confidentiality', 'integrity', 'availability', 'network', 'application', 'services'],
            'formats': formats,
            'output': output_dir,
            'parallel': False,  # Always sequential for remediation
            'skip_sfc': exec_options['skip_sfc']
        }
    return None


def run_dry_run_menu():
    """Menu for audit-only (dry run) mode."""
    clear_screen()
    print_banner()
    print_menu_header("AUDIT ONLY (DRY RUN)")
    
    print("""
  This mode will:
    - Scan all 90 security controls and report their status
    - NOT make any changes to your system
    - Show what WOULD be remediated if you ran a full audit
    - Generate comprehensive reports

  This is the SAFE mode for:
    - Initial assessment of system security posture
    - Compliance checking without modification
    - Understanding current vulnerabilities
    - Pre-change impact analysis
    """)
    
    choice = get_user_choice("  Proceed with Audit Only? [Y/N]: ", ['y', 'Y', 'n', 'N'])
    
    if choice.lower() == 'y':
        formats = select_report_formats()
        output_dir = select_output_directory()
        
        # v2.1: Execution options
        exec_options = select_execution_options(allow_parallel=True, total_controls=90)
        
        return {
            'mode': 'dry_run',
            'dry_run': True,
            'categories': ['confidentiality', 'integrity', 'availability', 'network', 'application', 'services'],
            'formats': formats,
            'output': output_dir,
            'parallel': exec_options['parallel'],
            'skip_sfc': exec_options['skip_sfc']
        }
    return None


def run_report_only_menu():
    """Menu for report-only mode."""
    clear_screen()
    print_banner()
    print_menu_header("REPORT ONLY (QUICK SCAN)")
    
    print("""
  This mode will:
    - Perform a quick scan of current system state
    - Generate reports without detailed control testing
    - Useful for documentation and baseline reporting
    - Fastest execution time

  Best for:
    - Generating documentation quickly
    - Creating baseline reports
    - System inventory and status snapshots
    """)
    
    choice = get_user_choice("  Proceed with Report Only? [Y/N]: ", ['y', 'Y', 'n', 'N'])
    
    if choice.lower() == 'y':
        formats = select_report_formats()
        output_dir = select_output_directory()
        
        # v2.1: Execution options (parallel allowed for report-only)
        exec_options = select_execution_options(allow_parallel=True, total_controls=90)
        
        return {
            'mode': 'report_only',
            'dry_run': True,
            'report_only': True,
            'categories': ['confidentiality', 'integrity', 'availability', 'network', 'application', 'services'],
            'formats': formats,
            'output': output_dir,
            'parallel': exec_options['parallel'],
            'skip_sfc': exec_options['skip_sfc']
        }
    return None


def run_custom_audit_menu():
    """Menu for custom audit configuration."""
    clear_screen()
    print_banner()
    print_menu_header("CUSTOM AUDIT CONFIGURATION")
    
    # Select categories
    print("\n  STEP 1: Select Categories to Audit")
    print("  " + "-" * 40)
    print_option("1", "All Categories (90 controls)",
                "Audit all 6 security categories")
    print_option("2", "CIA Triad Only (56 controls)",
                "Confidentiality, Integrity, and Availability")
    print_option("3", "Confidentiality Only (19 controls)",
                "BitLocker, SMB, Credentials, Hello, AutoRun...")
    print_option("4", "Integrity Only (20 controls)",
                "Defender, UAC, PowerShell, LSA, ASR, HVCI...")
    print_option("5", "Availability Only (17 controls)",
                "Firewall, VSS, Password Policy, Windows Update...")
    print_option("6", "Network Only (13 controls)",
                "RDP, NetBIOS, IPv6, WinRM, DoH...")
    print_option("7", "Application Only (11 controls)",
                "Office Macros, TLS/SSL, Browser, WDAC...")
    print_option("8", "Services Only (10 controls)",
                "Print Spooler, Remote Desktop, Telnet, Bluetooth...")
    print_option("9", "Custom Selection",
                "Choose specific categories manually")
    
    cat_choice = get_user_choice("  Select category option [1-9]: ", ['1', '2', '3', '4', '5', '6', '7', '8', '9'])
    
    if cat_choice == '1':
        categories = ['confidentiality', 'integrity', 'availability', 'network', 'application', 'services']
    elif cat_choice == '2':
        categories = ['confidentiality', 'integrity', 'availability']
    elif cat_choice == '3':
        categories = ['confidentiality']
    elif cat_choice == '4':
        categories = ['integrity']
    elif cat_choice == '5':
        categories = ['availability']
    elif cat_choice == '6':
        categories = ['network']
    elif cat_choice == '7':
        categories = ['application']
    elif cat_choice == '8':
        categories = ['services']
    elif cat_choice == '9':
        categories = []
        print("\n  Select categories (enter Y/N for each):")
        if get_user_choice("    Include Confidentiality (19)? [Y/N]: ", ['y', 'Y', 'n', 'N']).lower() == 'y':
            categories.append('confidentiality')
        if get_user_choice("    Include Integrity (20)? [Y/N]: ", ['y', 'Y', 'n', 'N']).lower() == 'y':
            categories.append('integrity')
        if get_user_choice("    Include Availability (17)? [Y/N]: ", ['y', 'Y', 'n', 'N']).lower() == 'y':
            categories.append('availability')
        if get_user_choice("    Include Network (13)? [Y/N]: ", ['y', 'Y', 'n', 'N']).lower() == 'y':
            categories.append('network')
        if get_user_choice("    Include Application (11)? [Y/N]: ", ['y', 'Y', 'n', 'N']).lower() == 'y':
            categories.append('application')
        if get_user_choice("    Include Services (10)? [Y/N]: ", ['y', 'Y', 'n', 'N']).lower() == 'y':
            categories.append('services')
        if not categories:
            print("  [!] No categories selected. Returning to main menu.")
            input("  Press Enter to continue...")
            return None
    else:
        return None
    
    # Select mode
    print("\n  STEP 2: Select Audit Mode")
    print("  " + "-" * 40)
    print_option("1", "Full Audit + Remediation",
                "Scan and automatically fix non-compliant controls")
    print_option("2", "Audit Only (No Changes)",
                "Scan and report only, no system modifications")
    
    mode_choice = get_user_choice("  Select mode [1-2]: ", ['1', '2'])
    dry_run = mode_choice == '2'
    
    # Select report formats
    formats = select_report_formats()
    
    # Select output directory
    output_dir = select_output_directory()
    
    # v2.2: Calculate total controls based on selected categories
    category_counts = {
        'confidentiality': 19,
        'integrity': 20,
        'availability': 17,
        'network': 13,
        'application': 11,
        'services': 10
    }
    total_controls = sum(category_counts.get(cat, 0) for cat in categories)
    
    # v2.1: Execution options (parallel only for dry-run/audit mode)
    exec_options = select_execution_options(allow_parallel=dry_run, total_controls=total_controls)
    
    # Confirm
    print("\n  CONFIGURATION SUMMARY")
    print("  " + "-" * 40)
    print(f"  Categories: {', '.join(c.title() for c in categories)}")
    actual_controls = total_controls - 1 if exec_options['skip_sfc'] else total_controls
    print(f"  Controls: {actual_controls}" + (" (skipping SFC)" if exec_options['skip_sfc'] else ""))
    print(f"  Mode: {'Audit Only' if dry_run else 'Full Audit + Remediation'}")
    print(f"  Execution: {'Parallel' if exec_options['parallel'] else 'Sequential'}")
    print(f"  Report Formats: {', '.join(f.upper() for f in formats)}")
    print(f"  Output Directory: {output_dir}")
    
    choice = get_user_choice("\n  Proceed with this configuration? [Y/N]: ", ['y', 'Y', 'n', 'N'])
    
    if choice.lower() == 'y':
        return {
            'mode': 'custom',
            'dry_run': dry_run,
            'categories': categories,
            'formats': formats,
            'output': output_dir,
            'parallel': exec_options['parallel'],
            'skip_sfc': exec_options['skip_sfc']
        }
    return None


def run_individual_control_menu():
    """Menu for selecting individual controls to audit."""
    clear_screen()
    print_banner()
    print_menu_header("INDIVIDUAL CONTROL SELECTION")
    
    # Display all available controls
    print("""
  Available Security Controls (90 total):
  
  CONFIDENTIALITY (21 controls):
    CONF-01  BitLocker Encryption              CONF-11  Cached Logons Limited
    CONF-02  SMB1 Protocol Disabled            CONF-12  LM Hash Storage Disabled
    CONF-03  Administrative Shares Disabled    CONF-13  Anonymous SID Enumeration
    CONF-04  SMB Signing Required              CONF-14  Anonymous Share Enumeration
    CONF-05  NTLM Restricted                   CONF-15  Remote SAM Access
    CONF-06  WDigest Disabled                  CONF-16  Null Session Pipes
    CONF-07  LLMNR Disabled                    CONF-17  AutoRun Disabled
    CONF-08  NetBIOS Name Release              CONF-18  Removable Media Access
    CONF-09  Credential Delegation Disabled    CONF-19  Windows Hello for Business
    CONF-10  Guest Account Disabled            CONF-20  Windows LAPS (Native)
                                               CONF-21  Kerberos Armoring (FAST)
  
  INTEGRITY (23 controls):
    INTG-01  Defender Real-time Protection     INTG-13  Object Access Audit
    INTG-02  UAC Configuration                 INTG-14  Privilege Use Audit
    INTG-03  PowerShell Execution Policy       INTG-15  Policy Change Audit
    INTG-04  Logon Audit Policy                INTG-16  SEHOP Enabled
    INTG-05  System File Integrity (SFC)       INTG-17  DEP/NX Enabled
    INTG-06  LSA Protection (RunAsPPL)         INTG-18  ASLR Enabled
    INTG-07  Credential Guard                  INTG-19  ASR Rules (Attack Surface)
    INTG-08  Secure Boot                       INTG-20  VBS/HVCI Memory Integrity
    INTG-09  Driver Signature Enforcement      INTG-21  Windows Exploit Protection
    INTG-10  PowerShell Script Block Log       INTG-22  Controlled Folder Access
    INTG-11  PowerShell Transcription          INTG-23  Early Launch Anti-Malware
    INTG-12  Command Line Auditing
  
  AVAILABILITY (18 controls):
    AVBL-01  Windows Firewall                  AVBL-10  Password Maximum Age
    AVBL-02  Volume Shadow Copy Service        AVBL-11  Windows Update Service
    AVBL-03  Virtual Memory Configuration      AVBL-12  Windows Defender Service
    AVBL-04  Windows Time Service              AVBL-13  BITS Service
    AVBL-05  Password Minimum Length           AVBL-14  Event Log Service
    AVBL-06  Password Complexity               AVBL-15  Crash Dump Configuration
    AVBL-07  Account Lockout Threshold         AVBL-16  Auto Restart Sign-on
    AVBL-08  Account Lockout Duration          AVBL-17  Screen Saver Timeout
    AVBL-09  Password History                  AVBL-18  Backup Configuration
  
  NETWORK (15 controls):
    NETW-01  RDP Network Level Auth            NETW-09  ICMP Redirects Disabled
    NETW-02  RDP Encryption Level              NETW-10  Source Routing Disabled
    NETW-03  RDP Idle Timeout                  NETW-11  IRDP Disabled
    NETW-04  NetBIOS over TCP/IP Disabled      NETW-12  DNS Multicast Disabled
    NETW-05  WPAD Disabled                     NETW-13  DNS over HTTPS (DoH)
    NETW-06  IPv6 Disabled                     NETW-14  SMB 3.0 Encryption
    NETW-07  Remote Registry Disabled          NETW-15  Firewall Advanced Logging
    NETW-08  WinRM Disabled/Secure
  
  APPLICATION (12 controls):
    APPS-01  Office Macros Disabled            APPS-07  .NET Strong Cryptography
    APPS-02  Office OLE Disabled               APPS-08  TLS 1.0/1.1 Disabled
    APPS-03  Adobe Reader Protected Mode       APPS-09  SSL 2.0/3.0 Disabled
    APPS-04  Browser Extensions Audit          APPS-10  Certificate Padding Check
    APPS-05  Java Browser Plugin Disabled      APPS-11  WDAC/AppLocker Whitelisting
    APPS-06  Flash Player Disabled             APPS-12  PowerShell Constrained Lang
  
  SERVICES (11 controls):
    SRVC-01  Print Spooler Disabled            SRVC-07  WMP Network Sharing
    SRVC-02  SSDP Discovery Disabled           SRVC-08  Xbox Services Disabled
    SRVC-03  UPnP Host Disabled                SRVC-09  Fax Service Disabled
    SRVC-04  Remote Desktop Disabled           SRVC-10  Bluetooth Disabled
    SRVC-05  Telnet Client Disabled            SRVC-11  RD Gateway Requirement
    SRVC-06  TFTP Client Disabled
    """)
    
    print("  " + "-" * 65)
    print("  Enter control IDs separated by commas (e.g., CONF-01,INTG-02,AVBL-01)")
    print("  Or type 'ALL' to select all controls")
    print("  Or type 'BACK' to return to main menu")
    print("  " + "-" * 65)
    
    selection = input("\n  Control IDs: ").strip().upper()
    
    if selection == 'BACK' or not selection:
        return None
    
    # Parse control IDs
    if selection == 'ALL':
        control_ids = None  # None means all controls
    else:
        # Parse comma-separated list
        control_ids = [cid.strip() for cid in selection.split(',') if cid.strip()]
        
        # Validate control IDs - all 100 controls
        valid_ids = [
            # Confidentiality (21)
            'CONF-01', 'CONF-02', 'CONF-03', 'CONF-04', 'CONF-05', 'CONF-06',
            'CONF-07', 'CONF-08', 'CONF-09', 'CONF-10', 'CONF-11', 'CONF-12',
            'CONF-13', 'CONF-14', 'CONF-15', 'CONF-16', 'CONF-17', 'CONF-18',
            'CONF-19', 'CONF-20', 'CONF-21',
            # Integrity (23)
            'INTG-01', 'INTG-02', 'INTG-03', 'INTG-04', 'INTG-05', 'INTG-06',
            'INTG-07', 'INTG-08', 'INTG-09', 'INTG-10', 'INTG-11', 'INTG-12',
            'INTG-13', 'INTG-14', 'INTG-15', 'INTG-16', 'INTG-17', 'INTG-18',
            'INTG-19', 'INTG-20', 'INTG-21', 'INTG-22', 'INTG-23',
            # Availability (18)
            'AVBL-01', 'AVBL-02', 'AVBL-03', 'AVBL-04', 'AVBL-05', 'AVBL-06',
            'AVBL-07', 'AVBL-08', 'AVBL-09', 'AVBL-10', 'AVBL-11', 'AVBL-12',
            'AVBL-13', 'AVBL-14', 'AVBL-15', 'AVBL-16', 'AVBL-17', 'AVBL-18',
            # Network (15)
            'NETW-01', 'NETW-02', 'NETW-03', 'NETW-04', 'NETW-05', 'NETW-06',
            'NETW-07', 'NETW-08', 'NETW-09', 'NETW-10', 'NETW-11', 'NETW-12',
            'NETW-13', 'NETW-14', 'NETW-15',
            # Application (12)
            'APPS-01', 'APPS-02', 'APPS-03', 'APPS-04', 'APPS-05',
            'APPS-06', 'APPS-07', 'APPS-08', 'APPS-09', 'APPS-10',
            'APPS-11', 'APPS-12',
            # Services (11)
            'SRVC-01', 'SRVC-02', 'SRVC-03', 'SRVC-04', 'SRVC-05',
            'SRVC-06', 'SRVC-07', 'SRVC-08', 'SRVC-09', 'SRVC-10', 'SRVC-11'
        ]
        
        invalid_ids = [cid for cid in control_ids if cid not in valid_ids]
        if invalid_ids:
            print(f"\n  [!] Invalid control IDs: {', '.join(invalid_ids)}")
            print("      Please check the control IDs and try again.")
            input("\n  Press Enter to continue...")
            return None
        
        if not control_ids:
            print("\n  [!] No valid control IDs entered.")
            input("\n  Press Enter to continue...")
            return None
    
    # Select mode
    print("\n  Select Audit Mode:")
    print("  " + "-" * 40)
    print_option("1", "Full Audit + Remediation",
                "Scan and automatically fix non-compliant controls")
    print_option("2", "Audit Only (No Changes)",
                "Scan and report only, no system modifications")
    
    mode_choice = get_user_choice("  Select mode [1-2]: ", ['1', '2'])
    dry_run = mode_choice == '2'
    
    # Select report formats
    formats = select_report_formats()
    
    # Select output directory
    output_dir = select_output_directory()
    
    # v2.2: Calculate total controls and check if INTG-05 is included
    total_controls = len(control_ids) if control_ids else 90
    has_sfc = control_ids is None or 'INTG-05' in control_ids
    
    # v2.1: Execution options (parallel only for dry-run, SFC skip only if INTG-05 selected)
    if has_sfc:
        exec_options = select_execution_options(allow_parallel=dry_run, total_controls=total_controls)
    else:
        # No SFC in selection, just show execution mode (if applicable)
        exec_options = {'parallel': dry_run, 'skip_sfc': False}
        if dry_run:
            print("\n  EXECUTION OPTIONS (v2.1)")
            print("  " + "-" * 45)
            print("\n  Select Execution Mode:")
            print_option("1", "Parallel (FAST - Recommended)",
                        "Run controls concurrently for ~5x speedup")
            print_option("2", "Sequential (DETAILED)",
                        "Run controls one-by-one with verbose output")
            
            exec_choice = get_user_choice("  Select execution mode [1-2] (default=1): ",
                                           ['1', '2', ''], default='1')
            exec_options['parallel'] = (exec_choice != '2')
            
            if exec_options['parallel']:
                print("  [i] Using Parallel Execution")
            else:
                print("  [i] Using Sequential Execution")
        else:
            print("\n  [i] Execution Mode: Sequential (required for remediation)")
    
    # Confirm
    print("\n  CONFIGURATION SUMMARY")
    print("  " + "-" * 40)
    if control_ids:
        display_controls = total_controls - 1 if (exec_options['skip_sfc'] and has_sfc) else total_controls
        print(f"  Controls: {', '.join(control_ids[:5])}" + (f"... (+{len(control_ids)-5} more)" if len(control_ids) > 5 else ""))
        print(f"  Total: {display_controls} control(s)" + (" (skipping SFC)" if exec_options['skip_sfc'] else ""))
    else:
        display_controls = 90 - 1 if exec_options['skip_sfc'] else 90
        print(f"  Controls: ALL ({display_controls} controls)" + (" - skipping SFC" if exec_options['skip_sfc'] else ""))
    print(f"  Mode: {'Audit Only' if dry_run else 'Full Audit + Remediation'}")
    print(f"  Execution: {'Parallel' if exec_options['parallel'] else 'Sequential'}")
    print(f"  Report Formats: {', '.join(f.upper() for f in formats)}")
    print(f"  Output Directory: {output_dir}")
    
    choice = get_user_choice("\n  Proceed with this configuration? [Y/N]: ", ['y', 'Y', 'n', 'N'])
    
    if choice.lower() == 'y':
        return {
            'mode': 'individual',
            'dry_run': dry_run,
            'control_ids': control_ids,
            'formats': formats,
            'output': output_dir,
            'parallel': exec_options['parallel'],
            'skip_sfc': exec_options['skip_sfc']
        }
    return None


def run_rollback_menu():
    """Menu for rolling back previous remediation changes."""
    clear_screen()
    print_banner()
    print_menu_header("ROLLBACK CHANGES")
    
    print("""
  This feature allows you to revert remediation changes made during an audit.
  
  [!] NOTE: Rollback is only available for:
      - Controls that were remediated in the CURRENT session
      - Controls that support backup/rollback functionality
      - Changes that haven't been overwritten by other operations
  
  To use rollback:
      1. First run an audit with remediation in this session
      2. Return to this menu to view and rollback changes
    """)
    
    # Try to get rollback info from a running engine
    # Note: In the current implementation, we'd need to pass the engine instance
    # For now, show informational message
    
    print("  " + "-" * 55)
    print("  Currently, rollback requires running an audit first in this session.")
    print("  After remediation, backups will be available here.")
    print("  " + "-" * 55)
    
    # If we had access to the engine, we'd do:
    # engine = get_global_engine()  # hypothetical
    # rollback_info = engine.get_rollback_info()
    # if rollback_info:
    #     for info in rollback_info:
    #         print(f"  {info['control_id']}: {info['name']}")
    # else:
    #     print("  No backups available for rollback.")
    
    input("\n  Press Enter to return to main menu...")
    return None


def select_report_formats():
    """Interactive menu to select report formats."""
    print("\n  STEP 3: Select Report Formats")
    print("  " + "-" * 40)
    print_option("1", "HTML + PDF (Recommended)",
                "Interactive HTML dashboard and formal PDF certificate")
    print_option("2", "All Formats",
                "HTML, PDF, JSON, and CSV exports")
    print_option("3", "HTML Only",
                "Interactive web dashboard with charts")
    print_option("4", "PDF Only",
                "Formal security certification document")
    print_option("5", "Data Export Only",
                "JSON and CSV for data analysis")
    
    fmt_choice = get_user_choice("  Select format option [1-5]: ", ['1', '2', '3', '4', '5'])
    
    format_map = {
        '1': ['html', 'pdf'],
        '2': ['html', 'pdf', 'json', 'csv'],
        '3': ['html'],
        '4': ['pdf'],
        '5': ['json', 'csv']
    }
    
    return format_map.get(fmt_choice, ['html', 'pdf'])


def select_output_directory():
    """Interactive menu to select output directory."""
    print("\n  STEP 4: Select Output Directory")
    print("  " + "-" * 40)
    default_dir = os.path.abspath('./reports')
    print(f"  Default: {default_dir}")
    
    choice = get_user_choice("  Use default directory? [Y/N]: ", ['y', 'Y', 'n', 'N'])
    
    if choice.lower() == 'y':
        return default_dir
    
    custom_dir = input("  Enter custom directory path: ").strip()
    if custom_dir:
        return os.path.abspath(custom_dir)
    return default_dir


def select_execution_options(allow_parallel=True, total_controls=85):
    """
    Interactive menu to select execution options (v2.1).
    
    Args:
        allow_parallel: If False, force sequential (for remediation modes)
        total_controls: Total controls being audited (for skip-sfc message)
    
    Returns:
        dict with 'parallel', 'skip_sfc' keys
    """
    print("\n  EXECUTION OPTIONS (v2.1)")
    print("  " + "-" * 45)
    
    options = {
        'parallel': True,
        'skip_sfc': False
    }
    
    # Execution mode selection (only if parallel is allowed)
    if allow_parallel:
        print("\n  Select Execution Mode:")
        print_option("1", "Parallel (FAST - Recommended)",
                    "Run controls concurrently for ~5x speedup")
        print_option("2", "Sequential (DETAILED)",
                    "Run controls one-by-one with verbose output")
        
        exec_choice = get_user_choice("  Select execution mode [1-2] (default=1): ",
                                       ['1', '2', ''], default='1')
        options['parallel'] = (exec_choice != '2')
        
        if options['parallel']:
            print("  [i] Using Parallel Execution")
        else:
            print("  [i] Using Sequential Execution")
    else:
        print("\n  [i] Execution Mode: Sequential (required for remediation)")
        options['parallel'] = False
    
    # Skip SFC option
    print("\n  SFC Scan Option (INTG-05 - System File Checker):")
    print("  " + "-" * 45)
    print("  SFC verifies Windows system file integrity.")
    print("  This scan typically takes 15-30+ minutes to complete.")
    print()
    print_option("N", "Include SFC (Recommended)",
                f"Thorough audit - all {total_controls} controls")
    print_option("Y", "Skip SFC (Faster)",
                f"Faster audit - {total_controls - 1} controls (skips INTG-05)")
    
    sfc_choice = get_user_choice("  Skip SFC scan? [Y/N] (default=N): ",
                                  ['y', 'Y', 'n', 'N', ''], default='n')
    options['skip_sfc'] = (sfc_choice.lower() == 'y')
    
    if options['skip_sfc']:
        print(f"  [i] SFC scan will be skipped ({total_controls - 1} controls)")
    else:
        print(f"  [i] SFC scan included ({total_controls} controls)")
    
    return options


def show_controls_info():
    """Display information about all security controls."""
    clear_screen()
    print_banner()
    print_menu_header("SECURITY CONTROLS REFERENCE (100 Controls)")
    
    print("""
  ╔═══════════════════════════════════════════════════════════════════════╗
  ║                  CONFIDENTIALITY CONTROLS (21)                        ║
  ╠═══════════════════════════════════════════════════════════════════════╣
  ║ CONF-01 │ BitLocker Encryption              │ CRITICAL │ Data at rest║
  ║ CONF-02 │ SMB1 Protocol Disabled            │ HIGH     │ WannaCry    ║
  ║ CONF-03 │ Administrative Shares Disabled    │ MEDIUM   │ Lateral move║
  ║ CONF-04 │ SMB Signing Required              │ HIGH     │ MITM protect║
  ║ CONF-05 │ NTLM Restricted                   │ HIGH     │ Credential  ║
  ║ CONF-06 │ WDigest Disabled                  │ HIGH     │ Mimikatz    ║
  ║ CONF-07 │ LLMNR Disabled                    │ HIGH     │ Responder   ║
  ║ CONF-08 │ NetBIOS Name Release Prevention   │ MEDIUM   │ Spoofing    ║
  ║ CONF-09 │ Credential Delegation Disabled    │ HIGH     │ Pass-the-Crd║
  ║ CONF-10 │ Guest Account Disabled            │ MEDIUM   │ Unauth acces║
  ║ CONF-11 │ Cached Logons Limited             │ MEDIUM   │ Offline attk║
  ║ CONF-12 │ LM Hash Storage Disabled          │ HIGH     │ Hash crackng║
  ║ CONF-13 │ Anonymous SID Enumeration         │ MEDIUM   │ Recon block ║
  ║ CONF-14 │ Anonymous Share Enumeration       │ MEDIUM   │ Recon block ║
  ║ CONF-15 │ Remote SAM Access Restricted      │ MEDIUM   │ Enum protect║
  ║ CONF-16 │ Null Session Pipes Restricted     │ MEDIUM   │ Anon access ║
  ║ CONF-17 │ AutoRun Disabled                  │ HIGH     │ USB malware ║
  ║ CONF-18 │ Removable Media Access Control    │ MEDIUM   │ Data leakage║
  ║ CONF-19 │ Windows Hello for Business        │ HIGH     │ Passwordless║
  ║ CONF-20 │ Windows LAPS (Native)             │ HIGH     │ Local admin ║
  ║ CONF-21 │ Kerberos Armoring (FAST)          │ HIGH     │ Kerberos sec║
  ╚═══════════════════════════════════════════════════════════════════════╝
    """)
    
    input("  Press Enter to continue...")
    
    print("""
  ╔═══════════════════════════════════════════════════════════════════════╗
  ║                     INTEGRITY CONTROLS (23)                           ║
  ╠═══════════════════════════════════════════════════════════════════════╣
  ║ INTG-01 │ Defender Real-time Protection     │ CRITICAL │ Malware     ║
  ║ INTG-02 │ UAC Configuration                 │ HIGH     │ Priv escal  ║
  ║ INTG-03 │ PowerShell Execution Policy       │ MEDIUM   │ Script block║
  ║ INTG-04 │ Logon Audit Policy                │ HIGH     │ Forensics   ║
  ║ INTG-05 │ System File Integrity (SFC)       │ HIGH     │ File verify ║
  ║ INTG-06 │ LSA Protection (RunAsPPL)         │ CRITICAL │ Credential  ║
  ║ INTG-07 │ Credential Guard                  │ CRITICAL │ VM isolation║
  ║ INTG-08 │ Secure Boot                       │ HIGH     │ Boot integr ║
  ║ INTG-09 │ Driver Signature Enforcement      │ HIGH     │ Rootkit prev║
  ║ INTG-10 │ PowerShell Script Block Logging   │ HIGH     │ PS forensics║
  ║ INTG-11 │ PowerShell Transcription          │ MEDIUM   │ PS logging  ║
  ║ INTG-12 │ Command Line Process Auditing     │ HIGH     │ Process log ║
  ║ INTG-13 │ Object Access Audit               │ MEDIUM   │ File access ║
  ║ INTG-14 │ Privilege Use Audit               │ HIGH     │ Priv monitor║
  ║ INTG-15 │ Policy Change Audit               │ HIGH     │ Config chng ║
  ║ INTG-16 │ SEHOP Enabled                     │ HIGH     │ Exploit prot║
  ║ INTG-17 │ DEP/NX Enabled                    │ HIGH     │ Memory prot ║
  ║ INTG-18 │ ASLR Enabled                      │ HIGH     │ Memory rand ║
  ║ INTG-19 │ Attack Surface Reduction Rules    │ CRITICAL │ ASR/Macros  ║
  ║ INTG-20 │ VBS/HVCI Memory Integrity         │ CRITICAL │ Kernel prot ║
  ║ INTG-21 │ Windows Exploit Protection        │ HIGH     │ CFG/DEP/etc ║
  ║ INTG-22 │ Controlled Folder Access          │ HIGH     │ Ransomware  ║
  ║ INTG-23 │ Early Launch Anti-Malware         │ HIGH     │ Boot protect║
  ╚═══════════════════════════════════════════════════════════════════════╝
    """)
    
    input("  Press Enter to continue...")
    
    print("""
  ╔═══════════════════════════════════════════════════════════════════════╗
  ║                    AVAILABILITY CONTROLS (18)                         ║
  ╠═══════════════════════════════════════════════════════════════════════╣
  ║ AVBL-01 │ Windows Firewall                  │ CRITICAL │ Network prot║
  ║ AVBL-02 │ Volume Shadow Copy Service        │ MEDIUM   │ Recovery    ║
  ║ AVBL-03 │ Virtual Memory Configuration      │ LOW      │ Stability   ║
  ║ AVBL-04 │ Windows Time Service              │ MEDIUM   │ Kerberos    ║
  ║ AVBL-05 │ Password Minimum Length           │ HIGH     │ 14+ chars   ║
  ║ AVBL-06 │ Password Complexity               │ HIGH     │ Strong pass ║
  ║ AVBL-07 │ Account Lockout Threshold         │ HIGH     │ Brute force ║
  ║ AVBL-08 │ Account Lockout Duration          │ MEDIUM   │ Lockout pol ║
  ║ AVBL-09 │ Password History                  │ MEDIUM   │ Reuse block ║
  ║ AVBL-10 │ Password Maximum Age              │ MEDIUM   │ Rotation    ║
  ║ AVBL-11 │ Windows Update Service            │ CRITICAL │ Patching    ║
  ║ AVBL-12 │ Windows Defender Service          │ CRITICAL │ AV running  ║
  ║ AVBL-13 │ BITS Service                      │ MEDIUM   │ Updates     ║
  ║ AVBL-14 │ Event Log Service                 │ HIGH     │ Logging     ║
  ║ AVBL-15 │ Crash Dump Configuration          │ LOW      │ Diagnostics ║
  ║ AVBL-16 │ Auto Restart Sign-on Disabled     │ MEDIUM   │ Sec reboot  ║
  ║ AVBL-17 │ Screen Saver Timeout              │ MEDIUM   │ Lock screen ║
  ║ AVBL-18 │ Backup Configuration              │ HIGH     │ Data recov  ║
  ╚═══════════════════════════════════════════════════════════════════════╝
    """)
    
    input("  Press Enter to continue...")
    
    print("""
  ╔═══════════════════════════════════════════════════════════════════════╗
  ║                      NETWORK CONTROLS (15)                            ║
  ╠═══════════════════════════════════════════════════════════════════════╣
  ║ NETW-01 │ RDP Network Level Authentication  │ HIGH     │ RDP security║
  ║ NETW-02 │ RDP Encryption Level (High)       │ HIGH     │ RDP encrypt ║
  ║ NETW-03 │ RDP Idle Session Timeout          │ MEDIUM   │ Session mgmt║
  ║ NETW-04 │ NetBIOS over TCP/IP Disabled      │ MEDIUM   │ Legacy prot ║
  ║ NETW-05 │ WPAD Disabled                     │ HIGH     │ Proxy hijack║
  ║ NETW-06 │ IPv6 Disabled (if unused)         │ LOW      │ Attack surf ║
  ║ NETW-07 │ Remote Registry Disabled          │ HIGH     │ Remote acces║
  ║ NETW-08 │ WinRM Disabled/Secured            │ HIGH     │ Remote mgmt ║
  ║ NETW-09 │ ICMP Redirects Disabled           │ MEDIUM   │ Route manip ║
  ║ NETW-10 │ IP Source Routing Disabled        │ MEDIUM   │ Spoofing    ║
  ║ NETW-11 │ IRDP Disabled                     │ MEDIUM   │ Route attack║
  ║ NETW-12 │ DNS Multicast (mDNS) Disabled     │ MEDIUM   │ DNS spoofing║
  ║ NETW-13 │ DNS over HTTPS (DoH)              │ HIGH     │ DNS encrypt ║
  ║ NETW-14 │ SMB 3.0 Encryption                │ HIGH     │ SMB security║
  ║ NETW-15 │ Firewall Advanced Logging         │ MEDIUM   │ Forensics   ║
  ╚═══════════════════════════════════════════════════════════════════════╝
    """)
    
    input("  Press Enter to continue...")
    
    print("""
  ╔═══════════════════════════════════════════════════════════════════════╗
  ║                   APPLICATION CONTROLS (12)                           ║
  ╠═══════════════════════════════════════════════════════════════════════╣
  ║ APPS-01 │ Office Macro Execution Disabled   │ CRITICAL │ Malware vec ║
  ║ APPS-02 │ Office OLE Disabled               │ HIGH     │ Exploit prev║
  ║ APPS-03 │ Adobe Reader Protected Mode       │ MEDIUM   │ PDF security║
  ║ APPS-04 │ Browser Extensions Audit          │ MEDIUM   │ Ext security║
  ║ APPS-05 │ Java Browser Plugin Disabled      │ HIGH     │ Java exploits║
  ║ APPS-06 │ Flash Player Disabled             │ HIGH     │ Flash vulns ║
  ║ APPS-07 │ .NET Strong Cryptography          │ HIGH     │ TLS enforce ║
  ║ APPS-08 │ TLS 1.0/1.1 Disabled              │ HIGH     │ Weak crypto ║
  ║ APPS-09 │ SSL 2.0/3.0 Disabled              │ CRITICAL │ POODLE/DROWN║
  ║ APPS-10 │ Certificate Padding Check         │ MEDIUM   │ Cert valid  ║
  ║ APPS-11 │ WDAC/AppLocker Whitelisting       │ CRITICAL │ Zero-trust  ║
  ║ APPS-12 │ PowerShell Constrained Lang Mode  │ HIGH     │ PS lockdown ║
  ╚═══════════════════════════════════════════════════════════════════════╝
    """)
    
    input("  Press Enter to continue...")
    
    print("""
  ╔═══════════════════════════════════════════════════════════════════════╗
  ║                    SERVICES CONTROLS (11)                             ║
  ╠═══════════════════════════════════════════════════════════════════════╣
  ║ SRVC-01 │ Print Spooler Disabled            │ CRITICAL │ PrintNightmr║
  ║ SRVC-02 │ SSDP Discovery Disabled           │ MEDIUM   │ UPnP exploit║
  ║ SRVC-03 │ UPnP Device Host Disabled         │ MEDIUM   │ Network risk║
  ║ SRVC-04 │ Remote Desktop Services           │ HIGH     │ Remote acces║
  ║ SRVC-05 │ Telnet Client Disabled            │ HIGH     │ Clear text  ║
  ║ SRVC-06 │ TFTP Client Disabled              │ MEDIUM   │ Unsecure xfr║
  ║ SRVC-07 │ WMP Network Sharing Disabled      │ LOW      │ Media expose║
  ║ SRVC-08 │ Xbox Services Disabled            │ LOW      │ Unnecessary ║
  ║ SRVC-09 │ Fax Service Disabled              │ LOW      │ Attack surf ║
  ║ SRVC-10 │ Bluetooth Support Disabled        │ MEDIUM   │ BT attacks  ║
  ║ SRVC-11 │ RD Gateway Requirement            │ MEDIUM   │ RDP gateway ║
  ╚═══════════════════════════════════════════════════════════════════════╝
    """)
    
    print("\n  RISK LEVELS:")
    print("  " + "-" * 50)
    print("  CRITICAL - Immediate action required, actively exploited vulnerabilities")
    print("  HIGH     - Important security control, significant risk if not addressed")
    print("  MEDIUM   - Moderate risk, recommended for defense-in-depth")
    print("  LOW      - Minor issue, best practice recommendation")
    
    print("\n  TOTAL: 100 Security Controls across 6 Categories")
    
    input("\n  Press Enter to return to main menu...")


def run_engine_with_config(config):
    """Run the Guardian Engine with the specified configuration."""
    from cia_guardian.engine import GuardianEngine
    
    print("\n")
    
    engine = GuardianEngine(
        output_dir=config['output'],
        log_dir=os.path.join(config['output'], 'logs')
    )
    
    # v2.1: Get parallel execution settings from config or defaults
    parallel = config.get('parallel', True)  # Default: parallel for dry-run
    max_workers = config.get('max_workers', 8)
    sfc_background = config.get('sfc_background', True)
    sfc_timeout = config.get('sfc_timeout', 2700)
    progress_style = config.get('progress_style', 'auto')  # v2.1: Progress style
    skip_sfc = config.get('skip_sfc', False)  # v2.1: Skip SFC option
    
    # Run based on mode
    if config.get('report_only'):
        print("[*] Report-only mode: Collecting system information...")
        engine.collect_system_info()
        engine.run_audit(
            dry_run=True, 
            categories=config.get('categories'),
            skip_preflight=True,
            parallel=parallel,
            max_workers=max_workers,
            sfc_background=sfc_background,
            sfc_timeout=sfc_timeout,
            skip_sfc=skip_sfc,  # v2.1
            progress_style=progress_style  # v2.1
        )
    elif config.get('mode') == 'individual':
        # Individual control selection mode
        engine.run_audit(
            dry_run=config['dry_run'],
            control_ids=config.get('control_ids'),
            enable_backup=not config['dry_run'],
            parallel=parallel and config['dry_run'],  # Only parallel for dry-run
            max_workers=max_workers,
            sfc_background=sfc_background,
            sfc_timeout=sfc_timeout,
            skip_sfc=skip_sfc,  # v2.1
            progress_style=progress_style  # v2.1
        )
    else:
        # Category-based audit (full, dry_run, custom)
        engine.run_audit(
            dry_run=config['dry_run'], 
            categories=config.get('categories'),
            enable_backup=not config['dry_run'],
            parallel=parallel and config['dry_run'],  # Only parallel for dry-run
            max_workers=max_workers,
            sfc_background=sfc_background,
            sfc_timeout=sfc_timeout,
            skip_sfc=skip_sfc,  # v2.1
            progress_style=progress_style  # v2.1
        )
    
    # Generate reports
    print("\n")
    generated = engine.generate_reports(formats=config['formats'])
    
    if generated:
        print("\n" + "=" * 65)
        print(" AUDIT COMPLETE")
        print("=" * 65)
        print(f"\n Generated Reports:")
        for fmt, path in generated.items():
            print(f"   - {fmt.upper()}: {path}")
        print(f"\n Log file: {engine.logger.log_file}")
        
        # Show rollback info if available
        if engine.controls_with_backups:
            print(f"\n Backups available for rollback: {', '.join(engine.controls_with_backups)}")
        
        print("=" * 65)
    
    return engine


def main():
    """Main entry point for CIA-Guardian."""
    parser = argparse.ArgumentParser(
        description='CIA-Guardian v2.3 - Windows Security Hardening Tool (100 Controls)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  cia_guardian.py                     Launch interactive menu
  cia_guardian.py --interactive       Launch interactive menu (explicit)
  cia_guardian.py --dry-run           Audit only, no changes (parallel by default)
  cia_guardian.py --dry-run --sequential  Audit only in sequential mode
  cia_guardian.py --dry-run --skip-sfc    Fast audit skipping SFC scan
  cia_guardian.py --report-only       Generate reports from current state
  cia_guardian.py --output ./my-reports --formats html,pdf,json
  cia_guardian.py --controls CONF-01,INTG-02,AVBL-01  Select specific controls
  cia_guardian.py --categories network,services       Audit specific categories
  cia_guardian.py --workers 4 --sfc-timeout 1800      Custom parallel config

Execution Modes (v2.3):
  - Parallel (default for dry-run): Runs controls concurrently for 5-6x speedup
  - Sequential (--sequential): Safer sequential execution for fixes
  - Skip SFC (--skip-sfc): Skip the slow SFC scan for faster audits
  - SFC Background: INTG-05 runs async with 45min timeout (configurable)

Categories: confidentiality (21), integrity (23), availability (18),
            network (15), application (12), services (11)

For more information, visit: https://github.com/cia-guardian
        '''
    )
    
    parser.add_argument(
        '--interactive', '-i',
        action='store_true',
        help='Launch interactive menu mode (default if no other options)'
    )
    
    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Audit only, no remediation will be applied'
    )
    
    parser.add_argument(
        '--report-only',
        action='store_true',
        help='Generate report from existing state without running full audit'
    )
    
    parser.add_argument(
        '--output', '-o',
        type=str,
        default='./reports',
        metavar='DIR',
        help='Report output directory (default: ./reports/)'
    )
    
    parser.add_argument(
        '--formats', '-f',
        type=str,
        default='html,pdf',
        metavar='FORMATS',
        help='Report formats: html,pdf,json,csv (default: html,pdf)'
    )
    
    parser.add_argument(
        '--categories', '-c',
        type=str,
        default='all',
        metavar='CATEGORIES',
        help='Categories to audit: all,confidentiality,integrity,availability,network,application,services'
    )
    
    parser.add_argument(
        '--controls',
        type=str,
        default=None,
        metavar='IDS',
        help='Specific control IDs to audit (e.g., CONF-01,INTG-02,AVBL-01)'
    )
    
    parser.add_argument(
        '--skip-preflight',
        action='store_true',
        help='Skip pre-flight system checks'
    )
    
    parser.add_argument(
        '--skip-long-running',
        action='store_true',
        help='Skip long-running controls like SFC (INTG-05) that can take 15-30+ minutes'
    )
    
    parser.add_argument(
        '--no-backup',
        action='store_true',
        help='Disable backup before remediation (no rollback available)'
    )
    
    # v2.1 Parallel execution arguments
    parser.add_argument(
        '--sequential',
        action='store_true',
        help='Disable parallel execution, run controls sequentially (v2.1)'
    )
    
    parser.add_argument(
        '--workers',
        type=int,
        default=8,
        metavar='N',
        help='Number of parallel worker threads (default: 8) (v2.1)'
    )
    
    parser.add_argument(
        '--sfc-timeout',
        type=int,
        default=2700,
        metavar='SECONDS',
        help='SFC (INTG-05) timeout in seconds (default: 2700 = 45 min) (v2.1)'
    )
    
    parser.add_argument(
        '--no-sfc-background',
        action='store_true',
        help='Run SFC synchronously instead of in background thread (v2.1)'
    )
    
    parser.add_argument(
        '--skip-sfc',
        action='store_true',
        help='Skip SFC scan (INTG-05) entirely - useful for faster audits (v2.1)'
    )
    
    parser.add_argument(
        '--progress-style',
        type=str,
        choices=['box', 'simple', 'minimal', 'ascii', 'auto'],
        default='auto',
        metavar='STYLE',
        help='Progress display style: box, simple, minimal, ascii, auto (default: auto) (v2.1)'
    )
    
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose output'
    )
    
    parser.add_argument(
        '--version',
        action='version',
        version='CIA-Guardian v2.3.0 (100 Security Controls, Parallel Execution)'
    )
    
    args = parser.parse_args()
    
    # Platform check
    if sys.platform != 'win32':
        print("[ERROR] CIA-Guardian is designed for Windows systems only.")
        print("        Please run this tool on Windows 10/11 or Server 2019+")
        sys.exit(1)
    
    # Check dependencies
    if not check_requirements():
        print("\n[INFO] Install dependencies with:")
        print("       pip install jinja2 fpdf2 colorama tabulate")
        sys.exit(1)
    
    # Determine if we should use interactive mode
    # Use interactive if explicitly requested OR if no action flags are provided
    use_interactive = args.interactive or not (args.dry_run or args.report_only)
    
    # If running interactively and no specific action flags
    if use_interactive and not args.dry_run and not args.report_only:
        try:
            config = interactive_mode()
            if config is None:
                sys.exit(0)
            
            # Check admin before running
            is_admin = check_admin()
            if not is_admin and not config['dry_run']:
                print("\n" + "=" * 65)
                print(" WARNING: Running without Administrator privileges!")
                print(" Some security controls may fail or report incorrect status.")
                print(" For full functionality, run as Administrator.")
                print("=" * 65 + "\n")
                
                response = input("Continue anyway? [y/N]: ")
                if response.lower() != 'y':
                    print("Exiting. Please run as Administrator.")
                    sys.exit(0)
            
            engine = run_engine_with_config(config)
            
            # Return appropriate exit code
            if engine.summary:
                if engine.summary.security_score >= 85:
                    sys.exit(0)
                elif engine.summary.security_score >= 60:
                    sys.exit(1)
                else:
                    sys.exit(2)
                    
        except KeyboardInterrupt:
            print("\n\n[!] Operation cancelled by user")
            sys.exit(130)
        except Exception as e:
            print(f"\n[ERROR] {str(e)}")
            if args.verbose:
                import traceback
                traceback.print_exc()
            sys.exit(1)
    
    else:
        # Non-interactive command-line mode
        from cia_guardian.engine import GuardianEngine
        
        # Check admin privileges
        is_admin = check_admin()
        if not is_admin:
            print("\n" + "=" * 60)
            print(" WARNING: Running without Administrator privileges!")
            print(" Some security controls may fail or report incorrect status.")
            print(" For full functionality, run as Administrator.")
            print("=" * 60 + "\n")
            
            response = input("Continue anyway? [y/N]: ")
            if response.lower() != 'y':
                print("Exiting. Please run as Administrator.")
                sys.exit(0)
        
        # Parse formats
        formats = [f.strip().lower() for f in args.formats.split(',')]
        valid_formats = ['html', 'pdf', 'json', 'csv']
        formats = [f for f in formats if f in valid_formats]
        
        if not formats:
            formats = ['html', 'pdf']
        
        # Parse categories
        if args.categories.lower() == 'all':
            categories = ['confidentiality', 'integrity', 'availability', 'network', 'application', 'services']
        else:
            categories = [c.strip().lower() for c in args.categories.split(',')]
            valid_cats = ['confidentiality', 'integrity', 'availability', 'network', 'application', 'services']
            categories = [c for c in categories if c in valid_cats]
        
        # Create and run engine
        try:
            engine = GuardianEngine(
                output_dir=os.path.abspath(args.output),
                log_dir=os.path.join(os.path.abspath(args.output), 'logs')
            )
            
            # Parse control IDs if provided
            control_ids = None
            if args.controls:
                control_ids = [c.strip().upper() for c in args.controls.split(',')]
                valid_ids = [
                    # Confidentiality (21)
                    'CONF-01', 'CONF-02', 'CONF-03', 'CONF-04', 'CONF-05', 'CONF-06',
                    'CONF-07', 'CONF-08', 'CONF-09', 'CONF-10', 'CONF-11', 'CONF-12',
                    'CONF-13', 'CONF-14', 'CONF-15', 'CONF-16', 'CONF-17', 'CONF-18',
                    'CONF-19', 'CONF-20', 'CONF-21',
                    # Integrity (23)
                    'INTG-01', 'INTG-02', 'INTG-03', 'INTG-04', 'INTG-05', 'INTG-06',
                    'INTG-07', 'INTG-08', 'INTG-09', 'INTG-10', 'INTG-11', 'INTG-12',
                    'INTG-13', 'INTG-14', 'INTG-15', 'INTG-16', 'INTG-17', 'INTG-18',
                    'INTG-19', 'INTG-20', 'INTG-21', 'INTG-22', 'INTG-23',
                    # Availability (18)
                    'AVBL-01', 'AVBL-02', 'AVBL-03', 'AVBL-04', 'AVBL-05', 'AVBL-06',
                    'AVBL-07', 'AVBL-08', 'AVBL-09', 'AVBL-10', 'AVBL-11', 'AVBL-12',
                    'AVBL-13', 'AVBL-14', 'AVBL-15', 'AVBL-16', 'AVBL-17', 'AVBL-18',
                    # Network (15)
                    'NETW-01', 'NETW-02', 'NETW-03', 'NETW-04', 'NETW-05', 'NETW-06',
                    'NETW-07', 'NETW-08', 'NETW-09', 'NETW-10', 'NETW-11', 'NETW-12',
                    'NETW-13', 'NETW-14', 'NETW-15',
                    # Application (12)
                    'APPS-01', 'APPS-02', 'APPS-03', 'APPS-04', 'APPS-05',
                    'APPS-06', 'APPS-07', 'APPS-08', 'APPS-09', 'APPS-10',
                    'APPS-11', 'APPS-12',
                    # Services (11)
                    'SRVC-01', 'SRVC-02', 'SRVC-03', 'SRVC-04', 'SRVC-05',
                    'SRVC-06', 'SRVC-07', 'SRVC-08', 'SRVC-09', 'SRVC-10', 'SRVC-11'
                ]
                invalid_ids = [cid for cid in control_ids if cid not in valid_ids]
                if invalid_ids:
                    print(f"[ERROR] Invalid control IDs: {', '.join(invalid_ids)}")
                    print("        Use --help to see available control IDs")
                    sys.exit(1)
            
            # Determine run mode
            if args.report_only:
                print("\n[*] Report-only mode: Collecting system information...")
                engine.collect_system_info()
                engine.run_audit(
                    dry_run=True, 
                    categories=categories,
                    skip_preflight=True,
                    skip_long_running=getattr(args, 'skip_long_running', False),
                    parallel=not args.sequential,
                    max_workers=args.workers,
                    sfc_background=not args.no_sfc_background,
                    sfc_timeout=args.sfc_timeout,
                    skip_sfc=args.skip_sfc,
                    progress_style=getattr(args, 'progress_style', 'auto')  # v2.1
                )
            else:
                engine.run_audit(
                    dry_run=args.dry_run, 
                    categories=categories if not control_ids else None,
                    control_ids=control_ids,
                    skip_preflight=getattr(args, 'skip_preflight', False),
                    enable_backup=not getattr(args, 'no_backup', False),
                    skip_long_running=getattr(args, 'skip_long_running', False),
                    parallel=not args.sequential,
                    max_workers=args.workers,
                    sfc_background=not args.no_sfc_background,
                    sfc_timeout=args.sfc_timeout,
                    skip_sfc=args.skip_sfc,
                    progress_style=getattr(args, 'progress_style', 'auto')  # v2.1
                )
            
            # Generate reports
            print("\n")
            generated = engine.generate_reports(formats=formats)
            
            if generated:
                print("\n" + "=" * 60)
                print(" AUDIT COMPLETE")
                print("=" * 60)
                print(f"\n Generated Reports:")
                for fmt, path in generated.items():
                    print(f"   - {fmt.upper()}: {path}")
                print(f"\n Log file: {engine.logger.log_file}")
                
                # Show rollback info if available
                if engine.controls_with_backups:
                    print(f"\n Backups available for rollback: {', '.join(engine.controls_with_backups)}")
                
                print("=" * 60)
            
            # Return appropriate exit code
            if engine.summary:
                if engine.summary.security_score >= 85:
                    sys.exit(0)
                elif engine.summary.security_score >= 60:
                    sys.exit(1)
                else:
                    sys.exit(2)
            
        except KeyboardInterrupt:
            print("\n\n[!] Audit cancelled by user")
            sys.exit(130)
        except Exception as e:
            print(f"\n[ERROR] {str(e)}")
            if args.verbose:
                import traceback
                traceback.print_exc()
            sys.exit(1)


if __name__ == '__main__':
    main()
