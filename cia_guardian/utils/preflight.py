"""
Pre-flight Checks Module
Verifies system requirements before running security audits.
"""

import os
import shutil
from dataclasses import dataclass
from typing import List, Tuple, Optional
from .command_runner import WindowsCommandRunner


@dataclass
class PreflightResult:
    """Result of a pre-flight check."""
    name: str
    passed: bool
    message: str
    details: str = ""
    is_critical: bool = False


class PreflightChecker:
    """
    Performs pre-flight checks before running security audits.
    Verifies PowerShell version, disk space, Windows features, etc.
    """
    
    MIN_DISK_SPACE_MB = 100  # Minimum disk space for reports
    MIN_PS_VERSION = (5, 1)   # Minimum PowerShell version
    RECOMMENDED_PS_VERSION = (7, 0)  # Recommended PowerShell version
    
    def __init__(self, runner: Optional[WindowsCommandRunner] = None):
        """Initialize the pre-flight checker."""
        self.runner = runner or WindowsCommandRunner()
        self.results: List[PreflightResult] = []
    
    def run_all_checks(self) -> Tuple[bool, List[PreflightResult]]:
        """
        Run all pre-flight checks.
        
        Returns:
            Tuple of (all_passed, results_list)
        """
        self.results = []
        
        # Run all checks
        self.check_powershell_version()
        self.check_disk_space()
        self.check_admin_privileges()
        self.check_windows_version()
        self.check_required_services()
        self.check_network_connectivity()
        
        # Determine if all critical checks passed
        all_passed = all(r.passed for r in self.results if r.is_critical)
        
        return all_passed, self.results
    
    def check_powershell_version(self) -> PreflightResult:
        """Check PowerShell version."""
        result = PreflightResult(
            name="PowerShell Version",
            passed=False,
            message="Checking PowerShell version...",
            is_critical=True
        )
        
        try:
            # Try PowerShell 7+ first
            ps7_result = self.runner.run_cmd('pwsh -NoProfile -Command "$PSVersionTable.PSVersion.ToString()"')
            
            if ps7_result.success and ps7_result.stdout.strip():
                version_str = ps7_result.stdout.strip()
                result.passed = True
                result.message = f"PowerShell 7+ found: v{version_str}"
                result.details = "Recommended version installed"
                self.results.append(result)
                return result
            
            # Fall back to PowerShell 5.1
            ps5_result = self.runner.run_powershell('$PSVersionTable.PSVersion.ToString()', use_pwsh=False)
            
            if ps5_result.success and ps5_result.stdout.strip():
                version_str = ps5_result.stdout.strip()
                parts = version_str.split('.')
                major = int(parts[0]) if parts else 0
                minor = int(parts[1]) if len(parts) > 1 else 0
                
                if (major, minor) >= self.MIN_PS_VERSION:
                    result.passed = True
                    result.message = f"PowerShell 5.1 found: v{version_str}"
                    result.details = "Minimum version met (7+ recommended for best performance)"
                else:
                    result.message = f"PowerShell version too old: v{version_str}"
                    result.details = f"Minimum required: {self.MIN_PS_VERSION[0]}.{self.MIN_PS_VERSION[1]}"
            else:
                result.message = "PowerShell not found or not accessible"
                result.details = "Please install PowerShell 5.1 or later"
                
        except Exception as e:
            result.message = f"Error checking PowerShell: {str(e)}"
            result.details = "Unable to determine PowerShell version"
        
        self.results.append(result)
        return result
    
    def check_disk_space(self) -> PreflightResult:
        """Check available disk space for reports."""
        result = PreflightResult(
            name="Disk Space",
            passed=False,
            message="Checking available disk space...",
            is_critical=False
        )
        
        try:
            # Get disk usage for current drive
            total, used, free = shutil.disk_usage(os.getcwd())
            free_mb = free // (1024 * 1024)
            
            if free_mb >= self.MIN_DISK_SPACE_MB:
                result.passed = True
                result.message = f"Sufficient disk space: {free_mb:,} MB available"
                result.details = f"Minimum required: {self.MIN_DISK_SPACE_MB} MB"
            else:
                result.message = f"Low disk space: {free_mb:,} MB available"
                result.details = f"Minimum required: {self.MIN_DISK_SPACE_MB} MB for reports"
                
        except Exception as e:
            result.message = f"Error checking disk space: {str(e)}"
            result.passed = True  # Non-critical, assume OK
        
        self.results.append(result)
        return result
    
    def check_admin_privileges(self) -> PreflightResult:
        """Check for administrator privileges."""
        result = PreflightResult(
            name="Administrator Privileges",
            passed=False,
            message="Checking administrator privileges...",
            is_critical=False  # Can run without admin, but limited
        )
        
        try:
            is_admin = self.runner.is_admin()
            
            if is_admin:
                result.passed = True
                result.message = "Running with Administrator privileges"
                result.details = "Full functionality available"
            else:
                result.passed = True  # Allow to continue
                result.message = "Running WITHOUT Administrator privileges"
                result.details = "Some controls may fail or report incorrect status"
                
        except Exception as e:
            result.message = f"Error checking privileges: {str(e)}"
            result.passed = True
        
        self.results.append(result)
        return result
    
    def check_windows_version(self) -> PreflightResult:
        """Check Windows version compatibility."""
        result = PreflightResult(
            name="Windows Version",
            passed=False,
            message="Checking Windows version...",
            is_critical=True
        )
        
        try:
            import platform
            version = platform.version()
            release = platform.release()
            
            # Parse version number
            parts = version.split('.')
            major = int(parts[0]) if parts else 0
            build = int(parts[2]) if len(parts) > 2 else 0
            
            # Windows 10 is 10.0.xxxxx, Windows 11 is 10.0.22000+
            # Windows Server 2019 is 10.0.17763+
            if major >= 10:
                if build >= 22000:
                    os_name = "Windows 11"
                elif build >= 17763:
                    os_name = f"Windows 10/Server 2019+ (Build {build})"
                else:
                    os_name = f"Windows 10 (Build {build})"
                
                result.passed = True
                result.message = f"Compatible: {os_name}"
                result.details = f"Version: {version}"
            else:
                result.message = f"Unsupported Windows version: {release}"
                result.details = "Requires Windows 10/11 or Server 2019+"
                
        except Exception as e:
            result.message = f"Error checking Windows version: {str(e)}"
            result.passed = True  # Assume compatible
        
        self.results.append(result)
        return result
    
    def check_required_services(self) -> PreflightResult:
        """Check if required Windows services are accessible."""
        result = PreflightResult(
            name="Required Services",
            passed=False,
            message="Checking required services...",
            is_critical=False
        )
        
        try:
            required_services = ['WinDefend', 'EventLog', 'Schedule']
            accessible = []
            failed = []
            
            for svc in required_services:
                svc_result = self.runner.run_sc(f'query {svc}')
                if svc_result.success or 'STATE' in svc_result.stdout:
                    accessible.append(svc)
                else:
                    failed.append(svc)
            
            if len(failed) == 0:
                result.passed = True
                result.message = f"All required services accessible ({len(accessible)}/{len(required_services)})"
                result.details = ", ".join(accessible)
            else:
                result.passed = True  # Non-critical
                result.message = f"Some services not accessible: {', '.join(failed)}"
                result.details = "Some controls may report errors"
                
        except Exception as e:
            result.message = f"Error checking services: {str(e)}"
            result.passed = True
        
        self.results.append(result)
        return result
    
    def check_network_connectivity(self) -> PreflightResult:
        """Check network connectivity for time sync and updates."""
        result = PreflightResult(
            name="Network Connectivity",
            passed=False,
            message="Checking network connectivity...",
            is_critical=False
        )
        
        try:
            # Try to resolve a common time server
            import socket
            socket.setdefaulttimeout(5)
            socket.gethostbyname('time.windows.com')
            
            result.passed = True
            result.message = "Network connectivity available"
            result.details = "Time synchronization endpoints reachable"
            
        except socket.gaierror:
            result.passed = True  # Non-critical
            result.message = "Limited network connectivity"
            result.details = "Time sync checks may be affected"
        except Exception as e:
            result.passed = True
            result.message = f"Network check skipped: {str(e)}"
        
        self.results.append(result)
        return result
    
    def print_results(self) -> None:
        """Print pre-flight check results to console."""
        print("\n" + "=" * 65)
        print("  PRE-FLIGHT CHECKS")
        print("=" * 65)
        
        for result in self.results:
            status = "[PASS]" if result.passed else "[FAIL]"
            critical = " (CRITICAL)" if result.is_critical and not result.passed else ""
            print(f"\n  {status} {result.name}{critical}")
            print(f"        {result.message}")
            if result.details:
                print(f"        {result.details}")
        
        print("\n" + "-" * 65)
        all_critical_passed = all(r.passed for r in self.results if r.is_critical)
        if all_critical_passed:
            print("  [OK] All critical checks passed. Ready to proceed.")
        else:
            print("  [!!] Critical checks failed. Please resolve issues before continuing.")
        print("=" * 65 + "\n")
