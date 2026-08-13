"""
Application Security Controls
APPS-01: Office Macro Disabled
APPS-02: Office OLE Disabled
APPS-03: Adobe Reader Protected Mode
APPS-04: Browser Extensions Audit
APPS-05: Java Disabled in Browser
APPS-06: Flash Disabled
APPS-07: .NET Strong Crypto
APPS-08: TLS 1.0/1.1 Disabled
APPS-09: SSL 2.0/3.0 Disabled
APPS-10: Certificate Padding Check
APPS-11: WDAC/AppLocker Application Whitelisting (v2.2)
APPS-12: PowerShell Constrained Language Mode (v2.3)
"""

from typing import Dict, Any, Optional, List
from .base import (
    SecurityControl, ControlResult, ControlStatus,
    RiskLevel, CIACategory, ControlGroup
)
from .registry_base import RegistryControl, MultiRegistryControl


class OfficeMacroDisabledControl(MultiRegistryControl):
    """
    APPS-01: Office Macro Disabled
    Ensures Office macros are disabled or restricted to prevent malware execution.
    Checks multiple Office versions (2016, 2019, 365).
    """
    
    # Check Word, Excel, PowerPoint macro settings
    # VBAWarnings: 1=Enable all, 2=Disable with notification, 3=Disable except digitally signed, 4=Disable all
    registry_checks = [
        {
            'path': r'HKCU\SOFTWARE\Microsoft\Office\16.0\Word\Security',
            'value': 'VBAWarnings',
            'expected': 4,
            'type': 'REG_DWORD',
            'comparison': 'greater_equal'
        },
        {
            'path': r'HKCU\SOFTWARE\Microsoft\Office\16.0\Excel\Security',
            'value': 'VBAWarnings',
            'expected': 4,
            'type': 'REG_DWORD',
            'comparison': 'greater_equal'
        },
        {
            'path': r'HKCU\SOFTWARE\Microsoft\Office\16.0\PowerPoint\Security',
            'value': 'VBAWarnings',
            'expected': 4,
            'type': 'REG_DWORD',
            'comparison': 'greater_equal'
        }
    ]
    require_all = False  # Any Office app configured is a start
    
    def __init__(self):
        super().__init__(
            control_id="APPS-01",
            name="Office Macro Disabled",
            description="Verify Office macros are disabled to prevent malware",
            category=CIACategory.APPLICATION,
            risk_level=RiskLevel.CRITICAL,
            cis_reference="CIS 18.9.85.1",
            nist_reference="CM-7"
        )
    
    def audit(self) -> ControlResult:
        """Check Office macro settings across multiple versions."""
        try:
            # Check if any Office application is installed
            office_paths = [
                r'HKLM\SOFTWARE\Microsoft\Office\16.0\Common\InstallRoot',
                r'HKLM\SOFTWARE\Microsoft\Office\15.0\Common\InstallRoot',
                r'HKLM\SOFTWARE\WOW6432Node\Microsoft\Office\16.0\Common\InstallRoot'
            ]
            
            office_installed = False
            for path in office_paths:
                result = self.runner.run_reg_query(path, 'Path')
                if result.success:
                    office_installed = True
                    break
            
            if not office_installed:
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.NOT_APPLICABLE,
                    risk_level=self.risk_level,
                    evidence="Microsoft Office not detected on this system"
                )
            
            # Now check macro settings
            return super().audit()
            
        except Exception as e:
            return ControlResult(
                control_id=self.control_id,
                name=self.name,
                category=self.category,
                status=ControlStatus.ERROR,
                risk_level=self.risk_level,
                evidence="Error checking Office macro settings",
                error_message=str(e)
            )


class OfficeOLEDisabledControl(MultiRegistryControl):
    """
    APPS-02: Office OLE Disabled
    Ensures OLE package activation is blocked to prevent embedded malware.
    """
    
    registry_checks = [
        {
            'path': r'HKCU\SOFTWARE\Microsoft\Office\16.0\Word\Security',
            'value': 'PackagerPrompt',
            'expected': 2,  # 2 = Block
            'type': 'REG_DWORD',
            'comparison': 'equal'
        },
        {
            'path': r'HKCU\SOFTWARE\Microsoft\Office\16.0\Excel\Security',
            'value': 'PackagerPrompt',
            'expected': 2,
            'type': 'REG_DWORD',
            'comparison': 'equal'
        },
        {
            'path': r'HKCU\SOFTWARE\Microsoft\Office\16.0\PowerPoint\Security',
            'value': 'PackagerPrompt',
            'expected': 2,
            'type': 'REG_DWORD',
            'comparison': 'equal'
        }
    ]
    require_all = False
    
    def __init__(self):
        super().__init__(
            control_id="APPS-02",
            name="Office OLE Disabled",
            description="Verify Office OLE package activation is blocked",
            category=CIACategory.APPLICATION,
            risk_level=RiskLevel.HIGH,
            cis_reference="CIS 18.9.85.2",
            nist_reference="CM-7"
        )
    
    def audit(self) -> ControlResult:
        """Check Office OLE settings."""
        try:
            # Check if Office is installed first
            result = self.runner.run_reg_query(
                r'HKLM\SOFTWARE\Microsoft\Office\16.0\Common\InstallRoot', 'Path'
            )
            if not result.success:
                result = self.runner.run_reg_query(
                    r'HKLM\SOFTWARE\WOW6432Node\Microsoft\Office\16.0\Common\InstallRoot', 'Path'
                )
            
            if not result.success:
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.NOT_APPLICABLE,
                    risk_level=self.risk_level,
                    evidence="Microsoft Office not detected on this system"
                )
            
            return super().audit()
            
        except Exception as e:
            return ControlResult(
                control_id=self.control_id,
                name=self.name,
                category=self.category,
                status=ControlStatus.ERROR,
                risk_level=self.risk_level,
                evidence="Error checking Office OLE settings",
                error_message=str(e)
            )


class AdobeReaderProtectedModeControl(RegistryControl):
    """
    APPS-03: Adobe Reader Protected Mode
    Ensures Adobe Reader Protected Mode is enabled for sandboxed execution.
    """
    
    registry_path = r'HKLM\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown'
    registry_value = 'bProtectedMode'
    expected_data = 1  # 1 = Enabled
    value_type = 'REG_DWORD'
    comparison = 'equal'
    
    def __init__(self):
        super().__init__(
            control_id="APPS-03",
            name="Adobe Reader Protected Mode",
            description="Verify Adobe Reader Protected Mode is enabled",
            category=CIACategory.APPLICATION,
            risk_level=RiskLevel.MEDIUM,
            cis_reference="N/A",
            nist_reference="SC-39"
        )
    
    def audit(self) -> ControlResult:
        """Check Adobe Reader protected mode."""
        try:
            # Check if Adobe Reader is installed
            adobe_paths = [
                r'HKLM\SOFTWARE\Adobe\Acrobat Reader',
                r'HKLM\SOFTWARE\WOW6432Node\Adobe\Acrobat Reader'
            ]
            
            adobe_installed = False
            for path in adobe_paths:
                result = self.runner.run_cmd(f'reg query "{path}"')
                if result.success and 'DC' in result.stdout:
                    adobe_installed = True
                    break
            
            if not adobe_installed:
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.NOT_APPLICABLE,
                    risk_level=self.risk_level,
                    evidence="Adobe Reader not detected on this system"
                )
            
            return super().audit()
            
        except Exception as e:
            return ControlResult(
                control_id=self.control_id,
                name=self.name,
                category=self.category,
                status=ControlStatus.ERROR,
                risk_level=self.risk_level,
                evidence="Error checking Adobe Reader settings",
                error_message=str(e)
            )


class BrowserExtensionsAuditControl(SecurityControl):
    """
    APPS-04: Browser Extensions Audit
    Audits browser extensions for potential security risks.
    Checks Chrome and Edge extension directories.
    """
    
    def __init__(self):
        super().__init__(
            control_id="APPS-04",
            name="Browser Extensions Audit",
            description="Audit browser extensions for security risks",
            category=CIACategory.APPLICATION,
            risk_level=RiskLevel.MEDIUM,
            cis_reference="N/A",
            nist_reference="CM-7"
        )
        self._supports_rollback = False  # Audit only
    
    def audit(self) -> ControlResult:
        """Audit browser extensions."""
        try:
            extensions_found = []
            
            # Check Chrome extensions
            chrome_result = self.runner.run_powershell(
                '''
                $userProfile = $env:USERPROFILE
                $chromePath = "$userProfile\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Extensions"
                if (Test-Path $chromePath) {
                    $extensions = Get-ChildItem -Path $chromePath -Directory | Select-Object -ExpandProperty Name
                    Write-Output "Chrome Extensions: $($extensions.Count)"
                    $extensions | ForEach-Object { Write-Output "  $_" }
                } else {
                    Write-Output "Chrome: Not installed or no extensions"
                }
                '''
            )
            if chrome_result.success:
                extensions_found.append(chrome_result.stdout.strip())
            
            # Check Edge extensions
            edge_result = self.runner.run_powershell(
                '''
                $userProfile = $env:USERPROFILE
                $edgePath = "$userProfile\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\Extensions"
                if (Test-Path $edgePath) {
                    $extensions = Get-ChildItem -Path $edgePath -Directory | Select-Object -ExpandProperty Name
                    Write-Output "Edge Extensions: $($extensions.Count)"
                    $extensions | ForEach-Object { Write-Output "  $_" }
                } else {
                    Write-Output "Edge: Not installed or no extensions"
                }
                '''
            )
            if edge_result.success:
                extensions_found.append(edge_result.stdout.strip())
            
            combined_output = "\n".join(extensions_found)
            
            # Count total extensions
            chrome_count = 0
            edge_count = 0
            
            if 'Chrome Extensions:' in combined_output:
                try:
                    chrome_line = [l for l in combined_output.split('\n') if 'Chrome Extensions:' in l][0]
                    chrome_count = int(chrome_line.split(':')[1].strip())
                except (IndexError, ValueError):
                    pass
            
            if 'Edge Extensions:' in combined_output:
                try:
                    edge_line = [l for l in combined_output.split('\n') if 'Edge Extensions:' in l][0]
                    edge_count = int(edge_line.split(':')[1].strip())
                except (IndexError, ValueError):
                    pass
            
            total_extensions = chrome_count + edge_count
            
            # Informational - too many extensions may indicate risk
            if total_extensions == 0:
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.COMPLIANT,
                    risk_level=self.risk_level,
                    evidence="No browser extensions detected",
                    command_output=combined_output
                )
            elif total_extensions <= 5:
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.COMPLIANT,
                    risk_level=self.risk_level,
                    evidence=f"{total_extensions} browser extensions found (within acceptable range)",
                    details="Review extensions periodically for security",
                    command_output=combined_output
                )
            else:
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.NON_COMPLIANT,
                    risk_level=self.risk_level,
                    evidence=f"{total_extensions} browser extensions found (high count)",
                    details="Consider reviewing and removing unnecessary extensions",
                    command_output=combined_output
                )
                
        except Exception as e:
            return ControlResult(
                control_id=self.control_id,
                name=self.name,
                category=self.category,
                status=ControlStatus.ERROR,
                risk_level=self.risk_level,
                evidence="Error auditing browser extensions",
                error_message=str(e)
            )
    
    def remediate(self) -> bool:
        """Cannot auto-remediate - audit only."""
        self._log('info', "Browser extensions audit is informational only. Manual review required.")
        return True
    
    def verify(self) -> ControlResult:
        """Re-audit browser extensions."""
        return self.audit()


class JavaBrowserDisabledControl(RegistryControl):
    """
    APPS-05: Java Disabled in Browser
    Ensures Java browser plugin is disabled to prevent exploitation.
    """
    
    registry_path = r'HKLM\SOFTWARE\JavaSoft\Java Plug-in'
    registry_value = 'UseJava2IExplorer'
    expected_data = 0  # 0 = Disabled
    value_type = 'REG_DWORD'
    comparison = 'equal'
    create_if_missing = False  # If Java not installed, that's fine
    
    def __init__(self):
        super().__init__(
            control_id="APPS-05",
            name="Java Browser Plugin Disabled",
            description="Verify Java browser plugin is disabled",
            category=CIACategory.APPLICATION,
            risk_level=RiskLevel.HIGH,
            cis_reference="N/A",
            nist_reference="CM-7"
        )
    
    def audit(self) -> ControlResult:
        """Check Java browser plugin status."""
        try:
            # Check if Java is installed
            java_paths = [
                r'HKLM\SOFTWARE\JavaSoft\Java Runtime Environment',
                r'HKLM\SOFTWARE\WOW6432Node\JavaSoft\Java Runtime Environment'
            ]
            
            java_installed = False
            for path in java_paths:
                result = self.runner.run_cmd(f'reg query "{path}"')
                if result.success:
                    java_installed = True
                    break
            
            if not java_installed:
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.COMPLIANT,
                    risk_level=self.risk_level,
                    evidence="Java Runtime not installed - no browser plugin risk"
                )
            
            # Java is installed, check browser plugin setting
            return super().audit()
            
        except Exception as e:
            return ControlResult(
                control_id=self.control_id,
                name=self.name,
                category=self.category,
                status=ControlStatus.ERROR,
                risk_level=self.risk_level,
                evidence="Error checking Java browser plugin",
                error_message=str(e)
            )


class FlashDisabledControl(SecurityControl):
    """
    APPS-06: Flash Disabled
    Ensures Adobe Flash Player is disabled or uninstalled.
    Flash reached end-of-life in December 2020.
    """
    
    def __init__(self):
        super().__init__(
            control_id="APPS-06",
            name="Flash Player Disabled",
            description="Verify Adobe Flash Player is disabled/uninstalled (EOL)",
            category=CIACategory.APPLICATION,
            risk_level=RiskLevel.CRITICAL,
            cis_reference="N/A",
            nist_reference="CM-7"
        )
        self._supports_rollback = False  # Uninstall is not reversible
    
    def audit(self) -> ControlResult:
        """Check if Flash Player is installed."""
        try:
            # Check multiple Flash locations
            flash_paths = [
                r'HKLM\SOFTWARE\Macromedia\FlashPlayer',
                r'HKLM\SOFTWARE\WOW6432Node\Macromedia\FlashPlayer',
                r'HKLM\SOFTWARE\Adobe\FlashPlayer',
                r'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Adobe Flash Player'
            ]
            
            flash_found = False
            flash_location = None
            
            for path in flash_paths:
                result = self.runner.run_cmd(f'reg query "{path}"')
                if result.success:
                    flash_found = True
                    flash_location = path
                    break
            
            # Also check for Flash executable
            flash_exe_result = self.runner.run_powershell(
                'Test-Path "$env:SYSTEMROOT\\System32\\Macromed\\Flash\\Flash*.ocx"'
            )
            
            if flash_exe_result.success and 'True' in flash_exe_result.stdout:
                flash_found = True
                flash_location = 'System32\\Macromed\\Flash'
            
            if flash_found:
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.NON_COMPLIANT,
                    risk_level=self.risk_level,
                    evidence=f"Flash Player detected at: {flash_location}",
                    details="Adobe Flash reached EOL December 2020 - CRITICAL security risk"
                )
            else:
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.COMPLIANT,
                    risk_level=self.risk_level,
                    evidence="Adobe Flash Player not detected on this system"
                )
                
        except Exception as e:
            return ControlResult(
                control_id=self.control_id,
                name=self.name,
                category=self.category,
                status=ControlStatus.ERROR,
                risk_level=self.risk_level,
                evidence="Error checking Flash Player",
                error_message=str(e)
            )
    
    def remediate(self) -> bool:
        """Attempt to uninstall Flash Player."""
        try:
            # Try using the Flash uninstaller if present
            result = self.runner.run_powershell(
                '''
                $flashUninstaller = Get-ChildItem -Path "$env:SYSTEMROOT\\System32" -Filter "FlashUtil*.exe" -ErrorAction SilentlyContinue
                if ($flashUninstaller) {
                    Start-Process -FilePath $flashUninstaller.FullName -ArgumentList "-uninstall" -Wait -NoNewWindow
                    Write-Output "Flash uninstaller executed"
                } else {
                    Write-Output "Flash uninstaller not found"
                }
                '''
            )
            
            self._log('info', f"Flash remediation: {result.stdout}")
            return True
            
        except Exception as e:
            self._log('error', f"Flash remediation error: {str(e)}")
            return False
    
    def verify(self) -> ControlResult:
        """Verify Flash is removed."""
        return self.audit()


class DotNetStrongCryptoControl(MultiRegistryControl):
    """
    APPS-07: .NET Strong Crypto
    Ensures .NET Framework uses strong cryptography for TLS.
    """
    
    registry_checks = [
        {
            'path': r'HKLM\SOFTWARE\Microsoft\.NETFramework\v4.0.30319',
            'value': 'SchUseStrongCrypto',
            'expected': 1,
            'type': 'REG_DWORD',
            'comparison': 'equal'
        },
        {
            'path': r'HKLM\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319',
            'value': 'SchUseStrongCrypto',
            'expected': 1,
            'type': 'REG_DWORD',
            'comparison': 'equal'
        },
        {
            'path': r'HKLM\SOFTWARE\Microsoft\.NETFramework\v4.0.30319',
            'value': 'SystemDefaultTlsVersions',
            'expected': 1,
            'type': 'REG_DWORD',
            'comparison': 'equal'
        },
        {
            'path': r'HKLM\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319',
            'value': 'SystemDefaultTlsVersions',
            'expected': 1,
            'type': 'REG_DWORD',
            'comparison': 'equal'
        }
    ]
    require_all = True
    
    def __init__(self):
        super().__init__(
            control_id="APPS-07",
            name=".NET Strong Cryptography",
            description="Verify .NET Framework uses strong cryptography",
            category=CIACategory.APPLICATION,
            risk_level=RiskLevel.HIGH,
            cis_reference="CIS 18.4.1",
            nist_reference="SC-13"
        )


class TLS10TLS11DisabledControl(MultiRegistryControl):
    """
    APPS-08: TLS 1.0/1.1 Disabled
    Ensures deprecated TLS versions are disabled.
    """
    
    registry_checks = [
        # TLS 1.0 Client
        {
            'path': r'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client',
            'value': 'Enabled',
            'expected': 0,
            'type': 'REG_DWORD',
            'comparison': 'equal'
        },
        # TLS 1.0 Server
        {
            'path': r'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server',
            'value': 'Enabled',
            'expected': 0,
            'type': 'REG_DWORD',
            'comparison': 'equal'
        },
        # TLS 1.1 Client
        {
            'path': r'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client',
            'value': 'Enabled',
            'expected': 0,
            'type': 'REG_DWORD',
            'comparison': 'equal'
        },
        # TLS 1.1 Server
        {
            'path': r'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server',
            'value': 'Enabled',
            'expected': 0,
            'type': 'REG_DWORD',
            'comparison': 'equal'
        }
    ]
    require_all = True
    
    def __init__(self):
        super().__init__(
            control_id="APPS-08",
            name="TLS 1.0/1.1 Disabled",
            description="Verify deprecated TLS 1.0 and TLS 1.1 are disabled",
            category=CIACategory.APPLICATION,
            risk_level=RiskLevel.HIGH,
            cis_reference="CIS 18.4.2",
            nist_reference="SC-8"
        )
    
    def remediate(self) -> bool:
        """Disable TLS 1.0 and TLS 1.1."""
        try:
            success = True
            
            # Create registry keys and set values for TLS 1.0
            for protocol in ['TLS 1.0', 'TLS 1.1']:
                for endpoint in ['Client', 'Server']:
                    path = f'HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\{protocol}\\{endpoint}'
                    
                    # Create key if it doesn't exist
                    self.runner.run_cmd(f'reg add "{path}" /f')
                    
                    # Disable the protocol
                    result = self.runner.run_reg_add(path, 'Enabled', 'REG_DWORD', '0')
                    if not result.success:
                        success = False
                    
                    # Also set DisabledByDefault
                    self.runner.run_reg_add(path, 'DisabledByDefault', 'REG_DWORD', '1')
            
            if success:
                self._log('info', "TLS 1.0 and TLS 1.1 disabled")
            
            return success
            
        except Exception as e:
            self._log('error', f"TLS remediation error: {str(e)}")
            return False


class SSL20SSL30DisabledControl(MultiRegistryControl):
    """
    APPS-09: SSL 2.0/3.0 Disabled
    Ensures deprecated SSL versions are disabled.
    """
    
    registry_checks = [
        # SSL 2.0 Client
        {
            'path': r'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client',
            'value': 'Enabled',
            'expected': 0,
            'type': 'REG_DWORD',
            'comparison': 'equal'
        },
        # SSL 2.0 Server
        {
            'path': r'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server',
            'value': 'Enabled',
            'expected': 0,
            'type': 'REG_DWORD',
            'comparison': 'equal'
        },
        # SSL 3.0 Client
        {
            'path': r'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client',
            'value': 'Enabled',
            'expected': 0,
            'type': 'REG_DWORD',
            'comparison': 'equal'
        },
        # SSL 3.0 Server
        {
            'path': r'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server',
            'value': 'Enabled',
            'expected': 0,
            'type': 'REG_DWORD',
            'comparison': 'equal'
        }
    ]
    require_all = True
    
    def __init__(self):
        super().__init__(
            control_id="APPS-09",
            name="SSL 2.0/3.0 Disabled",
            description="Verify deprecated SSL 2.0 and SSL 3.0 are disabled",
            category=CIACategory.APPLICATION,
            risk_level=RiskLevel.CRITICAL,
            cis_reference="CIS 18.4.3",
            nist_reference="SC-8"
        )
    
    def remediate(self) -> bool:
        """Disable SSL 2.0 and SSL 3.0."""
        try:
            success = True
            
            for protocol in ['SSL 2.0', 'SSL 3.0']:
                for endpoint in ['Client', 'Server']:
                    path = f'HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\{protocol}\\{endpoint}'
                    
                    # Create key if it doesn't exist
                    self.runner.run_cmd(f'reg add "{path}" /f')
                    
                    # Disable the protocol
                    result = self.runner.run_reg_add(path, 'Enabled', 'REG_DWORD', '0')
                    if not result.success:
                        success = False
                    
                    # Also set DisabledByDefault
                    self.runner.run_reg_add(path, 'DisabledByDefault', 'REG_DWORD', '1')
            
            if success:
                self._log('info', "SSL 2.0 and SSL 3.0 disabled")
            
            return success
            
        except Exception as e:
            self._log('error', f"SSL remediation error: {str(e)}")
            return False


class CertificatePaddingCheckControl(RegistryControl):
    """
    APPS-10: Certificate Padding Check
    Ensures certificate padding check is enabled to prevent CVE-2020-0601.
    """
    
    registry_path = r'HKLM\SOFTWARE\Microsoft\Cryptography\Wintrust\Config'
    registry_value = 'EnableCertPaddingCheck'
    expected_data = 1
    value_type = 'REG_DWORD'
    comparison = 'equal'
    
    def __init__(self):
        super().__init__(
            control_id="APPS-10",
            name="Certificate Padding Check",
            description="Verify certificate padding check is enabled (CVE-2020-0601)",
            category=CIACategory.APPLICATION,
            risk_level=RiskLevel.HIGH,
            cis_reference="N/A",
            nist_reference="SC-17"
        )


class WDACAppLockerControl(SecurityControl):
    """
    APPS-11: Windows Defender Application Control / AppLocker
    Verifies application whitelisting is configured for
    zero-trust application execution model.
    
    Checks WDAC first (modern, preferred), falls back to AppLocker (legacy).
    Remediation is NOT automatic as policy deployment requires careful planning.
    """
    
    def __init__(self):
        super().__init__(
            control_id="APPS-11",
            name="Application Whitelisting (WDAC/AppLocker)",
            description="Verify WDAC or AppLocker policies restrict application execution",
            category=CIACategory.APPLICATION,
            risk_level=RiskLevel.CRITICAL,
            cis_reference="CIS 18.9.67",
            nist_reference="CM-7(5)"
        )
        # Remediation requires careful policy design - not automatic
        self._supports_rollback = False
    
    def _capture_current_state(self) -> Optional[Dict[str, Any]]:
        """Capture is not supported for WDAC/AppLocker."""
        return None
    
    def _restore_state(self, state_data: Dict[str, Any]) -> bool:
        """Restoration not supported."""
        return False
    
    def audit(self) -> ControlResult:
        """Check WDAC or AppLocker status."""
        try:
            wdac_status = None
            applocker_status = None
            
            # Check WDAC (Windows Defender Application Control) first
            wdac_check = self.runner.run_powershell(
                'try { '
                '$policy = Get-CimInstance -Namespace root/Microsoft/Windows/CI '
                '-ClassName MSFT_CodeIntegrityPolicy -ErrorAction Stop; '
                'if ($policy) { '
                'Write-Output "WDAC_FOUND"; '
                'Write-Output "IsEnforced=$($policy.IsEnforced)"; '
                'Write-Output "IsAudit=$($policy.IsAuditMode)" '
                '} else { Write-Output "NO_WDAC" } '
                '} catch { Write-Output "WDAC_ERROR: $_" }'
            )
            
            if wdac_check.success and wdac_check.stdout:
                output = wdac_check.stdout.strip()
                if 'WDAC_FOUND' in output:
                    is_enforced = 'IsEnforced=True' in output
                    is_audit = 'IsAudit=True' in output
                    
                    if is_enforced:
                        return ControlResult(
                            control_id=self.control_id,
                            name=self.name,
                            category=self.category,
                            status=ControlStatus.COMPLIANT,
                            risk_level=self.risk_level,
                            evidence="WDAC policy active (enforcing mode)",
                            details="Windows Defender Application Control is enabled in enforcement mode. "
                                    "Only approved applications can execute. Excellent zero-trust posture.",
                            command_output=output[:500]
                        )
                    elif is_audit:
                        return ControlResult(
                            control_id=self.control_id,
                            name=self.name,
                            category=self.category,
                            status=ControlStatus.NON_COMPLIANT,
                            risk_level=self.risk_level,
                            evidence="WDAC policy in audit mode (not enforcing)",
                            details="WDAC is configured but in audit-only mode. Applications are not blocked. "
                                    "Review audit logs and switch to enforcement when ready.",
                            command_output=output[:500]
                        )
            
            # Check AppLocker if WDAC not found
            applocker_service = self.runner.run_powershell(
                'Get-Service -Name AppIDSvc -ErrorAction SilentlyContinue | '
                'Select-Object Status, StartType | ConvertTo-Json'
            )
            
            applocker_policy = self.runner.run_powershell(
                'try { '
                '$policy = Get-AppLockerPolicy -Effective -ErrorAction Stop; '
                'if ($policy.RuleCollections.Count -gt 0) { '
                '$exe = ($policy.RuleCollections | Where-Object { $_.RuleCollectionType -eq "Exe" }); '
                '$script = ($policy.RuleCollections | Where-Object { $_.RuleCollectionType -eq "Script" }); '
                'Write-Output "APPLOCKER_FOUND"; '
                'Write-Output "ExeRules=$($exe.Count)"; '
                'Write-Output "ScriptRules=$($script.Count)"; '
                'Write-Output "EnforcementMode=$($exe.EnforcementMode)" '
                '} else { Write-Output "NO_RULES" } '
                '} catch { Write-Output "APPLOCKER_ERROR: $_" }'
            )
            
            if applocker_policy.success and 'APPLOCKER_FOUND' in applocker_policy.stdout:
                output = applocker_policy.stdout.strip()
                is_enforcing = 'EnforcementMode=Enabled' in output or 'EnforcementMode=1' in output
                
                if is_enforcing:
                    return ControlResult(
                        control_id=self.control_id,
                        name=self.name,
                        category=self.category,
                        status=ControlStatus.COMPLIANT,
                        risk_level=self.risk_level,
                        evidence="AppLocker policy active (enforcing mode)",
                        details="AppLocker is enabled in enforcement mode. Consider migrating to WDAC "
                                "for better security and management capabilities.",
                        command_output=output[:500]
                    )
                else:
                    return ControlResult(
                        control_id=self.control_id,
                        name=self.name,
                        category=self.category,
                        status=ControlStatus.NON_COMPLIANT,
                        risk_level=self.risk_level,
                        evidence="AppLocker in audit mode (not enforcing)",
                        details="AppLocker has rules but is in audit-only mode. Applications are logged "
                                "but not blocked. Switch to enforcement mode when ready.",
                        command_output=output[:500]
                    )
            
            # Neither WDAC nor AppLocker configured
            return ControlResult(
                control_id=self.control_id,
                name=self.name,
                category=self.category,
                status=ControlStatus.NON_COMPLIANT,
                risk_level=self.risk_level,
                evidence="No application whitelisting configured",
                details="Neither WDAC nor AppLocker is configured. Any application can execute. "
                        "Deploy WDAC (recommended) or AppLocker policies to restrict execution to "
                        "approved applications only. See: https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/",
                command_output=f"WDAC: {wdac_check.stdout[:200] if wdac_check.stdout else 'N/A'}"
            )
                
        except Exception as e:
            return ControlResult(
                control_id=self.control_id,
                name=self.name,
                category=self.category,
                status=ControlStatus.ERROR,
                risk_level=self.risk_level,
                evidence="Error checking WDAC/AppLocker status",
                error_message=str(e)
            )
    
    def remediate(self) -> bool:
        """
        Remediation for WDAC/AppLocker is NOT automatic.
        Policy deployment requires careful planning and testing.
        """
        self._log('warning', 
                  f"[{self.control_id}] WDAC/AppLocker requires manual policy deployment. "
                  "Automatic remediation is not supported due to the risk of blocking "
                  "legitimate applications. See Microsoft documentation for deployment guidance.")
        return False
    
    def verify(self) -> ControlResult:
        """Verify WDAC/AppLocker status."""
        return self.audit()


class PowerShellConstrainedLanguageControl(SecurityControl):
    """
    APPS-12: PowerShell Constrained Language Mode
    Verifies PowerShell is configured to use Constrained Language Mode to limit
    the attack surface by restricting access to sensitive .NET types and methods.
    """
    
    def __init__(self):
        super().__init__(
            control_id="APPS-12",
            name="PowerShell Constrained Language Mode",
            description="Verify PowerShell Constrained Language Mode is enforced",
            category=CIACategory.APPLICATION,
            risk_level=RiskLevel.HIGH,
            cis_reference="CIS 18.9.102",
            nist_reference="CM-7(2)"
        )
        self._supports_rollback = True
    
    def audit(self) -> ControlResult:
        """Check PowerShell language mode configuration."""
        try:
            # Check current language mode
            lang_mode_check = "$ExecutionContext.SessionState.LanguageMode"
            lang_result = self.runner.run_powershell(lang_mode_check)
            current_mode = lang_result.stdout.strip() if lang_result.success else "Unknown"
            
            # Check __PSLockdownPolicy environment variable
            lockdown_check = "[Environment]::GetEnvironmentVariable('__PSLockdownPolicy', 'Machine')"
            lockdown_result = self.runner.run_powershell(lockdown_check)
            lockdown_policy = lockdown_result.stdout.strip() if lockdown_result.success else None
            
            # Check if WDAC/AppLocker is enforcing CLM
            wdac_check = """
            $ci = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\\Microsoft\\Windows\\DeviceGuard -ErrorAction SilentlyContinue
            if ($ci -and $ci.CodeIntegrityPolicyEnforcementStatus -eq 2) { "WDAC_ENFORCED" } else { "NO_WDAC" }
            """
            wdac_result = self.runner.run_powershell(wdac_check)
            wdac_enforced = wdac_result.success and "WDAC_ENFORCED" in wdac_result.stdout
            
            evidence_parts = [f"Current session mode: {current_mode}"]
            
            if lockdown_policy:
                evidence_parts.append(f"__PSLockdownPolicy: {lockdown_policy}")
            
            if wdac_enforced:
                evidence_parts.append("WDAC enforcing CLM")
            
            evidence = "; ".join(evidence_parts)
            
            # Compliant if CLM is active or lockdown policy is set
            if current_mode == "ConstrainedLanguage":
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.COMPLIANT,
                    risk_level=self.risk_level,
                    evidence="PowerShell Constrained Language Mode is active",
                    command_output=evidence
                )
            elif lockdown_policy == "4":
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.COMPLIANT,
                    risk_level=self.risk_level,
                    evidence="__PSLockdownPolicy is set to enforce CLM (new sessions will use CLM)",
                    command_output=evidence
                )
            elif wdac_enforced:
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.COMPLIANT,
                    risk_level=self.risk_level,
                    evidence="WDAC is enforcing Constrained Language Mode",
                    command_output=evidence
                )
            else:
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.NON_COMPLIANT,
                    risk_level=self.risk_level,
                    evidence=f"PowerShell is in {current_mode} mode (Full Language allows arbitrary .NET execution)",
                    details="PowerShell is in Full Language Mode which allows access to all .NET types. "
                            "Enable Constrained Language Mode via WDAC policy (recommended) or "
                            "set __PSLockdownPolicy=4 environment variable. Warning: May break admin scripts."
                )
            
        except Exception as e:
            return ControlResult(
                control_id=self.control_id,
                name=self.name,
                category=self.category,
                status=ControlStatus.ERROR,
                risk_level=self.risk_level,
                error_message=str(e)
            )
    
    def remediate(self) -> bool:
        """Set __PSLockdownPolicy to enable Constrained Language Mode."""
        try:
            # Set system environment variable
            ps_cmd = "[Environment]::SetEnvironmentVariable('__PSLockdownPolicy', '4', 'Machine')"
            result = self.runner.run_powershell(ps_cmd)
            
            if result.success:
                self.logger.warning(
                    "PowerShell Constrained Language Mode enabled via __PSLockdownPolicy. "
                    "New PowerShell sessions will use CLM. Warning: Administrative scripts "
                    "may need to be updated or signed to work properly."
                )
            return result.success
        except Exception as e:
            self.logger.error(f"Failed to enable PowerShell CLM: {e}")
            return False
    
    def rollback(self) -> bool:
        """Remove __PSLockdownPolicy to restore Full Language Mode."""
        try:
            ps_cmd = "[Environment]::SetEnvironmentVariable('__PSLockdownPolicy', $null, 'Machine')"
            result = self.runner.run_powershell(ps_cmd)
            return result.success
        except Exception:
            return False
    
    def verify(self) -> ControlResult:
        """Verify PowerShell language mode configuration."""
        return self.audit()


class ApplicationSecurityControls(ControlGroup):
    """Collection of all Application Security controls."""
    
    def __init__(self):
        super().__init__(
            name="Application Security Controls",
            category=CIACategory.APPLICATION,
            description="Controls for securing applications and preventing exploitation"
        )
        
        # Add all application security controls (APPS-01 to APPS-11)
        self.add_control(OfficeMacroDisabledControl())
        self.add_control(OfficeOLEDisabledControl())
        self.add_control(AdobeReaderProtectedModeControl())
        self.add_control(BrowserExtensionsAuditControl())
        self.add_control(JavaBrowserDisabledControl())
        self.add_control(FlashDisabledControl())
        self.add_control(DotNetStrongCryptoControl())
        self.add_control(TLS10TLS11DisabledControl())
        self.add_control(SSL20SSL30DisabledControl())
        self.add_control(CertificatePaddingCheckControl())
        # v2.2: New enterprise control
        self.add_control(WDACAppLockerControl())
        # v2.3: Additional enterprise control (APPS-12)
        self.add_control(PowerShellConstrainedLanguageControl())
    
    def initialize(self, runner, logger):
        """Initialize all controls with dependencies."""
        for control in self.controls:
            control.set_dependencies(runner, logger)
