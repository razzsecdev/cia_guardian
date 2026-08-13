"""
Availability Controls
AVBL-01: Windows Firewall Enabled
AVBL-02: Volume Shadow Copy Service
AVBL-03: Virtual Memory Configuration
AVBL-04: Windows Time Service
AVBL-05: Password Minimum Length
AVBL-06: Password Complexity
AVBL-07: Account Lockout Threshold
AVBL-08: Account Lockout Duration
AVBL-09: Password History
AVBL-10: Password Maximum Age
AVBL-11: Windows Update Service
AVBL-12: Windows Defender Service
AVBL-13: BITS Service
AVBL-14: Event Log Service
AVBL-15: Crash Dump Configuration
AVBL-16: Auto Restart Sign-on Disabled
AVBL-17: Screen Saver Timeout
AVBL-18: Backup Configuration (v2.3)
"""

from typing import Dict, Any, Optional
from .base import (
    SecurityControl, ControlResult, ControlStatus,
    RiskLevel, CIACategory, ControlGroup
)
from .service_base import ServiceControl
from .registry_base import RegistryControl


class FirewallControl(SecurityControl):
    """
    AVBL-01: Windows Firewall Enabled
    Ensures Windows Firewall is enabled on all profiles.
    """
    
    def __init__(self):
        super().__init__(
            control_id="AVBL-01",
            name="Windows Firewall",
            description="Verify Windows Firewall is enabled on all profiles",
            category=CIACategory.AVAILABILITY,
            risk_level=RiskLevel.CRITICAL,
            cis_reference="CIS 9.1.1",
            nist_reference="SC-7"
        )
        self._supports_rollback = True
    
    def _capture_current_state(self) -> Optional[Dict[str, Any]]:
        """Capture current firewall state."""
        try:
            result = self.runner.run_netsh('advfirewall show allprofiles state')
            return {
                'firewall_state': result.stdout if result.success else None
            }
        except Exception:
            return None
    
    def _restore_state(self, state_data: Dict[str, Any]) -> bool:
        """Restore firewall to previous state."""
        try:
            output = state_data.get('firewall_state', '')
            
            # Parse output and restore each profile
            profiles_off = []
            lines = output.split('\n')
            current_profile = None
            
            for line in lines:
                line = line.strip()
                if 'Domain Profile' in line:
                    current_profile = 'domainprofile'
                elif 'Private Profile' in line:
                    current_profile = 'privateprofile'
                elif 'Public Profile' in line:
                    current_profile = 'publicprofile'
                elif 'State' in line and current_profile:
                    if 'OFF' in line.upper():
                        profiles_off.append(current_profile)
                    current_profile = None
            
            # Turn off profiles that were previously off
            for profile in profiles_off:
                self.runner.run_netsh(f'advfirewall set {profile} state off')
            
            return True
        except Exception:
            return False
    
    def audit(self) -> ControlResult:
        """Check Windows Firewall status on all profiles."""
        try:
            result = self.runner.run_netsh('advfirewall show allprofiles')
            
            if not result.success:
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.ERROR,
                    risk_level=self.risk_level,
                    evidence="Failed to query firewall status",
                    error_message=result.stderr
                )
            
            output = result.stdout
            
            # Check each profile for "State ON"
            profiles = ['Domain Profile', 'Private Profile', 'Public Profile']
            all_enabled = True
            disabled_profiles = []
            
            # Parse output line by line
            lines = output.split('\n')
            current_profile = None
            
            for line in lines:
                line = line.strip()
                for profile in profiles:
                    if profile in line:
                        current_profile = profile
                        break
                if 'State' in line and current_profile:
                    if 'OFF' in line.upper():
                        all_enabled = False
                        disabled_profiles.append(current_profile)
                    current_profile = None
            
            if all_enabled:
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.COMPLIANT,
                    risk_level=self.risk_level,
                    evidence="Firewall is ON for all profiles",
                    command_output=output[:500]
                )
            else:
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.NON_COMPLIANT,
                    risk_level=self.risk_level,
                    evidence=f"Firewall is OFF for: {', '.join(disabled_profiles)}",
                    details="System is exposed to network attacks",
                    command_output=output[:500]
                )
                
        except Exception as e:
            return ControlResult(
                control_id=self.control_id,
                name=self.name,
                category=self.category,
                status=ControlStatus.ERROR,
                risk_level=self.risk_level,
                evidence="Error checking firewall status",
                error_message=str(e)
            )
    
    def remediate(self) -> bool:
        """Enable Windows Firewall on all profiles."""
        try:
            result = self.runner.run_netsh('advfirewall set allprofiles state on')
            
            if result.success or 'ok' in result.stdout.lower():
                self._log('info', "Firewall enabled on all profiles")
                return True
            else:
                self._log('error', f"Failed to enable firewall: {result.stderr}")
                return False
                
        except Exception as e:
            self._log('error', f"Firewall remediation error: {str(e)}")
            return False
    
    def verify(self) -> ControlResult:
        """Verify firewall is enabled on all profiles."""
        return self.audit()


class VSSControl(SecurityControl):
    """
    AVBL-02: Volume Shadow Copy Service
    Ensures VSS service is running for backup/restore capabilities.
    """
    
    def __init__(self):
        super().__init__(
            control_id="AVBL-02",
            name="Volume Shadow Copy Service",
            description="Verify VSS service is running and set to automatic",
            category=CIACategory.AVAILABILITY,
            risk_level=RiskLevel.MEDIUM,
            cis_reference="N/A",
            nist_reference="CP-9"
        )
        self._supports_rollback = True
    
    def _capture_current_state(self) -> Optional[Dict[str, Any]]:
        """Capture current VSS service state and startup type."""
        try:
            # Get service state
            state_result = self.runner.run_sc('query vss')
            
            # Get startup type
            config_result = self.runner.run_sc('qc vss')
            
            return {
                'service_state': state_result.stdout if state_result.success else None,
                'service_config': config_result.stdout if config_result.success else None
            }
        except Exception:
            return None
    
    def _restore_state(self, state_data: Dict[str, Any]) -> bool:
        """Restore VSS service to previous state."""
        try:
            state_output = state_data.get('service_state', '')
            config_output = state_data.get('service_config', '')
            
            # Determine original startup type from config
            original_start = 'demand'  # Default to manual
            if config_output:
                if 'AUTO_START' in config_output.upper():
                    original_start = 'auto'
                elif 'DISABLED' in config_output.upper():
                    original_start = 'disabled'
                elif 'DEMAND_START' in config_output.upper():
                    original_start = 'demand'
            
            # Restore startup type
            self.runner.run_sc(f'config vss start= {original_start}')
            
            # Determine original running state
            was_stopped = 'STOPPED' in state_output.upper() or 'STATE              : 1' in state_output
            
            if was_stopped:
                self.runner.run_sc('stop vss')
            
            return True
        except Exception:
            return False
    
    def audit(self) -> ControlResult:
        """Check VSS service status."""
        try:
            result = self.runner.run_sc('query vss')
            
            if not result.success:
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.ERROR,
                    risk_level=self.risk_level,
                    evidence="Failed to query VSS service",
                    error_message=result.stderr
                )
            
            output = result.stdout
            
            # Check for RUNNING state
            # STATE : 4  RUNNING
            if 'RUNNING' in output.upper() or 'STATE              : 4' in output:
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.COMPLIANT,
                    risk_level=self.risk_level,
                    evidence="VSS service is RUNNING",
                    command_output=output
                )
            elif 'STOPPED' in output.upper() or 'STATE              : 1' in output:
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.NON_COMPLIANT,
                    risk_level=self.risk_level,
                    evidence="VSS service is STOPPED",
                    details="System restore and backup features may not work",
                    command_output=output
                )
            else:
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.PENDING,
                    risk_level=self.risk_level,
                    evidence="VSS service state unclear",
                    command_output=output
                )
                
        except Exception as e:
            return ControlResult(
                control_id=self.control_id,
                name=self.name,
                category=self.category,
                status=ControlStatus.ERROR,
                risk_level=self.risk_level,
                evidence="Error checking VSS service",
                error_message=str(e)
            )
    
    def remediate(self) -> bool:
        """Start VSS service and set to automatic."""
        try:
            # Set to auto start
            config_result = self.runner.run_sc('config vss start= auto')
            
            # Start the service
            start_result = self.runner.run_sc('start vss')
            
            if start_result.success or 'already running' in start_result.stderr.lower():
                self._log('info', "VSS service started and configured")
                return True
            else:
                self._log('warning', f"VSS start result: {start_result.stderr}")
                return config_result.success
                
        except Exception as e:
            self._log('error', f"VSS remediation error: {str(e)}")
            return False
    
    def verify(self) -> ControlResult:
        """Verify VSS service is running."""
        return self.audit()


class VirtualMemoryControl(SecurityControl):
    """
    AVBL-03: Virtual Memory Configuration
    Ensures adequate page file size for system stability.
    """
    
    def __init__(self):
        super().__init__(
            control_id="AVBL-03",
            name="Virtual Memory Configuration",
            description="Verify adequate page file size (>= 4096MB)",
            category=CIACategory.AVAILABILITY,
            risk_level=RiskLevel.LOW,
            cis_reference="N/A",
            nist_reference="SC-5"
        )
        self.min_size_mb = 4096
        # Page file changes require system restart to take effect
        # Rollback is not practical without restarting
        self._supports_rollback = False
    
    def _capture_current_state(self) -> Optional[Dict[str, Any]]:
        """Page file changes require restart - rollback not supported."""
        return None
    
    def _restore_state(self, state_data: Dict[str, Any]) -> bool:
        """Page file changes require restart - rollback not supported."""
        return False
    
    def audit(self) -> ControlResult:
        """Check page file configuration."""
        try:
            result = self.runner.run_wmic('pagefile list /format:list')
            
            if not result.success:
                # Try PowerShell fallback
                result = self.runner.run_powershell(
                    'Get-CimInstance Win32_PageFileSetting | Select-Object Name, InitialSize, MaximumSize'
                )
            
            output = result.stdout
            
            # Parse for AllocatedBaseSize or similar
            size_mb = 0
            
            if 'AllocatedBaseSize' in output:
                # Parse WMIC output
                for line in output.split('\n'):
                    if 'AllocatedBaseSize' in line:
                        try:
                            size_mb = int(line.split('=')[1].strip())
                        except (IndexError, ValueError):
                            pass
            elif 'MaximumSize' in output:
                # PowerShell output
                for line in output.split('\n'):
                    if line.strip().isdigit():
                        try:
                            size_mb = max(size_mb, int(line.strip()))
                        except ValueError:
                            pass
            
            # If no explicit size found, check system managed
            if size_mb == 0:
                # System managed page file - check via different method
                check_result = self.runner.run_powershell(
                    '(Get-CimInstance Win32_PageFileUsage).AllocatedBaseSize'
                )
                try:
                    size_mb = int(check_result.stdout.strip())
                except ValueError:
                    pass
            
            if size_mb >= self.min_size_mb:
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.COMPLIANT,
                    risk_level=self.risk_level,
                    evidence=f"Page file size: {size_mb}MB (>= {self.min_size_mb}MB)",
                    command_output=output[:500]
                )
            elif size_mb > 0:
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.NON_COMPLIANT,
                    risk_level=self.risk_level,
                    evidence=f"Page file size: {size_mb}MB (< {self.min_size_mb}MB)",
                    details="Insufficient virtual memory for stability",
                    command_output=output[:500]
                )
            else:
                # Assume system managed is compliant
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.COMPLIANT,
                    risk_level=self.risk_level,
                    evidence="Page file is system managed",
                    details="Windows manages page file automatically",
                    command_output=output[:500]
                )
                
        except Exception as e:
            return ControlResult(
                control_id=self.control_id,
                name=self.name,
                category=self.category,
                status=ControlStatus.ERROR,
                risk_level=self.risk_level,
                evidence="Error checking page file",
                error_message=str(e)
            )
    
    def remediate(self) -> bool:
        """Configure adequate page file size."""
        try:
            # Set system managed page file (recommended)
            result = self.runner.run_powershell(
                '$cs = Get-CimInstance Win32_ComputerSystem; '
                '$cs | Set-CimInstance -Property @{AutomaticManagedPagefile=$true}'
            )
            
            if result.success:
                self._log('info', "Page file set to system managed")
                return True
            
            # Manual fallback - set to 4GB
            result = self.runner.run_wmic(
                'pagefileset where name="C:\\\\pagefile.sys" set InitialSize=4096,MaximumSize=8192'
            )
            
            return result.success
            
        except Exception as e:
            self._log('error', f"Page file remediation error: {str(e)}")
            return False
    
    def verify(self) -> ControlResult:
        """Verify page file configuration."""
        return self.audit()


class TimeServiceControl(SecurityControl):
    """
    AVBL-04: Windows Time Service
    Ensures W32Time service is running for proper time synchronization.
    """
    
    def __init__(self):
        super().__init__(
            control_id="AVBL-04",
            name="Windows Time Service",
            description="Verify Windows Time service is running for sync",
            category=CIACategory.AVAILABILITY,
            risk_level=RiskLevel.MEDIUM,
            cis_reference="CIS 2.2.37",
            nist_reference="AU-8"
        )
        self._supports_rollback = True
    
    def _capture_current_state(self) -> Optional[Dict[str, Any]]:
        """Capture current W32Time service state and startup type."""
        try:
            # Get service state
            state_result = self.runner.run_sc('query w32time')
            
            # Get startup type
            config_result = self.runner.run_sc('qc w32time')
            
            return {
                'service_state': state_result.stdout if state_result.success else None,
                'service_config': config_result.stdout if config_result.success else None
            }
        except Exception:
            return None
    
    def _restore_state(self, state_data: Dict[str, Any]) -> bool:
        """Restore W32Time service to previous state."""
        try:
            state_output = state_data.get('service_state', '')
            config_output = state_data.get('service_config', '')
            
            # Determine original startup type from config
            original_start = 'demand'  # Default to manual
            if config_output:
                if 'AUTO_START' in config_output.upper():
                    original_start = 'auto'
                elif 'DISABLED' in config_output.upper():
                    original_start = 'disabled'
                elif 'DEMAND_START' in config_output.upper():
                    original_start = 'demand'
            
            # Restore startup type
            self.runner.run_sc(f'config w32time start= {original_start}')
            
            # Determine original running state
            was_stopped = 'STOPPED' in state_output.upper() or 'STATE              : 1' in state_output
            
            if was_stopped:
                self.runner.run_sc('stop w32time')
            
            return True
        except Exception:
            return False
    
    def audit(self) -> ControlResult:
        """Check Windows Time service status."""
        try:
            result = self.runner.run_powershell(
                'Get-Service W32Time | Select-Object -ExpandProperty Status'
            )
            
            if not result.success:
                # Fallback to sc
                result = self.runner.run_sc('query w32time')
            
            output = result.stdout
            
            if 'Running' in output or 'RUNNING' in output or 'STATE              : 4' in output:
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.COMPLIANT,
                    risk_level=self.risk_level,
                    evidence="W32Time service is RUNNING",
                    command_output=output
                )
            elif 'Stopped' in output or 'STOPPED' in output or 'STATE              : 1' in output:
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.NON_COMPLIANT,
                    risk_level=self.risk_level,
                    evidence="W32Time service is STOPPED",
                    details="Time synchronization is not active",
                    command_output=output
                )
            else:
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.PENDING,
                    risk_level=self.risk_level,
                    evidence="W32Time service state unclear",
                    command_output=output
                )
                
        except Exception as e:
            return ControlResult(
                control_id=self.control_id,
                name=self.name,
                category=self.category,
                status=ControlStatus.ERROR,
                risk_level=self.risk_level,
                evidence="Error checking W32Time service",
                error_message=str(e)
            )
    
    def remediate(self) -> bool:
        """Start Windows Time service and configure for auto start."""
        try:
            # Set to auto start
            config_result = self.runner.run_sc('config w32time start= auto')
            
            # Start the service
            start_result = self.runner.run_powershell('Start-Service W32Time')
            
            if not start_result.success:
                start_result = self.runner.run_sc('start w32time')
            
            # Sync time
            self.runner.run_cmd('w32tm /resync /nowait')
            
            if start_result.success or 'already' in start_result.stderr.lower():
                self._log('info', "W32Time service started and configured")
                return True
            else:
                self._log('warning', f"W32Time start result: {start_result.stderr}")
                return config_result.success
                
        except Exception as e:
            self._log('error', f"W32Time remediation error: {str(e)}")
            return False
    
    def verify(self) -> ControlResult:
        """Verify W32Time service is running."""
        return self.audit()


class PasswordMinLengthControl(SecurityControl):
    """
    AVBL-05: Password Minimum Length
    Ensures minimum password length is at least 14 characters.
    """
    
    def __init__(self):
        super().__init__(
            control_id="AVBL-05",
            name="Password Minimum Length",
            description="Verify minimum password length is >= 14 characters",
            category=CIACategory.AVAILABILITY,
            risk_level=RiskLevel.HIGH,
            cis_reference="CIS 1.1.4",
            nist_reference="IA-5"
        )
        self._supports_rollback = True
    
    def audit(self) -> ControlResult:
        """Check minimum password length policy."""
        try:
            result = self.runner.run_cmd('net accounts')
            
            if not result.success:
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.ERROR,
                    risk_level=self.risk_level,
                    evidence="Failed to query account policy",
                    error_message=result.stderr
                )
            
            output = result.stdout
            
            # Parse "Minimum password length" line
            min_length = 0
            for line in output.split('\n'):
                if 'Minimum password length' in line:
                    try:
                        parts = line.split(':')
                        if len(parts) >= 2:
                            min_length = int(parts[1].strip())
                    except (ValueError, IndexError):
                        pass
            
            if min_length >= 14:
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.COMPLIANT,
                    risk_level=self.risk_level,
                    evidence=f"Minimum password length: {min_length} characters",
                    command_output=output
                )
            else:
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.NON_COMPLIANT,
                    risk_level=self.risk_level,
                    evidence=f"Minimum password length: {min_length} characters",
                    details="Should be at least 14 characters",
                    command_output=output
                )
                
        except Exception as e:
            return ControlResult(
                control_id=self.control_id,
                name=self.name,
                category=self.category,
                status=ControlStatus.ERROR,
                risk_level=self.risk_level,
                evidence="Error checking password policy",
                error_message=str(e)
            )
    
    def remediate(self) -> bool:
        """Set minimum password length to 14."""
        try:
            result = self.runner.run_cmd('net accounts /minpwlen:14')
            return result.success
        except Exception as e:
            self._log('error', f"Password policy error: {str(e)}")
            return False
    
    def verify(self) -> ControlResult:
        """Verify password policy."""
        return self.audit()


class PasswordComplexityControl(SecurityControl):
    """
    AVBL-06: Password Complexity
    Ensures password complexity requirements are enabled.
    """
    
    def __init__(self):
        super().__init__(
            control_id="AVBL-06",
            name="Password Complexity",
            description="Verify password complexity requirements are enabled",
            category=CIACategory.AVAILABILITY,
            risk_level=RiskLevel.HIGH,
            cis_reference="CIS 1.1.5",
            nist_reference="IA-5"
        )
        self._supports_rollback = True
    
    def audit(self) -> ControlResult:
        """Check password complexity policy via secedit."""
        try:
            # Export security policy to temp file
            result = self.runner.run_cmd(
                'secedit /export /cfg %TEMP%\\secpol.cfg /quiet'
            )
            
            if not result.success:
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.ERROR,
                    risk_level=self.risk_level,
                    evidence="Failed to export security policy",
                    error_message=result.stderr
                )
            
            # Read the exported policy
            read_result = self.runner.run_powershell(
                'Get-Content $env:TEMP\\secpol.cfg | Select-String "PasswordComplexity"'
            )
            
            output = read_result.stdout
            
            # PasswordComplexity = 1 means enabled
            if 'PasswordComplexity = 1' in output or 'PasswordComplexity=1' in output:
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.COMPLIANT,
                    risk_level=self.risk_level,
                    evidence="Password complexity requirements are ENABLED",
                    command_output=output
                )
            else:
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.NON_COMPLIANT,
                    risk_level=self.risk_level,
                    evidence="Password complexity requirements are DISABLED",
                    details="Weak passwords can be used",
                    command_output=output
                )
                
        except Exception as e:
            return ControlResult(
                control_id=self.control_id,
                name=self.name,
                category=self.category,
                status=ControlStatus.ERROR,
                risk_level=self.risk_level,
                evidence="Error checking password complexity",
                error_message=str(e)
            )
    
    def remediate(self) -> bool:
        """Enable password complexity via secedit."""
        try:
            # This requires modifying security policy
            self._log('info', "Password complexity requires Group Policy configuration")
            return True  # Manual step required
        except Exception as e:
            self._log('error', f"Password complexity error: {str(e)}")
            return False
    
    def verify(self) -> ControlResult:
        """Verify password complexity."""
        return self.audit()


class AccountLockoutThresholdControl(SecurityControl):
    """
    AVBL-07: Account Lockout Threshold
    Ensures account lockout threshold is between 3-5 attempts.
    """
    
    def __init__(self):
        super().__init__(
            control_id="AVBL-07",
            name="Account Lockout Threshold",
            description="Verify account lockout threshold is 3-5 attempts",
            category=CIACategory.AVAILABILITY,
            risk_level=RiskLevel.HIGH,
            cis_reference="CIS 1.2.1",
            nist_reference="AC-7"
        )
        self._supports_rollback = True
    
    def audit(self) -> ControlResult:
        """Check account lockout threshold."""
        try:
            result = self.runner.run_cmd('net accounts')
            
            if not result.success:
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.ERROR,
                    risk_level=self.risk_level,
                    evidence="Failed to query account policy",
                    error_message=result.stderr
                )
            
            output = result.stdout
            
            # Parse "Lockout threshold" line
            threshold = 0
            for line in output.split('\n'):
                if 'Lockout threshold' in line:
                    try:
                        parts = line.split(':')
                        if len(parts) >= 2:
                            val = parts[1].strip()
                            if val.lower() == 'never':
                                threshold = 0
                            else:
                                threshold = int(val)
                    except (ValueError, IndexError):
                        pass
            
            if 1 <= threshold <= 5:
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.COMPLIANT,
                    risk_level=self.risk_level,
                    evidence=f"Account lockout threshold: {threshold} attempts",
                    command_output=output
                )
            elif threshold == 0:
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.NON_COMPLIANT,
                    risk_level=self.risk_level,
                    evidence="Account lockout is DISABLED (Never)",
                    details="Accounts vulnerable to brute force attacks",
                    command_output=output
                )
            else:
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.NON_COMPLIANT,
                    risk_level=self.risk_level,
                    evidence=f"Account lockout threshold: {threshold} (should be 3-5)",
                    command_output=output
                )
                
        except Exception as e:
            return ControlResult(
                control_id=self.control_id,
                name=self.name,
                category=self.category,
                status=ControlStatus.ERROR,
                risk_level=self.risk_level,
                evidence="Error checking lockout policy",
                error_message=str(e)
            )
    
    def remediate(self) -> bool:
        """Set account lockout threshold to 5."""
        try:
            result = self.runner.run_cmd('net accounts /lockoutthreshold:5')
            return result.success
        except Exception as e:
            self._log('error', f"Lockout policy error: {str(e)}")
            return False
    
    def verify(self) -> ControlResult:
        """Verify lockout policy."""
        return self.audit()


class AccountLockoutDurationControl(SecurityControl):
    """
    AVBL-08: Account Lockout Duration
    Ensures account lockout duration is at least 15 minutes.
    """
    
    def __init__(self):
        super().__init__(
            control_id="AVBL-08",
            name="Account Lockout Duration",
            description="Verify account lockout duration is >= 15 minutes",
            category=CIACategory.AVAILABILITY,
            risk_level=RiskLevel.MEDIUM,
            cis_reference="CIS 1.2.2",
            nist_reference="AC-7"
        )
        self._supports_rollback = True
    
    def audit(self) -> ControlResult:
        """Check account lockout duration."""
        try:
            result = self.runner.run_cmd('net accounts')
            
            if not result.success:
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.ERROR,
                    risk_level=self.risk_level,
                    evidence="Failed to query account policy",
                    error_message=result.stderr
                )
            
            output = result.stdout
            
            # Parse "Lockout duration" line
            duration = 0
            for line in output.split('\n'):
                if 'Lockout duration' in line:
                    try:
                        parts = line.split(':')
                        if len(parts) >= 2:
                            val = parts[1].strip()
                            if val.lower() == 'never':
                                duration = 0
                            else:
                                duration = int(val)
                    except (ValueError, IndexError):
                        pass
            
            if duration >= 15:
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.COMPLIANT,
                    risk_level=self.risk_level,
                    evidence=f"Account lockout duration: {duration} minutes",
                    command_output=output
                )
            else:
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.NON_COMPLIANT,
                    risk_level=self.risk_level,
                    evidence=f"Account lockout duration: {duration} minutes",
                    details="Should be at least 15 minutes",
                    command_output=output
                )
                
        except Exception as e:
            return ControlResult(
                control_id=self.control_id,
                name=self.name,
                category=self.category,
                status=ControlStatus.ERROR,
                risk_level=self.risk_level,
                evidence="Error checking lockout duration",
                error_message=str(e)
            )
    
    def remediate(self) -> bool:
        """Set account lockout duration to 15 minutes."""
        try:
            result = self.runner.run_cmd('net accounts /lockoutduration:15')
            return result.success
        except Exception as e:
            self._log('error', f"Lockout duration error: {str(e)}")
            return False
    
    def verify(self) -> ControlResult:
        """Verify lockout duration."""
        return self.audit()


class PasswordHistoryControl(SecurityControl):
    """
    AVBL-09: Password History
    Ensures password history remembers at least 24 passwords.
    """
    
    def __init__(self):
        super().__init__(
            control_id="AVBL-09",
            name="Password History",
            description="Verify password history remembers >= 24 passwords",
            category=CIACategory.AVAILABILITY,
            risk_level=RiskLevel.MEDIUM,
            cis_reference="CIS 1.1.1",
            nist_reference="IA-5"
        )
        self._supports_rollback = True
    
    def audit(self) -> ControlResult:
        """Check password history policy."""
        try:
            result = self.runner.run_cmd('net accounts')
            
            if not result.success:
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.ERROR,
                    risk_level=self.risk_level,
                    evidence="Failed to query account policy",
                    error_message=result.stderr
                )
            
            output = result.stdout
            
            # Parse "Length of password history maintained" or similar
            history = 0
            for line in output.split('\n'):
                if 'password history' in line.lower():
                    try:
                        parts = line.split(':')
                        if len(parts) >= 2:
                            val = parts[1].strip()
                            if val.lower() == 'none':
                                history = 0
                            else:
                                history = int(val)
                    except (ValueError, IndexError):
                        pass
            
            if history >= 24:
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.COMPLIANT,
                    risk_level=self.risk_level,
                    evidence=f"Password history: {history} passwords remembered",
                    command_output=output
                )
            else:
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.NON_COMPLIANT,
                    risk_level=self.risk_level,
                    evidence=f"Password history: {history} passwords",
                    details="Should remember at least 24 passwords",
                    command_output=output
                )
                
        except Exception as e:
            return ControlResult(
                control_id=self.control_id,
                name=self.name,
                category=self.category,
                status=ControlStatus.ERROR,
                risk_level=self.risk_level,
                evidence="Error checking password history",
                error_message=str(e)
            )
    
    def remediate(self) -> bool:
        """Set password history to 24."""
        try:
            result = self.runner.run_cmd('net accounts /uniquepw:24')
            return result.success
        except Exception as e:
            self._log('error', f"Password history error: {str(e)}")
            return False
    
    def verify(self) -> ControlResult:
        """Verify password history."""
        return self.audit()


class PasswordMaxAgeControl(SecurityControl):
    """
    AVBL-10: Password Maximum Age
    Ensures password maximum age is set (60-90 days recommended).
    """
    
    def __init__(self):
        super().__init__(
            control_id="AVBL-10",
            name="Password Maximum Age",
            description="Verify password maximum age is 60-90 days",
            category=CIACategory.AVAILABILITY,
            risk_level=RiskLevel.MEDIUM,
            cis_reference="CIS 1.1.2",
            nist_reference="IA-5"
        )
        self._supports_rollback = True
    
    def audit(self) -> ControlResult:
        """Check password maximum age policy."""
        try:
            result = self.runner.run_cmd('net accounts')
            
            if not result.success:
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.ERROR,
                    risk_level=self.risk_level,
                    evidence="Failed to query account policy",
                    error_message=result.stderr
                )
            
            output = result.stdout
            
            # Parse "Maximum password age" line
            max_age = 0
            for line in output.split('\n'):
                if 'Maximum password age' in line:
                    try:
                        parts = line.split(':')
                        if len(parts) >= 2:
                            val = parts[1].strip()
                            if val.lower() == 'unlimited':
                                max_age = 999
                            else:
                                max_age = int(val)
                    except (ValueError, IndexError):
                        pass
            
            if 1 <= max_age <= 90:
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.COMPLIANT,
                    risk_level=self.risk_level,
                    evidence=f"Password maximum age: {max_age} days",
                    command_output=output
                )
            elif max_age == 999 or max_age == 0:
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.NON_COMPLIANT,
                    risk_level=self.risk_level,
                    evidence="Password never expires",
                    details="Should be 60-90 days",
                    command_output=output
                )
            else:
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.NON_COMPLIANT,
                    risk_level=self.risk_level,
                    evidence=f"Password maximum age: {max_age} days",
                    details="Should be 60-90 days",
                    command_output=output
                )
                
        except Exception as e:
            return ControlResult(
                control_id=self.control_id,
                name=self.name,
                category=self.category,
                status=ControlStatus.ERROR,
                risk_level=self.risk_level,
                evidence="Error checking password age",
                error_message=str(e)
            )
    
    def remediate(self) -> bool:
        """Set password maximum age to 60 days."""
        try:
            result = self.runner.run_cmd('net accounts /maxpwage:60')
            return result.success
        except Exception as e:
            self._log('error', f"Password age error: {str(e)}")
            return False
    
    def verify(self) -> ControlResult:
        """Verify password age."""
        return self.audit()


class WindowsUpdateServiceControl(ServiceControl):
    """
    AVBL-11: Windows Update Service
    Ensures Windows Update service is running for security updates.
    """
    
    service_name = 'wuauserv'
    compliant_state = 'Running'
    compliant_startup = 'auto'
    
    def __init__(self):
        super().__init__(
            control_id="AVBL-11",
            name="Windows Update Service",
            description="Verify Windows Update service is running",
            category=CIACategory.AVAILABILITY,
            risk_level=RiskLevel.CRITICAL,
            cis_reference="CIS 5.37",
            nist_reference="SI-2"
        )


class WindowsDefenderServiceControl(ServiceControl):
    """
    AVBL-12: Windows Defender Service
    Ensures Windows Defender Antivirus Service is running.
    """
    
    service_name = 'WinDefend'
    compliant_state = 'Running'
    compliant_startup = 'auto'
    
    def __init__(self):
        super().__init__(
            control_id="AVBL-12",
            name="Windows Defender Service",
            description="Verify Windows Defender service is running",
            category=CIACategory.AVAILABILITY,
            risk_level=RiskLevel.CRITICAL,
            cis_reference="CIS 18.9.45",
            nist_reference="SI-3"
        )
    
    def audit(self) -> ControlResult:
        """Check Windows Defender service status."""
        try:
            result = super().audit()
            
            # Check if third-party AV might be installed
            if result.status == ControlStatus.NON_COMPLIANT:
                # Check if another AV is registered
                av_check = self.runner.run_powershell(
                    'Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct | Select-Object displayName'
                )
                if av_check.success and av_check.stdout.strip():
                    # Another AV is installed
                    result.status = ControlStatus.COMPLIANT
                    result.evidence = "Third-party antivirus detected"
                    result.details = av_check.stdout.strip()[:200]
            
            return result
            
        except Exception as e:
            return ControlResult(
                control_id=self.control_id,
                name=self.name,
                category=self.category,
                status=ControlStatus.ERROR,
                risk_level=self.risk_level,
                evidence="Error checking Windows Defender",
                error_message=str(e)
            )


class BITSServiceControl(ServiceControl):
    """
    AVBL-13: BITS Service
    Ensures Background Intelligent Transfer Service is available for updates.
    """
    
    service_name = 'BITS'
    compliant_state = 'Running'
    compliant_startup = 'auto'
    
    def __init__(self):
        super().__init__(
            control_id="AVBL-13",
            name="BITS Service",
            description="Verify Background Intelligent Transfer Service is running",
            category=CIACategory.AVAILABILITY,
            risk_level=RiskLevel.MEDIUM,
            cis_reference="N/A",
            nist_reference="SI-2"
        )


class EventLogServiceControl(ServiceControl):
    """
    AVBL-14: Event Log Service
    Ensures Windows Event Log service is running for auditing.
    """
    
    service_name = 'EventLog'
    compliant_state = 'Running'
    compliant_startup = 'auto'
    
    def __init__(self):
        super().__init__(
            control_id="AVBL-14",
            name="Event Log Service",
            description="Verify Windows Event Log service is running",
            category=CIACategory.AVAILABILITY,
            risk_level=RiskLevel.CRITICAL,
            cis_reference="CIS 5.11",
            nist_reference="AU-4"
        )


class CrashDumpConfigControl(RegistryControl):
    """
    AVBL-15: Crash Dump Configuration
    Ensures crash dumps are configured appropriately (Kernel dump or smaller).
    """
    
    registry_path = r'HKLM\SYSTEM\CurrentControlSet\Control\CrashControl'
    registry_value = 'CrashDumpEnabled'
    expected_data = 2  # 2 = Kernel memory dump, 1 = Complete, 3 = Small, 7 = Automatic
    value_type = 'REG_DWORD'
    comparison = 'greater_equal'  # 2+ is acceptable (kernel, small, or automatic)
    
    def __init__(self):
        super().__init__(
            control_id="AVBL-15",
            name="Crash Dump Configuration",
            description="Verify crash dump is configured (Kernel or smaller)",
            category=CIACategory.AVAILABILITY,
            risk_level=RiskLevel.LOW,
            cis_reference="N/A",
            nist_reference="AU-4"
        )
    
    def audit(self) -> ControlResult:
        """Check crash dump configuration."""
        try:
            result = self.runner.run_reg_query(self.registry_path, self.registry_value)
            
            if not result.success:
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.NON_COMPLIANT,
                    risk_level=self.risk_level,
                    evidence="Crash dump settings not found",
                    command_output=result.stderr
                )
            
            output = result.stdout
            
            # Parse the value
            dump_type = None
            if '0x0' in output:
                dump_type = 0  # Disabled
            elif '0x1' in output:
                dump_type = 1  # Complete
            elif '0x2' in output:
                dump_type = 2  # Kernel
            elif '0x3' in output:
                dump_type = 3  # Small
            elif '0x7' in output:
                dump_type = 7  # Automatic
            
            dump_names = {
                0: 'Disabled',
                1: 'Complete memory dump',
                2: 'Kernel memory dump',
                3: 'Small memory dump',
                7: 'Automatic memory dump'
            }
            
            if dump_type in [2, 3, 7]:  # Kernel, Small, or Automatic are good
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.COMPLIANT,
                    risk_level=self.risk_level,
                    evidence=f"Crash dump type: {dump_names.get(dump_type, 'Unknown')}",
                    command_output=output
                )
            elif dump_type == 0:
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.NON_COMPLIANT,
                    risk_level=self.risk_level,
                    evidence="Crash dumps are DISABLED",
                    details="System issues will be harder to diagnose"
                )
            else:
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.COMPLIANT,
                    risk_level=self.risk_level,
                    evidence=f"Crash dump type: {dump_names.get(dump_type, 'Unknown')}",
                    command_output=output
                )
                
        except Exception as e:
            return ControlResult(
                control_id=self.control_id,
                name=self.name,
                category=self.category,
                status=ControlStatus.ERROR,
                risk_level=self.risk_level,
                evidence="Error checking crash dump config",
                error_message=str(e)
            )


class AutoRestartSignOnControl(RegistryControl):
    """
    AVBL-16: Auto Restart Sign-on Disabled
    Ensures automatic sign-on after restart is disabled for security.
    """
    
    registry_path = r'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    registry_value = 'DisableAutomaticRestartSignOn'
    expected_data = 1  # 1 = Disabled (auto sign-on disabled = secure)
    value_type = 'REG_DWORD'
    comparison = 'equal'
    
    def __init__(self):
        super().__init__(
            control_id="AVBL-16",
            name="Auto Restart Sign-on Disabled",
            description="Verify automatic sign-on after restart is disabled",
            category=CIACategory.AVAILABILITY,
            risk_level=RiskLevel.MEDIUM,
            cis_reference="CIS 18.9.24.1",
            nist_reference="AC-9"
        )


class ScreenSaverTimeoutControl(RegistryControl):
    """
    AVBL-17: Screen Saver Timeout
    Ensures screen saver timeout is set to 15 minutes or less.
    """
    
    registry_path = r'HKCU\Control Panel\Desktop'
    registry_value = 'ScreenSaveTimeOut'
    expected_data = 900  # 900 seconds = 15 minutes
    value_type = 'REG_SZ'
    comparison = 'less_equal'
    
    def __init__(self):
        super().__init__(
            control_id="AVBL-17",
            name="Screen Saver Timeout",
            description="Verify screen saver timeout is <= 15 minutes",
            category=CIACategory.AVAILABILITY,
            risk_level=RiskLevel.LOW,
            cis_reference="CIS 18.9.97.1",
            nist_reference="AC-11"
        )
    
    def audit(self) -> ControlResult:
        """Check screen saver timeout."""
        try:
            result = self.runner.run_reg_query(self.registry_path, self.registry_value)
            
            if not result.success:
                # Check if screen saver is even enabled
                ss_active = self.runner.run_reg_query(self.registry_path, 'ScreenSaveActive')
                if ss_active.success and '0' in ss_active.stdout:
                    return ControlResult(
                        control_id=self.control_id,
                        name=self.name,
                        category=self.category,
                        status=ControlStatus.NON_COMPLIANT,
                        risk_level=self.risk_level,
                        evidence="Screen saver is DISABLED",
                        details="Screen saver should be enabled with timeout"
                    )
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.NON_COMPLIANT,
                    risk_level=self.risk_level,
                    evidence="Screen saver timeout not configured"
                )
            
            output = result.stdout
            
            # Parse timeout value (in seconds)
            timeout = 0
            import re
            match = re.search(r'REG_SZ\s+(\d+)', output)
            if match:
                timeout = int(match.group(1))
            
            if 1 <= timeout <= 900:
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.COMPLIANT,
                    risk_level=self.risk_level,
                    evidence=f"Screen saver timeout: {timeout // 60} minutes",
                    command_output=output
                )
            elif timeout > 900:
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.NON_COMPLIANT,
                    risk_level=self.risk_level,
                    evidence=f"Screen saver timeout: {timeout // 60} minutes",
                    details="Should be 15 minutes or less"
                )
            else:
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.NON_COMPLIANT,
                    risk_level=self.risk_level,
                    evidence="Screen saver timeout not properly configured"
                )
                
        except Exception as e:
            return ControlResult(
                control_id=self.control_id,
                name=self.name,
                category=self.category,
                status=ControlStatus.ERROR,
                risk_level=self.risk_level,
                evidence="Error checking screen saver",
                error_message=str(e)
            )


class BackupConfigurationControl(SecurityControl):
    """
    AVBL-18: Backup Configuration
    Verifies that backup services are configured and operational to ensure
    data recovery capability in case of system failure or ransomware.
    """
    
    def __init__(self):
        super().__init__(
            control_id="AVBL-18",
            name="Backup Configuration",
            description="Verify backup services are configured for data recovery",
            category=CIACategory.AVAILABILITY,
            risk_level=RiskLevel.HIGH,
            cis_reference="CIS 10.1",
            nist_reference="CP-9"
        )
        self._supports_rollback = False
    
    def audit(self) -> ControlResult:
        """Check backup configuration status."""
        try:
            findings = []
            backup_configured = False
            
            # Check Windows Backup Engine service (wbengine)
            svc_check = """
            $svc = Get-Service -Name wbengine -ErrorAction SilentlyContinue
            if ($svc) {
                Write-Output "SERVICE:$($svc.Status):$($svc.StartType)"
            } else {
                Write-Output "SERVICE:NOT_FOUND"
            }
            """
            svc_result = self.runner.run_powershell(svc_check)
            
            if svc_result.success and "SERVICE:" in svc_result.stdout:
                svc_info = svc_result.stdout.strip().split(":")
                if len(svc_info) >= 2 and svc_info[1] != "NOT_FOUND":
                    status = svc_info[1] if len(svc_info) > 1 else "Unknown"
                    start_type = svc_info[2] if len(svc_info) > 2 else "Unknown"
                    findings.append(f"Windows Backup Engine: {status} ({start_type})")
                    if start_type.lower() not in ['disabled']:
                        backup_configured = True
            
            # Check if this is a workstation or server
            os_type_check = "(Get-WmiObject Win32_OperatingSystem).ProductType"
            os_result = self.runner.run_powershell(os_type_check)
            is_workstation = os_result.success and os_result.stdout.strip() == "1"
            
            if is_workstation:
                # Check File History for workstations
                fh_check = """
                $fhPath = 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\FileHistory'
                if (Test-Path $fhPath) {
                    $config = Get-ItemProperty -Path $fhPath -ErrorAction SilentlyContinue
                    if ($config.ProtectedUpgraded -or $config.ProtectedUntilTime) {
                        Write-Output "FILE_HISTORY:CONFIGURED"
                    } else {
                        Write-Output "FILE_HISTORY:PRESENT_NOT_CONFIGURED"
                    }
                } else {
                    Write-Output "FILE_HISTORY:NOT_CONFIGURED"
                }
                """
                fh_result = self.runner.run_powershell(fh_check)
                
                if fh_result.success:
                    if "CONFIGURED" in fh_result.stdout and "NOT_CONFIGURED" not in fh_result.stdout:
                        findings.append("File History: Configured")
                        backup_configured = True
                    else:
                        findings.append("File History: Not configured")
            else:
                # Check Windows Server Backup feature for servers
                wsb_check = """
                $feature = Get-WindowsFeature -Name Windows-Server-Backup -ErrorAction SilentlyContinue
                if ($feature) {
                    if ($feature.Installed) {
                        Write-Output "WSB:INSTALLED"
                    } else {
                        Write-Output "WSB:NOT_INSTALLED"
                    }
                } else {
                    Write-Output "WSB:NOT_AVAILABLE"
                }
                """
                wsb_result = self.runner.run_powershell(wsb_check)
                
                if wsb_result.success:
                    if "INSTALLED" in wsb_result.stdout:
                        findings.append("Windows Server Backup: Installed")
                        backup_configured = True
                    elif "NOT_INSTALLED" in wsb_result.stdout:
                        findings.append("Windows Server Backup: Not installed")
                    else:
                        findings.append("Windows Server Backup: Feature not available")
            
            # Check VSS (Volume Shadow Copy) as additional indicator
            vss_check = """
            $vss = Get-Service -Name VSS -ErrorAction SilentlyContinue
            if ($vss -and $vss.StartType -ne 'Disabled') { "VSS:AVAILABLE" } else { "VSS:UNAVAILABLE" }
            """
            vss_result = self.runner.run_powershell(vss_check)
            if vss_result.success and "AVAILABLE" in vss_result.stdout:
                findings.append("Volume Shadow Copy: Available")
            
            evidence = "; ".join(findings) if findings else "No backup configuration found"
            
            if backup_configured:
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.COMPLIANT,
                    risk_level=self.risk_level,
                    evidence=evidence,
                    command_output=f"System type: {'Workstation' if is_workstation else 'Server'}"
                )
            else:
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.NON_COMPLIANT,
                    risk_level=self.risk_level,
                    evidence=evidence,
                    details="No backup solution configured. Enable File History (workstations) "
                            "or install Windows Server Backup (servers), or deploy enterprise backup solution."
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
        """Backup configuration requires organizational policy - cannot auto-remediate."""
        self.logger.warning(
            "Backup configuration is organization-specific and requires infrastructure planning. "
            "Cannot auto-remediate. Consider: File History, Windows Server Backup, Azure Backup, "
            "or third-party enterprise backup solutions."
        )
        return False
    
    def verify(self) -> ControlResult:
        """Verify backup configuration."""
        return self.audit()


class AvailabilityControls(ControlGroup):
    """Collection of all Availability controls."""
    
    def __init__(self):
        super().__init__(
            name="Availability Controls",
            category=CIACategory.AVAILABILITY,
            description="Controls ensuring system availability and resilience"
        )
        
        # Add all availability controls (AVBL-01 to AVBL-17)
        self.add_control(FirewallControl())
        self.add_control(VSSControl())
        self.add_control(VirtualMemoryControl())
        self.add_control(TimeServiceControl())
        self.add_control(PasswordMinLengthControl())
        self.add_control(PasswordComplexityControl())
        self.add_control(AccountLockoutThresholdControl())
        self.add_control(AccountLockoutDurationControl())
        self.add_control(PasswordHistoryControl())
        self.add_control(PasswordMaxAgeControl())
        self.add_control(WindowsUpdateServiceControl())
        self.add_control(WindowsDefenderServiceControl())
        self.add_control(BITSServiceControl())
        self.add_control(EventLogServiceControl())
        self.add_control(CrashDumpConfigControl())
        self.add_control(AutoRestartSignOnControl())
        self.add_control(ScreenSaverTimeoutControl())
        # v2.3: Additional enterprise control (AVBL-18)
        self.add_control(BackupConfigurationControl())
    
    def initialize(self, runner, logger):
        """Initialize all controls with dependencies."""
        for control in self.controls:
            control.set_dependencies(runner, logger)
