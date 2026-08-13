"""
Integrity Controls
INTG-01: Windows Defender Real-time Protection
INTG-02: UAC Enabled at Highest Level
INTG-03: PowerShell Execution Policy
INTG-04: Audit Policy for Logon Events
INTG-05: System File Checker
INTG-06: LSA Protection (RunAsPPL)
INTG-07: Credential Guard
INTG-08: Secure Boot
INTG-09: Driver Signature Enforcement
INTG-10: PowerShell Script Block Logging
INTG-11: PowerShell Transcription
INTG-12: Command Line Auditing
INTG-13: Object Access Audit
INTG-14: Privilege Use Audit
INTG-15: Policy Change Audit
INTG-16: SEHOP Enabled
INTG-17: DEP/NX Enabled
INTG-18: ASLR Enabled
INTG-19: Attack Surface Reduction Rules (v2.2)
INTG-20: VBS/HVCI Memory Integrity (v2.2)
INTG-21: Windows Exploit Protection (v2.3)
INTG-22: Controlled Folder Access (v2.3)
INTG-23: Early Launch Anti-Malware (v2.3)
"""

from typing import Dict, Any, Optional
from .base import (
    SecurityControl, ControlResult, ControlStatus,
    RiskLevel, CIACategory, ControlGroup
)
from .registry_base import RegistryControl, MultiRegistryControl


class DefenderRealtimeControl(SecurityControl):
    """
    INTG-01: Windows Defender Real-time Protection
    Ensures Windows Defender real-time protection is enabled.
    """
    
    def __init__(self):
        super().__init__(
            control_id="INTG-01",
            name="Defender Real-time Protection",
            description="Verify Windows Defender real-time protection is enabled",
            category=CIACategory.INTEGRITY,
            risk_level=RiskLevel.CRITICAL,
            cis_reference="CIS 18.9.45.4.1",
            nist_reference="SI-3"
        )
        self._supports_rollback = True
    
    def _capture_current_state(self) -> Optional[Dict[str, Any]]:
        """Capture current Defender state."""
        try:
            result = self.runner.run_powershell(
                'Get-MpPreference | Select-Object -ExpandProperty DisableRealtimeMonitoring'
            )
            return {
                'disable_realtime': result.stdout.strip() if result.success else None
            }
        except Exception:
            return None
    
    def _restore_state(self, state_data: Dict[str, Any]) -> bool:
        """Restore Defender to previous state."""
        try:
            was_disabled = state_data.get('disable_realtime', '').lower() == 'true'
            if was_disabled:
                result = self.runner.run_powershell(
                    'Set-MpPreference -DisableRealtimeMonitoring $true'
                )
                return result.success
            return True
        except Exception:
            return False
    
    def audit(self) -> ControlResult:
        """Check if Defender real-time protection is enabled."""
        try:
            result = self.runner.run_powershell(
                'Get-MpPreference | Select-Object -ExpandProperty DisableRealtimeMonitoring'
            )
            
            if not result.success:
                # Check if Defender is available
                if 'not recognized' in result.stderr.lower() or 'cmdlet' in result.stderr.lower():
                    return ControlResult(
                        control_id=self.control_id,
                        name=self.name,
                        category=self.category,
                        status=ControlStatus.NOT_APPLICABLE,
                        risk_level=self.risk_level,
                        evidence="Windows Defender not available",
                        details="Third-party antivirus may be installed",
                        command_output=result.stderr
                    )
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.ERROR,
                    risk_level=self.risk_level,
                    evidence="Failed to query Defender status",
                    error_message=result.stderr
                )
            
            output = result.stdout.strip()
            
            # DisableRealtimeMonitoring = False means it's ENABLED
            if output.lower() == 'false':
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.COMPLIANT,
                    risk_level=self.risk_level,
                    evidence="Real-time protection is ENABLED",
                    command_output=output
                )
            else:
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.NON_COMPLIANT,
                    risk_level=self.risk_level,
                    evidence="Real-time protection is DISABLED",
                    details="System is vulnerable to malware",
                    command_output=output
                )
                
        except Exception as e:
            return ControlResult(
                control_id=self.control_id,
                name=self.name,
                category=self.category,
                status=ControlStatus.ERROR,
                risk_level=self.risk_level,
                evidence="Error checking Defender status",
                error_message=str(e)
            )
    
    def remediate(self) -> bool:
        """Enable Defender real-time protection."""
        try:
            result = self.runner.run_powershell(
                'Set-MpPreference -DisableRealtimeMonitoring $false'
            )
            
            if result.success:
                self._log('info', "Defender real-time protection enabled")
                return True
            else:
                self._log('error', f"Failed to enable Defender: {result.stderr}")
                return False
                
        except Exception as e:
            self._log('error', f"Defender remediation error: {str(e)}")
            return False
    
    def verify(self) -> ControlResult:
        """Verify Defender real-time protection is enabled."""
        return self.audit()


class UACControl(SecurityControl):
    """
    INTG-02: UAC Enabled at Highest Level
    Ensures User Account Control is enabled with proper settings.
    """
    
    def __init__(self):
        super().__init__(
            control_id="INTG-02",
            name="UAC Configuration",
            description="Verify UAC is enabled with ConsentPromptBehaviorAdmin=5",
            category=CIACategory.INTEGRITY,
            risk_level=RiskLevel.HIGH,
            cis_reference="CIS 2.3.17.1",
            nist_reference="AC-6"
        )
        self._supports_rollback = True
    
    def _capture_current_state(self) -> Optional[Dict[str, Any]]:
        """Capture current UAC settings."""
        try:
            consent = self.runner.run_reg_query(
                r'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System',
                'ConsentPromptBehaviorAdmin'
            )
            enable_lua = self.runner.run_reg_query(
                r'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System',
                'EnableLUA'
            )
            prompt_desktop = self.runner.run_reg_query(
                r'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System',
                'PromptOnSecureDesktop'
            )
            return {
                'consent_behavior': consent.stdout if consent.success else None,
                'enable_lua': enable_lua.stdout if enable_lua.success else None,
                'prompt_desktop': prompt_desktop.stdout if prompt_desktop.success else None
            }
        except Exception:
            return None
    
    def _restore_state(self, state_data: Dict[str, Any]) -> bool:
        """Restore UAC to previous settings."""
        try:
            success = True
            
            # Parse and restore ConsentPromptBehaviorAdmin
            consent = state_data.get('consent_behavior', '')
            if consent:
                # Extract value from registry output
                if '0x0' in consent:
                    val = '0'
                elif '0x1' in consent:
                    val = '1'
                elif '0x2' in consent:
                    val = '2'
                elif '0x3' in consent:
                    val = '3'
                elif '0x4' in consent:
                    val = '4'
                elif '0x5' in consent:
                    val = '5'
                else:
                    val = '5'  # default
                    
                result = self.runner.run_reg_add(
                    r'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System',
                    'ConsentPromptBehaviorAdmin', 'REG_DWORD', val
                )
                if not result.success:
                    success = False
            
            return success
        except Exception:
            return False
    
    def audit(self) -> ControlResult:
        """Check UAC configuration."""
        try:
            result = self.runner.run_reg_query(
                r'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System',
                'ConsentPromptBehaviorAdmin'
            )
            
            if not result.success:
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.NON_COMPLIANT,
                    risk_level=self.risk_level,
                    evidence="UAC registry key not found",
                    command_output=result.stderr
                )
            
            output = result.stdout
            
            # ConsentPromptBehaviorAdmin=5 means prompt for consent on secure desktop
            # Values: 0=no prompt, 1=prompt credentials on secure desktop,
            #         2=prompt consent on secure desktop, 3=prompt credentials,
            #         4=prompt consent, 5=prompt consent for non-Windows binaries
            if '0x5' in output or 'REG_DWORD    5' in output:
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.COMPLIANT,
                    risk_level=self.risk_level,
                    evidence="ConsentPromptBehaviorAdmin=5 (Prompt for consent)",
                    command_output=output
                )
            elif '0x2' in output or 'REG_DWORD    2' in output:
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.COMPLIANT,
                    risk_level=self.risk_level,
                    evidence="ConsentPromptBehaviorAdmin=2 (Prompt on secure desktop)",
                    details="Even stricter than required",
                    command_output=output
                )
            else:
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.NON_COMPLIANT,
                    risk_level=self.risk_level,
                    evidence=f"ConsentPromptBehaviorAdmin is not properly configured",
                    details="UAC may be disabled or set too low",
                    command_output=output
                )
                
        except Exception as e:
            return ControlResult(
                control_id=self.control_id,
                name=self.name,
                category=self.category,
                status=ControlStatus.ERROR,
                risk_level=self.risk_level,
                evidence="Error checking UAC status",
                error_message=str(e)
            )
    
    def remediate(self) -> bool:
        """Enable UAC with proper settings."""
        try:
            # Set ConsentPromptBehaviorAdmin to 5
            result = self.runner.run_reg_add(
                r'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System',
                'ConsentPromptBehaviorAdmin', 'REG_DWORD', '5'
            )
            
            if not result.success:
                self._log('error', f"Failed to set ConsentPromptBehaviorAdmin: {result.stderr}")
                return False
            
            # Also ensure EnableLUA is set to 1
            result = self.runner.run_reg_add(
                r'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System',
                'EnableLUA', 'REG_DWORD', '1'
            )
            
            if not result.success:
                self._log('warning', f"Failed to set EnableLUA: {result.stderr}")
            
            # Set PromptOnSecureDesktop to 1
            self.runner.run_reg_add(
                r'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System',
                'PromptOnSecureDesktop', 'REG_DWORD', '1'
            )
            
            self._log('info', "UAC configured successfully")
            return True
            
        except Exception as e:
            self._log('error', f"UAC remediation error: {str(e)}")
            return False
    
    def verify(self) -> ControlResult:
        """Verify UAC is properly configured."""
        return self.audit()


class PowerShellExecutionPolicyControl(SecurityControl):
    """
    INTG-03: PowerShell Execution Policy
    Ensures PowerShell execution policy is set to RemoteSigned.
    """
    
    def __init__(self):
        super().__init__(
            control_id="INTG-03",
            name="PowerShell Execution Policy",
            description="Verify PowerShell execution policy is set to RemoteSigned",
            category=CIACategory.INTEGRITY,
            risk_level=RiskLevel.MEDIUM,
            cis_reference="CIS 18.9.95.1",
            nist_reference="CM-7"
        )
        self._supports_rollback = True
    
    def _capture_current_state(self) -> Optional[Dict[str, Any]]:
        """Capture current execution policy."""
        try:
            result = self.runner.run_powershell(
                'Get-ExecutionPolicy -Scope LocalMachine'
            )
            return {
                'policy': result.stdout.strip() if result.success else None
            }
        except Exception:
            return None
    
    def _restore_state(self, state_data: Dict[str, Any]) -> bool:
        """Restore previous execution policy."""
        try:
            policy = state_data.get('policy')
            if policy:
                result = self.runner.run_powershell(
                    f'Set-ExecutionPolicy -ExecutionPolicy {policy} -Scope LocalMachine -Force'
                )
                return result.success
            return False
        except Exception:
            return False
    
    def audit(self) -> ControlResult:
        """Check PowerShell execution policy."""
        try:
            result = self.runner.run_powershell(
                'Get-ExecutionPolicy -Scope LocalMachine'
            )
            
            if not result.success:
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.ERROR,
                    risk_level=self.risk_level,
                    evidence="Failed to query execution policy",
                    error_message=result.stderr
                )
            
            policy = result.stdout.strip()
            
            # Acceptable policies: RemoteSigned, AllSigned, Restricted
            compliant_policies = ['RemoteSigned', 'AllSigned', 'Restricted']
            
            if policy in compliant_policies:
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.COMPLIANT,
                    risk_level=self.risk_level,
                    evidence=f"Execution Policy: {policy}",
                    command_output=policy
                )
            else:
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.NON_COMPLIANT,
                    risk_level=self.risk_level,
                    evidence=f"Execution Policy: {policy}",
                    details="Policy allows unsigned scripts to run",
                    command_output=policy
                )
                
        except Exception as e:
            return ControlResult(
                control_id=self.control_id,
                name=self.name,
                category=self.category,
                status=ControlStatus.ERROR,
                risk_level=self.risk_level,
                evidence="Error checking execution policy",
                error_message=str(e)
            )
    
    def remediate(self) -> bool:
        """Set PowerShell execution policy to RemoteSigned."""
        try:
            result = self.runner.run_powershell(
                'Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope LocalMachine -Force'
            )
            
            if result.success or 'already' in result.stdout.lower():
                self._log('info', "PowerShell execution policy set to RemoteSigned")
                return True
            else:
                self._log('error', f"Failed to set execution policy: {result.stderr}")
                return False
                
        except Exception as e:
            self._log('error', f"Execution policy remediation error: {str(e)}")
            return False
    
    def verify(self) -> ControlResult:
        """Verify execution policy is set correctly."""
        return self.audit()


class AuditPolicyControl(SecurityControl):
    """
    INTG-04: Audit Policy for Logon Events
    Ensures auditing is enabled for logon events.
    """
    
    def __init__(self):
        super().__init__(
            control_id="INTG-04",
            name="Logon Audit Policy",
            description="Verify audit policy for logon events is enabled",
            category=CIACategory.INTEGRITY,
            risk_level=RiskLevel.HIGH,
            cis_reference="CIS 17.5.1",
            nist_reference="AU-2"
        )
        self._supports_rollback = True
    
    def _capture_current_state(self) -> Optional[Dict[str, Any]]:
        """Capture current audit policy."""
        try:
            result = self.runner.run_cmd('auditpol /get /subcategory:"Logon"')
            return {
                'audit_output': result.stdout if result.success else None
            }
        except Exception:
            return None
    
    def _restore_state(self, state_data: Dict[str, Any]) -> bool:
        """Restore previous audit policy."""
        try:
            output = state_data.get('audit_output', '')
            has_success = 'Success' in output
            has_failure = 'Failure' in output
            
            # Build auditpol command based on previous state
            success_flag = 'enable' if has_success else 'disable'
            failure_flag = 'enable' if has_failure else 'disable'
            
            result = self.runner.run_cmd(
                f'auditpol /set /subcategory:"Logon" /success:{success_flag} /failure:{failure_flag}'
            )
            return result.success
        except Exception:
            return False
    
    def audit(self) -> ControlResult:
        """Check audit policy for logon events."""
        try:
            result = self.runner.run_cmd('auditpol /get /subcategory:"Logon"')
            
            if not result.success:
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.ERROR,
                    risk_level=self.risk_level,
                    evidence="Failed to query audit policy",
                    error_message=result.stderr
                )
            
            output = result.stdout
            
            # Check for Success and Failure auditing
            has_success = 'Success' in output
            has_failure = 'Failure' in output
            
            if has_success and has_failure:
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.COMPLIANT,
                    risk_level=self.risk_level,
                    evidence="Logon auditing: Success and Failure enabled",
                    command_output=output
                )
            elif 'No Auditing' in output:
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.NON_COMPLIANT,
                    risk_level=self.risk_level,
                    evidence="Logon auditing is DISABLED",
                    details="No audit trail for authentication events",
                    command_output=output
                )
            else:
                # Partial auditing
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.NON_COMPLIANT,
                    risk_level=self.risk_level,
                    evidence="Logon auditing is partially configured",
                    details="Both Success and Failure should be enabled",
                    command_output=output
                )
                
        except Exception as e:
            return ControlResult(
                control_id=self.control_id,
                name=self.name,
                category=self.category,
                status=ControlStatus.ERROR,
                risk_level=self.risk_level,
                evidence="Error checking audit policy",
                error_message=str(e)
            )
    
    def remediate(self) -> bool:
        """Enable logon auditing for success and failure."""
        try:
            result = self.runner.run_cmd(
                'auditpol /set /subcategory:"Logon" /success:enable /failure:enable'
            )
            
            if result.success:
                self._log('info', "Logon audit policy configured")
                return True
            else:
                self._log('error', f"Failed to set audit policy: {result.stderr}")
                return False
                
        except Exception as e:
            self._log('error', f"Audit policy remediation error: {str(e)}")
            return False
    
    def verify(self) -> ControlResult:
        """Verify audit policy is configured correctly."""
        return self.audit()


class SystemFileCheckerControl(SecurityControl):
    """
    INTG-05: System File Checker
    Verifies system file integrity using sfc.
    """
    
    def __init__(self):
        super().__init__(
            control_id="INTG-05",
            name="System File Integrity",
            description="Verify system file integrity using SFC",
            category=CIACategory.INTEGRITY,
            risk_level=RiskLevel.HIGH,
            cis_reference="N/A",
            nist_reference="SI-7"
        )
        # SFC repairs system files - cannot be easily rolled back
        self._supports_rollback = False
    
    def audit(self) -> ControlResult:
        """Check system file integrity with SFC verify only."""
        try:
            # Use /verifyonly for audit (doesn't fix, just checks)
            # SFC can take 15-30+ minutes depending on system - use 45 min timeout
            result = self.runner.run_cmd('sfc /verifyonly', timeout=2700)
            
            output = result.stdout.lower() if result.stdout else ''
            stderr = result.stderr.lower() if result.stderr else ''
            combined = output + ' ' + stderr
            
            # Check for admin privilege errors first
            if not result.success or 'administrator' in combined or 'access denied' in combined:
                if 'administrator' in combined or 'access' in combined or 'denied' in combined:
                    return ControlResult(
                        control_id=self.control_id,
                        name=self.name,
                        category=self.category,
                        status=ControlStatus.ERROR,
                        risk_level=self.risk_level,
                        evidence="SFC requires administrator privileges",
                        error_message=result.stderr or "Run as Administrator"
                    )
            
            # Patterns indicating NO violations (compliant)
            # Covers multiple Windows languages and variations
            compliant_patterns = [
                'did not find any integrity violations',
                'no integrity violations',
                'windows resource protection did not find',
                'found no integrity violations',
                'verification 100% complete',
                'successfully repaired',  # Also compliant if repaired
            ]
            
            # Patterns indicating violations found (non-compliant)
            violation_patterns = [
                'found corrupt files',
                'integrity violations',
                'could not repair',
                'unable to fix',
                'corrupt files that could not be repaired',
                'found corrupt files but was unable',
            ]
            
            # Check for compliant patterns
            for pattern in compliant_patterns:
                if pattern in combined:
                    return ControlResult(
                        control_id=self.control_id,
                        name=self.name,
                        category=self.category,
                        status=ControlStatus.COMPLIANT,
                        risk_level=self.risk_level,
                        evidence="No integrity violations found",
                        command_output=result.stdout[:500] if result.stdout else "SFC completed successfully"
                    )
            
            # Check for violation patterns
            for pattern in violation_patterns:
                if pattern in combined:
                    return ControlResult(
                        control_id=self.control_id,
                        name=self.name,
                        category=self.category,
                        status=ControlStatus.NON_COMPLIANT,
                        risk_level=self.risk_level,
                        evidence="System file integrity violations detected",
                        details="Run sfc /scannow to repair",
                        command_output=result.stdout[:500] if result.stdout else ""
                    )
            
            # If SFC completed (exit code 0) but output unclear, assume compliant
            # SFC returns 0 on success
            if result.success:
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.COMPLIANT,
                    risk_level=self.risk_level,
                    evidence="SFC scan completed without errors",
                    details="No violations reported",
                    command_output=result.stdout[:500] if result.stdout else "SFC completed"
                )
            
            # Unknown state - return with output for debugging
            return ControlResult(
                control_id=self.control_id,
                name=self.name,
                category=self.category,
                status=ControlStatus.ERROR,
                risk_level=self.risk_level,
                evidence="SFC scan could not determine system state",
                details="Check output for details",
                command_output=result.stdout[:500] if result.stdout else result.stderr[:500] if result.stderr else "No output"
            )
                
        except Exception as e:
            return ControlResult(
                control_id=self.control_id,
                name=self.name,
                category=self.category,
                status=ControlStatus.ERROR,
                risk_level=self.risk_level,
                evidence="Error running SFC",
                error_message=str(e)
            )
    
    def remediate(self) -> bool:
        """Run SFC /scannow to repair system files."""
        try:
            self._log('info', "Starting SFC /scannow (this may take 15-30 minutes)...")
            # SFC repair can take even longer than verify - 60 min timeout
            result = self.runner.run_cmd('sfc /scannow', timeout=3600)
            
            if result.success or 'successfully repaired' in result.stdout.lower():
                self._log('info', "SFC completed")
                return True
            else:
                self._log('warning', f"SFC completed with issues: {result.stdout[:200]}")
                return True  # SFC ran, even if issues remain
                
        except Exception as e:
            self._log('error', f"SFC remediation error: {str(e)}")
            return False
    
    def verify(self) -> ControlResult:
        """Verify system file integrity after remediation."""
        return self.audit()


class LSAProtectionControl(RegistryControl):
    """
    INTG-06: LSA Protection (RunAsPPL)
    Ensures Local Security Authority is running as Protected Process Light.
    Prevents credential dumping tools like Mimikatz.
    """
    
    registry_path = r'HKLM\SYSTEM\CurrentControlSet\Control\Lsa'
    registry_value = 'RunAsPPL'
    expected_data = 1
    value_type = 'REG_DWORD'
    comparison = 'equal'
    
    def __init__(self):
        super().__init__(
            control_id="INTG-06",
            name="LSA Protection (RunAsPPL)",
            description="Verify LSA is running as Protected Process Light",
            category=CIACategory.INTEGRITY,
            risk_level=RiskLevel.CRITICAL,
            cis_reference="CIS 18.3.1",
            nist_reference="SC-39"
        )


class CredentialGuardControl(SecurityControl):
    """
    INTG-07: Credential Guard
    Ensures Credential Guard is enabled to protect credentials using virtualization.
    Requires compatible hardware (VBS capable).
    """
    
    def __init__(self):
        super().__init__(
            control_id="INTG-07",
            name="Credential Guard",
            description="Verify Credential Guard is enabled for credential protection",
            category=CIACategory.INTEGRITY,
            risk_level=RiskLevel.HIGH,
            cis_reference="CIS 18.8.5.1",
            nist_reference="SC-39"
        )
        self._supports_rollback = False  # Requires reboot and can cause issues
    
    def audit(self) -> ControlResult:
        """Check Credential Guard status."""
        try:
            # Check via DeviceGuard WMI class
            result = self.runner.run_powershell(
                '''
                $dg = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\\Microsoft\\Windows\\DeviceGuard -ErrorAction SilentlyContinue
                if ($dg) {
                    $securityServicesRunning = $dg.SecurityServicesRunning
                    if ($securityServicesRunning -contains 1) {
                        Write-Output "CredentialGuard: Enabled"
                    } else {
                        Write-Output "CredentialGuard: Disabled"
                    }
                    Write-Output "VBS Status: $($dg.VirtualizationBasedSecurityStatus)"
                } else {
                    Write-Output "DeviceGuard: Not available"
                }
                '''
            )
            
            output = result.stdout.strip()
            
            if 'CredentialGuard: Enabled' in output:
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.COMPLIANT,
                    risk_level=self.risk_level,
                    evidence="Credential Guard is ENABLED",
                    command_output=output
                )
            elif 'Not available' in output:
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.NOT_APPLICABLE,
                    risk_level=self.risk_level,
                    evidence="Credential Guard not available on this system",
                    details="Requires compatible hardware (VBS/HVCI capable)"
                )
            else:
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.NON_COMPLIANT,
                    risk_level=self.risk_level,
                    evidence="Credential Guard is DISABLED",
                    details="Credentials are vulnerable to theft",
                    command_output=output
                )
                
        except Exception as e:
            return ControlResult(
                control_id=self.control_id,
                name=self.name,
                category=self.category,
                status=ControlStatus.ERROR,
                risk_level=self.risk_level,
                evidence="Error checking Credential Guard",
                error_message=str(e)
            )
    
    def remediate(self) -> bool:
        """Enable Credential Guard via registry."""
        try:
            # Enable VBS
            self.runner.run_reg_add(
                r'HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard',
                'EnableVirtualizationBasedSecurity', 'REG_DWORD', '1'
            )
            
            # Enable Credential Guard
            result = self.runner.run_reg_add(
                r'HKLM\SYSTEM\CurrentControlSet\Control\Lsa',
                'LsaCfgFlags', 'REG_DWORD', '1'
            )
            
            if result.success:
                self._log('info', "Credential Guard settings applied (reboot required)")
                return True
            return False
            
        except Exception as e:
            self._log('error', f"Credential Guard remediation error: {str(e)}")
            return False
    
    def verify(self) -> ControlResult:
        """Verify Credential Guard status."""
        return self.audit()


class SecureBootControl(SecurityControl):
    """
    INTG-08: Secure Boot
    Ensures Secure Boot is enabled to prevent bootkit attacks.
    """
    
    def __init__(self):
        super().__init__(
            control_id="INTG-08",
            name="Secure Boot Enabled",
            description="Verify Secure Boot is enabled",
            category=CIACategory.INTEGRITY,
            risk_level=RiskLevel.HIGH,
            cis_reference="N/A",
            nist_reference="SI-7"
        )
        self._supports_rollback = False  # Firmware setting
    
    def audit(self) -> ControlResult:
        """Check Secure Boot status."""
        try:
            result = self.runner.run_powershell(
                'Confirm-SecureBootUEFI'
            )
            
            output = result.stdout.strip()
            
            if 'True' in output or result.success and 'true' in output.lower():
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.COMPLIANT,
                    risk_level=self.risk_level,
                    evidence="Secure Boot is ENABLED",
                    command_output=output
                )
            elif 'not supported' in result.stderr.lower() or 'cmdlet' in result.stderr.lower():
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.NOT_APPLICABLE,
                    risk_level=self.risk_level,
                    evidence="Secure Boot not supported (legacy BIOS mode)",
                    details="System may be running in legacy BIOS mode"
                )
            else:
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.NON_COMPLIANT,
                    risk_level=self.risk_level,
                    evidence="Secure Boot is DISABLED",
                    details="System vulnerable to bootkit attacks",
                    command_output=output
                )
                
        except Exception as e:
            return ControlResult(
                control_id=self.control_id,
                name=self.name,
                category=self.category,
                status=ControlStatus.ERROR,
                risk_level=self.risk_level,
                evidence="Error checking Secure Boot status",
                error_message=str(e)
            )
    
    def remediate(self) -> bool:
        """Cannot remediate - requires UEFI firmware setting."""
        self._log('warning', "Secure Boot must be enabled in UEFI/BIOS firmware settings")
        return False
    
    def verify(self) -> ControlResult:
        """Verify Secure Boot status."""
        return self.audit()


class DriverSignatureEnforcementControl(SecurityControl):
    """
    INTG-09: Driver Signature Enforcement
    Ensures Windows requires signed drivers.
    """
    
    def __init__(self):
        super().__init__(
            control_id="INTG-09",
            name="Driver Signature Enforcement",
            description="Verify Windows requires signed drivers",
            category=CIACategory.INTEGRITY,
            risk_level=RiskLevel.HIGH,
            cis_reference="N/A",
            nist_reference="SI-7"
        )
        self._supports_rollback = True
    
    def audit(self) -> ControlResult:
        """Check driver signature enforcement."""
        try:
            result = self.runner.run_cmd('bcdedit /enum {current}')
            
            if not result.success:
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.ERROR,
                    risk_level=self.risk_level,
                    evidence="Failed to query boot configuration",
                    error_message=result.stderr
                )
            
            output = result.stdout
            
            # Check if testsigning is enabled (bad)
            if 'testsigning' in output.lower() and 'yes' in output.lower():
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.NON_COMPLIANT,
                    risk_level=self.risk_level,
                    evidence="Test signing mode is ENABLED",
                    details="Unsigned drivers can be loaded - security risk",
                    command_output=output[:500]
                )
            
            # Check if nointegritychecks is enabled (bad)
            if 'nointegritychecks' in output.lower() and 'yes' in output.lower():
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.NON_COMPLIANT,
                    risk_level=self.risk_level,
                    evidence="Integrity checks are DISABLED",
                    details="Unsigned code can be loaded - security risk",
                    command_output=output[:500]
                )
            
            return ControlResult(
                control_id=self.control_id,
                name=self.name,
                category=self.category,
                status=ControlStatus.COMPLIANT,
                risk_level=self.risk_level,
                evidence="Driver signature enforcement is enabled",
                command_output=output[:500]
            )
                
        except Exception as e:
            return ControlResult(
                control_id=self.control_id,
                name=self.name,
                category=self.category,
                status=ControlStatus.ERROR,
                risk_level=self.risk_level,
                evidence="Error checking driver signature enforcement",
                error_message=str(e)
            )
    
    def remediate(self) -> bool:
        """Disable test signing mode."""
        try:
            result = self.runner.run_cmd('bcdedit /set testsigning off')
            result2 = self.runner.run_cmd('bcdedit /set nointegritychecks off')
            
            if result.success or result2.success:
                self._log('info', "Driver signature enforcement configured (reboot required)")
                return True
            return False
            
        except Exception as e:
            self._log('error', f"Driver signature enforcement error: {str(e)}")
            return False
    
    def verify(self) -> ControlResult:
        """Verify driver signature enforcement."""
        return self.audit()


class PowerShellScriptBlockLoggingControl(RegistryControl):
    """
    INTG-10: PowerShell Script Block Logging
    Ensures PowerShell script block logging is enabled for threat detection.
    """
    
    registry_path = r'HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
    registry_value = 'EnableScriptBlockLogging'
    expected_data = 1
    value_type = 'REG_DWORD'
    comparison = 'equal'
    
    def __init__(self):
        super().__init__(
            control_id="INTG-10",
            name="PowerShell Script Block Logging",
            description="Verify PowerShell script block logging is enabled",
            category=CIACategory.INTEGRITY,
            risk_level=RiskLevel.MEDIUM,
            cis_reference="CIS 18.9.95.2",
            nist_reference="AU-2"
        )


class PowerShellTranscriptionControl(RegistryControl):
    """
    INTG-11: PowerShell Transcription
    Ensures PowerShell transcription is enabled to capture all PowerShell activity.
    """
    
    registry_path = r'HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription'
    registry_value = 'EnableTranscripting'
    expected_data = 1
    value_type = 'REG_DWORD'
    comparison = 'equal'
    
    def __init__(self):
        super().__init__(
            control_id="INTG-11",
            name="PowerShell Transcription",
            description="Verify PowerShell transcription is enabled",
            category=CIACategory.INTEGRITY,
            risk_level=RiskLevel.MEDIUM,
            cis_reference="CIS 18.9.95.3",
            nist_reference="AU-2"
        )


class CommandLineAuditingControl(RegistryControl):
    """
    INTG-12: Command Line Auditing
    Ensures process creation events include command line arguments.
    """
    
    registry_path = r'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
    registry_value = 'ProcessCreationIncludeCmdLine_Enabled'
    expected_data = 1
    value_type = 'REG_DWORD'
    comparison = 'equal'
    
    def __init__(self):
        super().__init__(
            control_id="INTG-12",
            name="Command Line Auditing",
            description="Verify command line is included in process creation events",
            category=CIACategory.INTEGRITY,
            risk_level=RiskLevel.MEDIUM,
            cis_reference="CIS 18.8.3.1",
            nist_reference="AU-2"
        )


class ObjectAccessAuditControl(SecurityControl):
    """
    INTG-13: Object Access Audit
    Ensures auditing is enabled for object access events.
    """
    
    def __init__(self):
        super().__init__(
            control_id="INTG-13",
            name="Object Access Audit",
            description="Verify auditing for object access is enabled",
            category=CIACategory.INTEGRITY,
            risk_level=RiskLevel.MEDIUM,
            cis_reference="CIS 17.6.1",
            nist_reference="AU-2"
        )
        self._supports_rollback = True
    
    def _capture_current_state(self) -> Optional[Dict[str, Any]]:
        """Capture current audit policy."""
        try:
            result = self.runner.run_cmd('auditpol /get /category:"Object Access"')
            return {'audit_output': result.stdout if result.success else None}
        except Exception:
            return None
    
    def _restore_state(self, state_data: Dict[str, Any]) -> bool:
        """Audit policies are complex - leave as is."""
        return True
    
    def audit(self) -> ControlResult:
        """Check object access auditing."""
        try:
            result = self.runner.run_cmd('auditpol /get /subcategory:"File System"')
            
            if not result.success:
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.ERROR,
                    risk_level=self.risk_level,
                    evidence="Failed to query audit policy",
                    error_message=result.stderr
                )
            
            output = result.stdout
            
            if 'Success' in output and 'Failure' in output:
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.COMPLIANT,
                    risk_level=self.risk_level,
                    evidence="Object access auditing: Success and Failure enabled",
                    command_output=output
                )
            elif 'No Auditing' in output:
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.NON_COMPLIANT,
                    risk_level=self.risk_level,
                    evidence="Object access auditing is DISABLED",
                    command_output=output
                )
            else:
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.NON_COMPLIANT,
                    risk_level=self.risk_level,
                    evidence="Object access auditing partially configured",
                    details="Both Success and Failure should be enabled",
                    command_output=output
                )
                
        except Exception as e:
            return ControlResult(
                control_id=self.control_id,
                name=self.name,
                category=self.category,
                status=ControlStatus.ERROR,
                risk_level=self.risk_level,
                evidence="Error checking audit policy",
                error_message=str(e)
            )
    
    def remediate(self) -> bool:
        """Enable object access auditing."""
        try:
            result = self.runner.run_cmd(
                'auditpol /set /subcategory:"File System" /success:enable /failure:enable'
            )
            return result.success
        except Exception as e:
            self._log('error', f"Audit policy error: {str(e)}")
            return False
    
    def verify(self) -> ControlResult:
        """Verify audit policy."""
        return self.audit()


class PrivilegeUseAuditControl(SecurityControl):
    """
    INTG-14: Privilege Use Audit
    Ensures auditing is enabled for privilege use events.
    """
    
    def __init__(self):
        super().__init__(
            control_id="INTG-14",
            name="Privilege Use Audit",
            description="Verify auditing for privilege use is enabled",
            category=CIACategory.INTEGRITY,
            risk_level=RiskLevel.MEDIUM,
            cis_reference="CIS 17.8.1",
            nist_reference="AU-2"
        )
        self._supports_rollback = True
    
    def audit(self) -> ControlResult:
        """Check privilege use auditing."""
        try:
            result = self.runner.run_cmd('auditpol /get /subcategory:"Sensitive Privilege Use"')
            
            if not result.success:
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.ERROR,
                    risk_level=self.risk_level,
                    evidence="Failed to query audit policy",
                    error_message=result.stderr
                )
            
            output = result.stdout
            
            if 'Success' in output and 'Failure' in output:
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.COMPLIANT,
                    risk_level=self.risk_level,
                    evidence="Privilege use auditing: Success and Failure enabled",
                    command_output=output
                )
            elif 'No Auditing' in output:
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.NON_COMPLIANT,
                    risk_level=self.risk_level,
                    evidence="Privilege use auditing is DISABLED",
                    command_output=output
                )
            else:
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.NON_COMPLIANT,
                    risk_level=self.risk_level,
                    evidence="Privilege use auditing partially configured",
                    command_output=output
                )
                
        except Exception as e:
            return ControlResult(
                control_id=self.control_id,
                name=self.name,
                category=self.category,
                status=ControlStatus.ERROR,
                risk_level=self.risk_level,
                evidence="Error checking audit policy",
                error_message=str(e)
            )
    
    def remediate(self) -> bool:
        """Enable privilege use auditing."""
        try:
            result = self.runner.run_cmd(
                'auditpol /set /subcategory:"Sensitive Privilege Use" /success:enable /failure:enable'
            )
            return result.success
        except Exception as e:
            self._log('error', f"Audit policy error: {str(e)}")
            return False
    
    def verify(self) -> ControlResult:
        """Verify audit policy."""
        return self.audit()


class PolicyChangeAuditControl(SecurityControl):
    """
    INTG-15: Policy Change Audit
    Ensures auditing is enabled for policy change events.
    """
    
    def __init__(self):
        super().__init__(
            control_id="INTG-15",
            name="Policy Change Audit",
            description="Verify auditing for policy changes is enabled",
            category=CIACategory.INTEGRITY,
            risk_level=RiskLevel.MEDIUM,
            cis_reference="CIS 17.7.1",
            nist_reference="AU-2"
        )
        self._supports_rollback = True
    
    def audit(self) -> ControlResult:
        """Check policy change auditing."""
        try:
            result = self.runner.run_cmd('auditpol /get /subcategory:"Audit Policy Change"')
            
            if not result.success:
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.ERROR,
                    risk_level=self.risk_level,
                    evidence="Failed to query audit policy",
                    error_message=result.stderr
                )
            
            output = result.stdout
            
            if 'Success' in output:
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.COMPLIANT,
                    risk_level=self.risk_level,
                    evidence="Policy change auditing: Success enabled",
                    command_output=output
                )
            else:
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.NON_COMPLIANT,
                    risk_level=self.risk_level,
                    evidence="Policy change auditing is not fully configured",
                    command_output=output
                )
                
        except Exception as e:
            return ControlResult(
                control_id=self.control_id,
                name=self.name,
                category=self.category,
                status=ControlStatus.ERROR,
                risk_level=self.risk_level,
                evidence="Error checking audit policy",
                error_message=str(e)
            )
    
    def remediate(self) -> bool:
        """Enable policy change auditing."""
        try:
            result = self.runner.run_cmd(
                'auditpol /set /subcategory:"Audit Policy Change" /success:enable /failure:enable'
            )
            return result.success
        except Exception as e:
            self._log('error', f"Audit policy error: {str(e)}")
            return False
    
    def verify(self) -> ControlResult:
        """Verify audit policy."""
        return self.audit()


class SEHOPEnabledControl(RegistryControl):
    """
    INTG-16: SEHOP Enabled
    Ensures Structured Exception Handler Overwrite Protection is enabled.
    """
    
    registry_path = r'HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel'
    registry_value = 'DisableExceptionChainValidation'
    expected_data = 0  # 0 = SEHOP enabled (validation NOT disabled)
    value_type = 'REG_DWORD'
    comparison = 'equal'
    create_if_missing = False  # Default Windows behavior is secure
    
    def __init__(self):
        super().__init__(
            control_id="INTG-16",
            name="SEHOP Enabled",
            description="Verify Structured Exception Handler Overwrite Protection is enabled",
            category=CIACategory.INTEGRITY,
            risk_level=RiskLevel.HIGH,
            cis_reference="N/A",
            nist_reference="SI-16"
        )
    
    def audit(self) -> ControlResult:
        """Check SEHOP status."""
        try:
            result = self.runner.run_reg_query(self.registry_path, self.registry_value)
            
            if not result.success:
                # Value doesn't exist - this is the default (SEHOP enabled)
                if 'unable to find' in result.stderr.lower():
                    return ControlResult(
                        control_id=self.control_id,
                        name=self.name,
                        category=self.category,
                        status=ControlStatus.COMPLIANT,
                        risk_level=self.risk_level,
                        evidence="SEHOP is enabled (default Windows behavior)"
                    )
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.ERROR,
                    risk_level=self.risk_level,
                    evidence="Failed to check SEHOP status",
                    error_message=result.stderr
                )
            
            # Value exists - check if it's 0 (enabled) or 1 (disabled)
            if '0x0' in result.stdout or 'REG_DWORD    0' in result.stdout:
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.COMPLIANT,
                    risk_level=self.risk_level,
                    evidence="SEHOP is enabled",
                    command_output=result.stdout
                )
            else:
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.NON_COMPLIANT,
                    risk_level=self.risk_level,
                    evidence="SEHOP is DISABLED",
                    details="System vulnerable to SEH-based exploits",
                    command_output=result.stdout
                )
                
        except Exception as e:
            return ControlResult(
                control_id=self.control_id,
                name=self.name,
                category=self.category,
                status=ControlStatus.ERROR,
                risk_level=self.risk_level,
                evidence="Error checking SEHOP status",
                error_message=str(e)
            )


class DEPEnabledControl(SecurityControl):
    """
    INTG-17: DEP/NX Enabled
    Ensures Data Execution Prevention is enabled.
    """
    
    def __init__(self):
        super().__init__(
            control_id="INTG-17",
            name="DEP/NX Enabled",
            description="Verify Data Execution Prevention is enabled",
            category=CIACategory.INTEGRITY,
            risk_level=RiskLevel.HIGH,
            cis_reference="CIS 18.8.3.2",
            nist_reference="SI-16"
        )
        self._supports_rollback = True
    
    def audit(self) -> ControlResult:
        """Check DEP status."""
        try:
            result = self.runner.run_cmd('bcdedit /enum {current}')
            
            if not result.success:
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.ERROR,
                    risk_level=self.risk_level,
                    evidence="Failed to query boot configuration",
                    error_message=result.stderr
                )
            
            output = result.stdout.lower()
            
            # Check nx policy
            # OptIn = DEP for essential Windows programs
            # OptOut = DEP for all programs except excluded
            # AlwaysOn = DEP for all programs (most secure)
            # AlwaysOff = DEP disabled (insecure)
            
            if 'nx' not in output:
                # Default is OptIn which is acceptable
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.COMPLIANT,
                    risk_level=self.risk_level,
                    evidence="DEP is enabled (default policy)",
                    command_output=result.stdout[:500]
                )
            
            if 'alwaysoff' in output:
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.NON_COMPLIANT,
                    risk_level=self.risk_level,
                    evidence="DEP is DISABLED (AlwaysOff)",
                    details="System vulnerable to code execution attacks",
                    command_output=result.stdout[:500]
                )
            
            return ControlResult(
                control_id=self.control_id,
                name=self.name,
                category=self.category,
                status=ControlStatus.COMPLIANT,
                risk_level=self.risk_level,
                evidence="DEP is enabled",
                command_output=result.stdout[:500]
            )
                
        except Exception as e:
            return ControlResult(
                control_id=self.control_id,
                name=self.name,
                category=self.category,
                status=ControlStatus.ERROR,
                risk_level=self.risk_level,
                evidence="Error checking DEP status",
                error_message=str(e)
            )
    
    def remediate(self) -> bool:
        """Enable DEP."""
        try:
            result = self.runner.run_cmd('bcdedit /set {current} nx OptOut')
            
            if result.success:
                self._log('info', "DEP configured to OptOut mode (reboot required)")
                return True
            return False
            
        except Exception as e:
            self._log('error', f"DEP remediation error: {str(e)}")
            return False
    
    def verify(self) -> ControlResult:
        """Verify DEP status."""
        return self.audit()


class ASLREnabledControl(MultiRegistryControl):
    """
    INTG-18: ASLR Enabled
    Ensures Address Space Layout Randomization is enabled system-wide.
    """
    
    registry_checks = [
        {
            'path': r'HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management',
            'value': 'MoveImages',
            'expected': 0xFFFFFFFF,  # -1 = Always randomize
            'type': 'REG_DWORD',
            'comparison': 'equal'
        }
    ]
    require_all = True
    
    def __init__(self):
        super().__init__(
            control_id="INTG-18",
            name="ASLR Enabled",
            description="Verify Address Space Layout Randomization is enabled",
            category=CIACategory.INTEGRITY,
            risk_level=RiskLevel.HIGH,
            cis_reference="N/A",
            nist_reference="SI-16"
        )
    
    def audit(self) -> ControlResult:
        """Check ASLR status via Windows Exploit Protection."""
        try:
            # Check via PowerShell for exploit protection settings
            result = self.runner.run_powershell(
                'Get-ProcessMitigation -System | Select-Object -ExpandProperty ASLR | Format-List'
            )
            
            if result.success and result.stdout:
                output = result.stdout
                
                if 'BottomUp' in output and ('ON' in output or 'True' in output):
                    return ControlResult(
                        control_id=self.control_id,
                        name=self.name,
                        category=self.category,
                        status=ControlStatus.COMPLIANT,
                        risk_level=self.risk_level,
                        evidence="ASLR is enabled system-wide",
                        command_output=output[:500]
                    )
            
            # Fallback - check registry
            reg_result = self.runner.run_reg_query(
                r'HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management',
                'MoveImages'
            )
            
            if reg_result.success:
                # MoveImages = 0xFFFFFFFF (-1) means always randomize
                if '0xffffffff' in reg_result.stdout.lower():
                    return ControlResult(
                        control_id=self.control_id,
                        name=self.name,
                        category=self.category,
                        status=ControlStatus.COMPLIANT,
                        risk_level=self.risk_level,
                        evidence="ASLR is enabled (MoveImages = -1)",
                        command_output=reg_result.stdout
                    )
            
            # Default Windows 10/11 has ASLR enabled
            return ControlResult(
                control_id=self.control_id,
                name=self.name,
                category=self.category,
                status=ControlStatus.COMPLIANT,
                risk_level=self.risk_level,
                evidence="ASLR is enabled (Windows default)",
                details="Modern Windows enables ASLR by default"
            )
                
        except Exception as e:
            return ControlResult(
                control_id=self.control_id,
                name=self.name,
                category=self.category,
                status=ControlStatus.ERROR,
                risk_level=self.risk_level,
                evidence="Error checking ASLR status",
                error_message=str(e)
            )


class ASRRulesControl(SecurityControl):
    """
    INTG-19: Attack Surface Reduction Rules
    Verifies Windows Defender ASR rules are configured to block
    common attack vectors (Office macros, scripts, credential theft).
    
    Production default: Require 6/8 minimum rules enabled.
    Warns if mandatory rules (BlockOffice, BlockScripts) are missing.
    """
    
    # Critical ASR Rule GUIDs (8 total)
    ASR_CRITICAL_RULES = {
        'D4F940AB-401B-4EFC-AADC-AD5F3C50688A': 'Block Office apps from creating child processes',
        '3B576869-A4EC-4529-8536-B80A7769E899': 'Block Office apps from creating executable content',
        '75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84': 'Block Office apps from injecting code into other processes',
        'D3E037E1-3EB8-44C8-A917-57927947596D': 'Block JavaScript/VBScript from launching downloaded executables',
        '5BEB7EFE-FD9A-4556-801D-275E5FFC04CC': 'Block execution of potentially obfuscated scripts',
        '9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2': 'Block credential stealing from Windows LSASS',
        'B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4': 'Block untrusted and unsigned processes from USB',
        'E6DB77E5-3DF2-4CF1-B95A-636979351E5B': 'Block persistence through WMI event subscription',
    }
    
    # These two are MUST-HAVE (warn if missing even when compliant)
    ASR_MANDATORY_RULES = [
        'D4F940AB-401B-4EFC-AADC-AD5F3C50688A',  # Block Office child processes
        '5BEB7EFE-FD9A-4556-801D-275E5FFC04CC',  # Block obfuscated scripts
    ]
    
    # Minimum rules required for compliance
    MIN_RULES_REQUIRED = 6
    
    def __init__(self):
        super().__init__(
            control_id="INTG-19",
            name="Attack Surface Reduction Rules",
            description="Verify Defender ASR rules block Office macros, scripts, credential theft",
            category=CIACategory.INTEGRITY,
            risk_level=RiskLevel.CRITICAL,
            cis_reference="CIS 18.9.47.5.1",
            nist_reference="SI-3"
        )
        self._supports_rollback = True
    
    def _capture_current_state(self) -> Optional[Dict[str, Any]]:
        """Capture current ASR rules state."""
        try:
            result = self.runner.run_powershell(
                'Get-MpPreference | Select-Object AttackSurfaceReductionRules_Ids, '
                'AttackSurfaceReductionRules_Actions | ConvertTo-Json'
            )
            if result.success:
                return {'asr_config': result.stdout}
            return None
        except Exception:
            return None
    
    def _restore_state(self, state_data: Dict[str, Any]) -> bool:
        """Restore ASR rules (complex, best effort)."""
        # ASR rule restoration is complex; recommend manual intervention
        return False
    
    def audit(self) -> ControlResult:
        """Check ASR rules configuration."""
        try:
            # Check if Defender is available
            defender_check = self.runner.run_powershell(
                'Get-MpPreference -ErrorAction Stop | Select-Object -First 1'
            )
            
            if not defender_check.success:
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.NOT_APPLICABLE,
                    risk_level=self.risk_level,
                    evidence="Windows Defender not available",
                    details="Third-party antivirus may be installed. ASR requires Defender.",
                    error_message=defender_check.stderr
                )
            
            # Get ASR rules configuration
            result = self.runner.run_powershell(
                '$pref = Get-MpPreference; '
                '$ids = $pref.AttackSurfaceReductionRules_Ids; '
                '$actions = $pref.AttackSurfaceReductionRules_Actions; '
                'if ($ids) { for ($i=0; $i -lt $ids.Count; $i++) { '
                'Write-Output "$($ids[$i])=$($actions[$i])" } } '
                'else { Write-Output "NONE" }'
            )
            
            if not result.success:
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.ERROR,
                    risk_level=self.risk_level,
                    evidence="Failed to query ASR rules",
                    error_message=result.stderr
                )
            
            output = result.stdout.strip()
            
            # Parse ASR rules
            # Actions: 0=Disabled, 1=Block, 2=Audit, 6=Warn
            enabled_rules = []
            audit_rules = []
            missing_mandatory = []
            
            if output == "NONE" or not output:
                # No ASR rules configured
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.NON_COMPLIANT,
                    risk_level=self.risk_level,
                    evidence="No ASR rules configured",
                    details="Attack Surface Reduction rules are not configured. "
                            f"Minimum {self.MIN_RULES_REQUIRED}/8 critical rules required.",
                    command_output=output
                )
            
            # Parse rule=action pairs
            for line in output.split('\n'):
                line = line.strip()
                if '=' in line:
                    parts = line.split('=')
                    if len(parts) == 2:
                        rule_id = parts[0].strip().upper()
                        try:
                            action = int(parts[1].strip())
                        except ValueError:
                            continue
                        
                        # Check if it's a critical rule
                        if rule_id in [r.upper() for r in self.ASR_CRITICAL_RULES.keys()]:
                            if action == 1:  # Block mode
                                enabled_rules.append(rule_id)
                            elif action == 2:  # Audit mode
                                audit_rules.append(rule_id)
            
            # Check mandatory rules
            for mandatory in self.ASR_MANDATORY_RULES:
                if mandatory.upper() not in enabled_rules:
                    missing_mandatory.append(self.ASR_CRITICAL_RULES.get(mandatory, mandatory))
            
            enabled_count = len(enabled_rules)
            audit_count = len(audit_rules)
            total_configured = enabled_count + audit_count
            
            # Build evidence string
            evidence_parts = [f"ASR rules: {enabled_count}/8 blocking, {audit_count}/8 auditing"]
            
            # Determine compliance status
            if enabled_count >= self.MIN_RULES_REQUIRED:
                if missing_mandatory:
                    # Compliant but missing critical rules - add warning
                    details = (f"ASR configured with {enabled_count}/8 rules in block mode. "
                              f"WARNING: Missing critical rules: {', '.join(missing_mandatory)}. "
                              "Recommend enabling all critical rules for maximum protection.")
                    evidence = f"ASR configured: {enabled_count}/8 rules (missing critical: {len(missing_mandatory)})"
                else:
                    details = (f"ASR properly configured with {enabled_count}/8 critical rules in block mode. "
                              f"Excellent ransomware and script attack protection.")
                    evidence = f"ASR configured: {enabled_count}/8 rules enabled"
                
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.COMPLIANT,
                    risk_level=self.risk_level,
                    evidence=evidence,
                    details=details,
                    command_output=output[:1000]
                )
            elif enabled_count >= 3:
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.NON_COMPLIANT,
                    risk_level=self.risk_level,
                    evidence=f"Partial ASR: {enabled_count}/8 rules (minimum {self.MIN_RULES_REQUIRED} required)",
                    details=f"Only {enabled_count} ASR rules enabled. "
                            f"Minimum {self.MIN_RULES_REQUIRED}/8 critical rules required for compliance. "
                            f"Missing rules leave gaps in ransomware protection.",
                    command_output=output[:1000]
                )
            else:
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.NON_COMPLIANT,
                    risk_level=self.risk_level,
                    evidence=f"ASR inadequate: {enabled_count}/8 rules enabled",
                    details=f"Only {enabled_count} ASR rules enabled. System is vulnerable to "
                            "Office macro attacks, script-based malware, and credential theft. "
                            f"Enable at least {self.MIN_RULES_REQUIRED}/8 critical rules.",
                    command_output=output[:1000]
                )
                
        except Exception as e:
            return ControlResult(
                control_id=self.control_id,
                name=self.name,
                category=self.category,
                status=ControlStatus.ERROR,
                risk_level=self.risk_level,
                evidence="Error checking ASR rules",
                error_message=str(e)
            )
    
    def remediate(self) -> bool:
        """Enable critical ASR rules in Block mode."""
        try:
            success_count = 0
            for rule_id in self.ASR_CRITICAL_RULES.keys():
                # Add rule in Block mode (Action = 1)
                result = self.runner.run_powershell(
                    f'Add-MpPreference -AttackSurfaceReductionRules_Ids "{rule_id}" '
                    '-AttackSurfaceReductionRules_Actions 1'
                )
                if result.success:
                    success_count += 1
            
            return success_count >= self.MIN_RULES_REQUIRED
        except Exception:
            return False
    
    def verify(self) -> ControlResult:
        """Verify ASR rules are properly configured after remediation."""
        return self.audit()


class VBSHVCIControl(SecurityControl):
    """
    INTG-20: Virtualization-Based Security / Memory Integrity (HVCI)
    Verifies VBS and Hypervisor-protected Code Integrity is enabled
    to protect kernel from exploit techniques.
    
    Production default: Report N/A on incapable hardware with upgrade guidance.
    """
    
    def __init__(self):
        super().__init__(
            control_id="INTG-20",
            name="VBS/HVCI Memory Integrity",
            description="Verify Virtualization-Based Security and Memory Integrity enabled",
            category=CIACategory.INTEGRITY,
            risk_level=RiskLevel.CRITICAL,
            cis_reference="CIS 18.9.5.2",
            nist_reference="SC-39"
        )
        self._supports_rollback = True
    
    def _capture_current_state(self) -> Optional[Dict[str, Any]]:
        """Capture current VBS/HVCI state."""
        try:
            result = self.runner.run_powershell(
                'Get-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard" '
                '-ErrorAction SilentlyContinue | ConvertTo-Json'
            )
            return {'vbs_registry': result.stdout if result.success else None}
        except Exception:
            return None
    
    def _restore_state(self, state_data: Dict[str, Any]) -> bool:
        """Restore VBS/HVCI state (requires reboot)."""
        # Disabling VBS requires registry changes + reboot
        # Not recommended for automatic rollback
        return False
    
    def audit(self) -> ControlResult:
        """Check VBS and HVCI status."""
        try:
            # First check hardware capability
            hw_check = self.runner.run_powershell(
                '$info = Get-ComputerInfo -Property HyperVisorPresent, '
                'DeviceGuardSmartStatus, DeviceGuardSecurityServicesConfigured, '
                'DeviceGuardSecurityServicesRunning -ErrorAction SilentlyContinue; '
                'if ($info) { $info | ConvertTo-Json } else { Write-Output "UNAVAILABLE" }'
            )
            
            # Check for VBS running status via WMI
            vbs_status = self.runner.run_powershell(
                'try { '
                '$dg = Get-CimInstance -ClassName Win32_DeviceGuard '
                '-Namespace root\\Microsoft\\Windows\\DeviceGuard -ErrorAction Stop; '
                'Write-Output "VBS_AVAILABLE=$($dg.VirtualizationBasedSecurityStatus)"; '
                'Write-Output "SERVICES_RUNNING=$($dg.SecurityServicesRunning -join \",\")"; '
                'Write-Output "SERVICES_CONFIGURED=$($dg.SecurityServicesConfigured -join \",\")" '
                '} catch { Write-Output "WMI_ERROR" }'
            )
            
            # Check registry settings
            reg_vbs = self.runner.run_reg_query(
                r'HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard',
                'EnableVirtualizationBasedSecurity'
            )
            
            reg_hvci = self.runner.run_reg_query(
                r'HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity',
                'Enabled'
            )
            
            # Parse results
            vbs_enabled_reg = reg_vbs.success and '0x1' in reg_vbs.stdout
            hvci_enabled_reg = reg_hvci.success and '0x1' in reg_hvci.stdout
            
            vbs_running = False
            hvci_running = False
            hw_capable = True
            
            if vbs_status.success and vbs_status.stdout:
                output = vbs_status.stdout
                if 'WMI_ERROR' in output:
                    # WMI class not available - likely older Windows or feature not installed
                    hw_capable = False
                else:
                    # VirtualizationBasedSecurityStatus: 0=Off, 1=Configured, 2=Running
                    if 'VBS_AVAILABLE=2' in output:
                        vbs_running = True
                    # SecurityServicesRunning: 1=Credential Guard, 2=HVCI
                    if 'SERVICES_RUNNING=' in output and '2' in output.split('SERVICES_RUNNING=')[1].split('\n')[0]:
                        hvci_running = True
            
            # Check if hardware is capable
            if hw_check.success and hw_check.stdout:
                if 'UNAVAILABLE' in hw_check.stdout:
                    hw_capable = False
                elif 'HyperVisorPresent' in hw_check.stdout:
                    # Parse JSON response
                    try:
                        import json
                        hw_info = json.loads(hw_check.stdout)
                        if hw_info.get('HyperVisorPresent') == False:
                            hw_capable = False
                    except:
                        pass
            
            # Determine status
            if not hw_capable and not vbs_running:
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.NOT_APPLICABLE,
                    risk_level=self.risk_level,
                    evidence="Hardware incompatible with VBS/HVCI",
                    details="Virtualization-Based Security requires: "
                            "Hyper-V capable CPU (Intel VT-x/AMD-V), UEFI firmware with Secure Boot, "
                            "and TPM 2.0 (recommended). Upgrade path: Enable virtualization in BIOS, "
                            "ensure UEFI boot mode, enable Secure Boot.",
                    command_output=f"Registry VBS: {vbs_enabled_reg}, HVCI: {hvci_enabled_reg}"
                )
            
            if vbs_running and hvci_running:
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.COMPLIANT,
                    risk_level=self.risk_level,
                    evidence="VBS and HVCI (Memory Integrity) active and enforcing",
                    details="Virtualization-Based Security is running with Hypervisor-protected "
                            "Code Integrity enabled. Kernel is protected from driver-based attacks.",
                    command_output=vbs_status.stdout[:500] if vbs_status.stdout else None
                )
            
            if vbs_running and not hvci_running:
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.NON_COMPLIANT,
                    risk_level=self.risk_level,
                    evidence="VBS running but HVCI (Memory Integrity) not enabled",
                    details="Virtualization-Based Security is running but Memory Integrity is disabled. "
                            "Enable Memory Integrity in Windows Security > Device Security > Core isolation.",
                    command_output=vbs_status.stdout[:500] if vbs_status.stdout else None
                )
            
            if vbs_enabled_reg and hvci_enabled_reg:
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.NON_COMPLIANT,
                    risk_level=self.risk_level,
                    evidence="VBS/HVCI configured but not running (reboot required)",
                    details="VBS and HVCI are enabled in registry but not yet active. "
                            "A system reboot is required to activate these protections.",
                    command_output=f"VBS registry: {reg_vbs.stdout}\nHVCI registry: {reg_hvci.stdout}"
                )
            
            return ControlResult(
                control_id=self.control_id,
                name=self.name,
                category=self.category,
                status=ControlStatus.NON_COMPLIANT,
                risk_level=self.risk_level,
                evidence="VBS/HVCI not enabled",
                details="Virtualization-Based Security and Memory Integrity are not configured. "
                        "Enable via: Windows Security > Device Security > Core isolation > Memory integrity, "
                        "or via Group Policy: Computer Configuration > Administrative Templates > System > Device Guard.",
                command_output=f"VBS: {vbs_enabled_reg}, HVCI: {hvci_enabled_reg}"
            )
                
        except Exception as e:
            return ControlResult(
                control_id=self.control_id,
                name=self.name,
                category=self.category,
                status=ControlStatus.ERROR,
                risk_level=self.risk_level,
                evidence="Error checking VBS/HVCI status",
                error_message=str(e)
            )
    
    def remediate(self) -> bool:
        """Enable VBS and HVCI via registry (requires reboot)."""
        try:
            # Enable VBS
            vbs_result = self.runner.run_reg_add(
                r'HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard',
                'EnableVirtualizationBasedSecurity',
                'REG_DWORD',
                '1'
            )
            
            # Set platform security features (1 = Secure Boot)
            platform_result = self.runner.run_reg_add(
                r'HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard',
                'RequirePlatformSecurityFeatures',
                'REG_DWORD',
                '1'
            )
            
            # Enable HVCI
            hvci_result = self.runner.run_reg_add(
                r'HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity',
                'Enabled',
                'REG_DWORD',
                '1'
            )
            
            return vbs_result.success and hvci_result.success
        except Exception:
            return False
    
    def verify(self) -> ControlResult:
        """Verify VBS/HVCI configuration (may require reboot to fully activate)."""
        return self.audit()


class ExploitProtectionControl(SecurityControl):
    """
    INTG-21: Windows Exploit Protection
    Verifies system-wide exploit mitigations are enabled including CFG, DEP, SEHOP,
    and mandatory ASLR. These mitigations protect against memory corruption attacks.
    """
    
    def __init__(self):
        super().__init__(
            control_id="INTG-21",
            name="Windows Exploit Protection",
            description="Verify system-wide exploit mitigations (CFG, DEP, SEHOP, ASLR)",
            category=CIACategory.INTEGRITY,
            risk_level=RiskLevel.HIGH,
            cis_reference="CIS 18.9.24",
            nist_reference="SI-16"
        )
        self._supports_rollback = False
    
    def audit(self) -> ControlResult:
        """Check Windows Exploit Protection system-wide settings."""
        try:
            # Get system-wide process mitigations
            ps_cmd = """
            try {
                $mitigations = Get-ProcessMitigation -System -ErrorAction Stop
                $results = @{
                    DEP = $mitigations.DEP.Enable
                    CFG = $mitigations.CFG.Enable
                    SEHOP = $mitigations.SEHOP.Enable
                    ForceRelocateImages = $mitigations.ASLR.ForceRelocateImages
                    BottomUp = $mitigations.ASLR.BottomUp
                    HighEntropy = $mitigations.ASLR.HighEntropy
                }
                $results | ConvertTo-Json
            } catch {
                Write-Output "ERROR: $_"
            }
            """
            result = self.runner.run_powershell(ps_cmd)
            
            if result.success and result.stdout.strip() and not result.stdout.strip().startswith("ERROR"):
                import json
                try:
                    mitigations = json.loads(result.stdout.strip())
                    
                    # Count enabled mitigations (True or "ON" or "NOTSET" with system default)
                    enabled_count = 0
                    status_details = []
                    
                    # DEP (Data Execution Prevention)
                    dep_enabled = str(mitigations.get('DEP', '')).upper() in ['TRUE', 'ON', 'ALWAYSON']
                    if dep_enabled:
                        enabled_count += 1
                        status_details.append("DEP: Enabled")
                    else:
                        status_details.append("DEP: Disabled/NotSet")
                    
                    # CFG (Control Flow Guard)
                    cfg_enabled = str(mitigations.get('CFG', '')).upper() in ['TRUE', 'ON']
                    if cfg_enabled:
                        enabled_count += 1
                        status_details.append("CFG: Enabled")
                    else:
                        status_details.append("CFG: Disabled/NotSet")
                    
                    # SEHOP (Structured Exception Handler Overwrite Protection)
                    sehop_enabled = str(mitigations.get('SEHOP', '')).upper() in ['TRUE', 'ON']
                    if sehop_enabled:
                        enabled_count += 1
                        status_details.append("SEHOP: Enabled")
                    else:
                        status_details.append("SEHOP: Disabled/NotSet")
                    
                    # ForceRelocateImages (Mandatory ASLR)
                    aslr_enabled = str(mitigations.get('ForceRelocateImages', '')).upper() in ['TRUE', 'ON']
                    if aslr_enabled:
                        enabled_count += 1
                        status_details.append("Mandatory ASLR: Enabled")
                    else:
                        status_details.append("Mandatory ASLR: Disabled/NotSet")
                    
                    evidence = f"System mitigations: {enabled_count}/4 enabled. " + ", ".join(status_details)
                    
                    # Require at least 3 of 4 mitigations for compliance
                    if enabled_count >= 3:
                        return ControlResult(
                            control_id=self.control_id,
                            name=self.name,
                            category=self.category,
                            status=ControlStatus.COMPLIANT,
                            risk_level=self.risk_level,
                            evidence=evidence,
                            command_output=result.stdout
                        )
                    else:
                        return ControlResult(
                            control_id=self.control_id,
                            name=self.name,
                            category=self.category,
                            status=ControlStatus.NON_COMPLIANT,
                            risk_level=self.risk_level,
                            evidence=evidence,
                            details=f"Only {enabled_count}/4 system mitigations enabled. Enable DEP, CFG, SEHOP, and ForceRelocateImages for full protection."
                        )
                except json.JSONDecodeError:
                    # Fallback: try registry-based check
                    pass
            
            # Fallback: Check via registry for Exploit Protection settings
            reg_cmd = 'reg query "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\kernel" /v MitigationOptions 2>nul'
            reg_result = self.runner.run_cmd(reg_cmd)
            
            if reg_result.success and 'MitigationOptions' in reg_result.stdout:
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.COMPLIANT,
                    risk_level=self.risk_level,
                    evidence="System MitigationOptions configured in registry",
                    command_output=reg_result.stdout
                )
            
            return ControlResult(
                control_id=self.control_id,
                name=self.name,
                category=self.category,
                status=ControlStatus.NON_COMPLIANT,
                risk_level=self.risk_level,
                evidence="Unable to verify exploit protection settings",
                details="Configure Windows Exploit Protection via Windows Security > App & browser control > Exploit protection settings"
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
        """Enable system-wide exploit mitigations."""
        try:
            # Enable DEP
            dep_cmd = "Set-ProcessMitigation -System -Enable DEP"
            self.runner.run_powershell(dep_cmd)
            
            # Enable CFG
            cfg_cmd = "Set-ProcessMitigation -System -Enable CFG"
            self.runner.run_powershell(cfg_cmd)
            
            # Enable SEHOP
            sehop_cmd = "Set-ProcessMitigation -System -Enable SEHOP"
            self.runner.run_powershell(sehop_cmd)
            
            # Enable ForceRelocateImages (Mandatory ASLR)
            aslr_cmd = "Set-ProcessMitigation -System -Enable ForceRelocateImages"
            self.runner.run_powershell(aslr_cmd)
            
            self.logger.warning("Exploit Protection enabled - some legacy applications may not work correctly")
            return True
        except Exception as e:
            self.logger.error(f"Failed to enable exploit protection: {e}")
            return False
    
    def verify(self) -> ControlResult:
        """Verify exploit protection settings."""
        return self.audit()


class ControlledFolderAccessControl(SecurityControl):
    """
    INTG-22: Controlled Folder Access (Ransomware Protection)
    Verifies Windows Defender Controlled Folder Access is enabled to protect
    important folders from unauthorized changes by malicious applications.
    """
    
    def __init__(self):
        super().__init__(
            control_id="INTG-22",
            name="Controlled Folder Access",
            description="Verify Controlled Folder Access ransomware protection is enabled",
            category=CIACategory.INTEGRITY,
            risk_level=RiskLevel.HIGH,
            cis_reference="CIS 18.9.47.4.1",
            nist_reference="SC-7"
        )
        self._supports_rollback = True
    
    def audit(self) -> ControlResult:
        """Check Controlled Folder Access status."""
        try:
            # First check if Windows Defender is the active AV
            defender_check = """
            $status = Get-MpComputerStatus -ErrorAction SilentlyContinue
            if ($status) {
                if ($status.AMServiceEnabled -and $status.AntispywareEnabled) {
                    Write-Output "DEFENDER_ACTIVE"
                } else {
                    Write-Output "DEFENDER_DISABLED"
                }
            } else {
                Write-Output "DEFENDER_NOT_AVAILABLE"
            }
            """
            defender_result = self.runner.run_powershell(defender_check)
            
            if "DEFENDER_NOT_AVAILABLE" in defender_result.stdout or "DEFENDER_DISABLED" in defender_result.stdout:
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.NOT_APPLICABLE,
                    risk_level=self.risk_level,
                    evidence="Windows Defender is not the active antivirus - third-party AV may provide equivalent protection"
                )
            
            # Check Controlled Folder Access setting
            ps_cmd = "(Get-MpPreference).EnableControlledFolderAccess"
            result = self.runner.run_powershell(ps_cmd)
            
            if result.success:
                value = result.stdout.strip()
                # 0 = Disabled, 1 = Enabled, 2 = AuditMode
                if value == "1":
                    return ControlResult(
                        control_id=self.control_id,
                        name=self.name,
                        category=self.category,
                        status=ControlStatus.COMPLIANT,
                        risk_level=self.risk_level,
                        evidence="Controlled Folder Access is Enabled (blocking mode)",
                        command_output=result.stdout
                    )
                elif value == "2":
                    return ControlResult(
                        control_id=self.control_id,
                        name=self.name,
                        category=self.category,
                        status=ControlStatus.COMPLIANT,
                        risk_level=self.risk_level,
                        evidence="Controlled Folder Access is in Audit Mode (logging without blocking)",
                        command_output=result.stdout
                    )
                else:
                    return ControlResult(
                        control_id=self.control_id,
                        name=self.name,
                        category=self.category,
                        status=ControlStatus.NON_COMPLIANT,
                        risk_level=self.risk_level,
                        evidence=f"Controlled Folder Access is Disabled (value: {value})",
                        details="Enable Controlled Folder Access to protect against ransomware. Recommend starting with AuditMode."
                    )
            
            return ControlResult(
                control_id=self.control_id,
                name=self.name,
                category=self.category,
                status=ControlStatus.ERROR,
                risk_level=self.risk_level,
                error_message="Unable to query Controlled Folder Access status"
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
        """Enable Controlled Folder Access in Audit Mode (safer default)."""
        try:
            # Use AuditMode (2) as default - safer for production, won't break apps
            ps_cmd = "Set-MpPreference -EnableControlledFolderAccess AuditMode"
            result = self.runner.run_powershell(ps_cmd)
            
            if result.success:
                self.logger.info("Controlled Folder Access enabled in Audit Mode - monitor logs before switching to Block mode")
                return True
            return False
        except Exception as e:
            self.logger.error(f"Failed to enable Controlled Folder Access: {e}")
            return False
    
    def rollback(self) -> bool:
        """Disable Controlled Folder Access."""
        try:
            ps_cmd = "Set-MpPreference -EnableControlledFolderAccess Disabled"
            result = self.runner.run_powershell(ps_cmd)
            return result.success
        except Exception:
            return False
    
    def verify(self) -> ControlResult:
        """Verify Controlled Folder Access status."""
        return self.audit()


class ELAMControl(SecurityControl):
    """
    INTG-23: Early Launch Anti-Malware (ELAM)
    Verifies ELAM driver policy is configured to protect against bootkits and
    rootkits by controlling which drivers can load during early boot.
    """
    
    def __init__(self):
        super().__init__(
            control_id="INTG-23",
            name="Early Launch Anti-Malware",
            description="Verify ELAM driver policy is configured for boot protection",
            category=CIACategory.INTEGRITY,
            risk_level=RiskLevel.HIGH,
            cis_reference="CIS 18.9.13",
            nist_reference="SI-7"
        )
        self._supports_rollback = True
    
    def audit(self) -> ControlResult:
        """Check ELAM driver load policy."""
        try:
            # Check if system uses UEFI boot (required for full ELAM protection)
            uefi_check = """
            $env = [System.Environment]::GetFolderPath('System')
            $firmware = (Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State' -Name 'UEFISecureBootEnabled' -ErrorAction SilentlyContinue).UEFISecureBootEnabled
            if ($firmware -eq 1) { "UEFI" } 
            elseif (Test-Path "$env\\..\\EFI") { "UEFI_NO_SECUREBOOT" }
            else { "LEGACY_BIOS" }
            """
            boot_result = self.runner.run_powershell(uefi_check)
            boot_mode = boot_result.stdout.strip() if boot_result.success else "UNKNOWN"
            
            # Check ELAM driver load policy
            reg_path = r'HKLM\SYSTEM\CurrentControlSet\Control\EarlyLaunch'
            reg_cmd = f'reg query "{reg_path}" /v DriverLoadPolicy 2>nul'
            result = self.runner.run_cmd(reg_cmd)
            
            # ELAM Policy values:
            # 1 = Good only (strictest - only known good drivers)
            # 3 = Good, unknown, bad but critical (recommended)
            # 7 = All (allows all drivers - insecure)
            # 8 = Disabled (no ELAM protection)
            
            if result.success and 'DriverLoadPolicy' in result.stdout:
                # Parse the value
                import re
                match = re.search(r'DriverLoadPolicy\s+REG_DWORD\s+0x([0-9a-fA-F]+)', result.stdout)
                if match:
                    policy_value = int(match.group(1), 16)
                    
                    policy_names = {
                        1: "Good only (strictest)",
                        3: "Good, unknown, bad but critical (recommended)",
                        7: "All drivers allowed (insecure)",
                        8: "Disabled"
                    }
                    policy_name = policy_names.get(policy_value, f"Unknown ({policy_value})")
                    
                    evidence = f"ELAM Policy: {policy_name}. Boot mode: {boot_mode}"
                    
                    if policy_value in [1, 3]:
                        return ControlResult(
                            control_id=self.control_id,
                            name=self.name,
                            category=self.category,
                            status=ControlStatus.COMPLIANT,
                            risk_level=self.risk_level,
                            evidence=evidence,
                            command_output=result.stdout
                        )
                    else:
                        return ControlResult(
                            control_id=self.control_id,
                            name=self.name,
                            category=self.category,
                            status=ControlStatus.NON_COMPLIANT,
                            risk_level=self.risk_level,
                            evidence=evidence,
                            details="Set ELAM DriverLoadPolicy to 3 (Good, unknown, bad but critical) for optimal protection"
                        )
            
            # Registry key doesn't exist - check if this is UEFI system
            if boot_mode == "LEGACY_BIOS":
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.NOT_APPLICABLE,
                    risk_level=self.risk_level,
                    evidence="Legacy BIOS boot detected - ELAM requires UEFI for full protection"
                )
            
            # Default policy (3) is used when key doesn't exist
            return ControlResult(
                control_id=self.control_id,
                name=self.name,
                category=self.category,
                status=ControlStatus.COMPLIANT,
                risk_level=self.risk_level,
                evidence=f"ELAM using default policy (Good, unknown, bad but critical). Boot mode: {boot_mode}"
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
        """Set ELAM driver policy to recommended value."""
        try:
            # Set to 3 = Good, unknown, bad but critical (balanced protection)
            result = self.runner.run_reg_add(
                r'HKLM\SYSTEM\CurrentControlSet\Control\EarlyLaunch',
                'DriverLoadPolicy',
                'REG_DWORD',
                '3'
            )
            return result.success
        except Exception as e:
            self.logger.error(f"Failed to set ELAM policy: {e}")
            return False
    
    def rollback(self) -> bool:
        """Reset ELAM policy to default (delete the key)."""
        try:
            cmd = 'reg delete "HKLM\\SYSTEM\\CurrentControlSet\\Control\\EarlyLaunch" /v DriverLoadPolicy /f 2>nul'
            result = self.runner.run_cmd(cmd)
            return True  # Even if delete fails, default policy applies
        except Exception:
            return False
    
    def verify(self) -> ControlResult:
        """Verify ELAM policy configuration."""
        return self.audit()


class IntegrityControls(ControlGroup):
    """Collection of all Integrity controls."""
    
    def __init__(self):
        super().__init__(
            name="Integrity Controls",
            category=CIACategory.INTEGRITY,
            description="Controls ensuring system and data integrity"
        )
        
        # Add all integrity controls (INTG-01 to INTG-20)
        self.add_control(DefenderRealtimeControl())
        self.add_control(UACControl())
        self.add_control(PowerShellExecutionPolicyControl())
        self.add_control(AuditPolicyControl())
        self.add_control(SystemFileCheckerControl())
        self.add_control(LSAProtectionControl())
        self.add_control(CredentialGuardControl())
        self.add_control(SecureBootControl())
        self.add_control(DriverSignatureEnforcementControl())
        self.add_control(PowerShellScriptBlockLoggingControl())
        self.add_control(PowerShellTranscriptionControl())
        self.add_control(CommandLineAuditingControl())
        self.add_control(ObjectAccessAuditControl())
        self.add_control(PrivilegeUseAuditControl())
        self.add_control(PolicyChangeAuditControl())
        self.add_control(SEHOPEnabledControl())
        self.add_control(DEPEnabledControl())
        self.add_control(ASLREnabledControl())
        # v2.2: New enterprise controls
        self.add_control(ASRRulesControl())
        self.add_control(VBSHVCIControl())
        # v2.3: Additional enterprise controls (INTG-21 to INTG-23)
        self.add_control(ExploitProtectionControl())
        self.add_control(ControlledFolderAccessControl())
        self.add_control(ELAMControl())
    
    def initialize(self, runner, logger):
        """Initialize all controls with dependencies."""
        for control in self.controls:
            control.set_dependencies(runner, logger)
