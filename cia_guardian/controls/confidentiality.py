"""
Confidentiality Controls
CONF-01: BitLocker Encryption
CONF-02: SMB1 Protocol Disabled
CONF-03: Administrative Shares Disabled
CONF-04: SMB Signing Required
CONF-05: Guest Account Disabled
CONF-06: RDP Network Level Authentication
CONF-07: Remote Registry Disabled
CONF-08: AutoPlay Disabled
CONF-09: Anonymous Enumeration Disabled
CONF-10: NTLM Restriction
CONF-11: WDigest Disabled
CONF-12: Cached Credentials Limited
CONF-13: LAN Manager Hash Disabled
CONF-14: Anonymous SAM Access Disabled
CONF-15: Null Session Pipes Empty
CONF-16: Printer Driver Installation Restricted
CONF-17: Always Install Elevated Disabled
CONF-18: Telemetry Level Restricted
CONF-19: Windows Hello for Business
CONF-20: Windows LAPS (Native)
CONF-21: Kerberos Armoring (FAST)
"""

from typing import Dict, Any, Optional
from .base import (
    SecurityControl, ControlResult, ControlStatus, 
    RiskLevel, CIACategory, ControlGroup
)
from .registry_base import RegistryControl
from .service_base import ServiceControl


class BitLockerControl(SecurityControl):
    """
    CONF-01: BitLocker Drive Encryption
    Ensures system drives are encrypted with BitLocker.
    """
    
    def __init__(self):
        super().__init__(
            control_id="CONF-01",
            name="BitLocker Encryption",
            description="Verify BitLocker is enabled on system drives",
            category=CIACategory.CONFIDENTIALITY,
            risk_level=RiskLevel.CRITICAL,
            cis_reference="CIS 1.1.1",
            nist_reference="SC-28"
        )
        # BitLocker cannot be easily rolled back
        self._supports_rollback = False
    
    def audit(self) -> ControlResult:
        """Check BitLocker status on system drive."""
        try:
            result = self.runner.run_cmd('manage-bde -status C:')
            
            if not result.success:
                # manage-bde might not be available
                if 'not recognized' in result.stderr.lower():
                    return ControlResult(
                        control_id=self.control_id,
                        name=self.name,
                        category=self.category,
                        status=ControlStatus.NOT_APPLICABLE,
                        risk_level=self.risk_level,
                        evidence="BitLocker (manage-bde) not available on this system",
                        details="May be Windows Home edition",
                        command_output=result.stderr
                    )
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.ERROR,
                    risk_level=self.risk_level,
                    evidence="Failed to query BitLocker status",
                    error_message=result.stderr,
                    command_output=result.stdout
                )
            
            output = result.stdout
            protection_on = 'Protection Status:    Protection On' in output or \
                           'Protection Status:        Protection On' in output
            
            if protection_on:
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.COMPLIANT,
                    risk_level=self.risk_level,
                    evidence="BitLocker protection is ON",
                    details="C: drive is encrypted",
                    command_output=output
                )
            else:
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.NON_COMPLIANT,
                    risk_level=self.risk_level,
                    evidence="BitLocker protection is OFF or not enabled",
                    details="C: drive is not encrypted",
                    command_output=output
                )
                
        except Exception as e:
            return ControlResult(
                control_id=self.control_id,
                name=self.name,
                category=self.category,
                status=ControlStatus.ERROR,
                risk_level=self.risk_level,
                evidence="Error checking BitLocker status",
                error_message=str(e)
            )
    
    def remediate(self) -> bool:
        """
        Enable BitLocker on the system drive.
        Note: BitLocker enablement requires TPM and may need user interaction.
        """
        try:
            # First check if TPM is available
            tpm_result = self.runner.run_powershell('Get-Tpm | Select-Object -ExpandProperty TpmPresent')
            
            if 'True' not in tpm_result.stdout:
                self._log('warning', "TPM not present or not enabled - BitLocker requires TPM")
                return False
            
            # Enable BitLocker with recovery password
            # This is a non-interactive approach using recovery password
            enable_result = self.runner.run_powershell(
                'Enable-BitLocker -MountPoint "C:" -EncryptionMethod XtsAes256 '
                '-RecoveryPasswordProtector -SkipHardwareTest'
            )
            
            if enable_result.success or 'already' in enable_result.stdout.lower():
                self._log('info', "BitLocker enable command executed")
                return True
            else:
                self._log('error', f"BitLocker enable failed: {enable_result.stderr}")
                return False
                
        except Exception as e:
            self._log('error', f"BitLocker remediation error: {str(e)}")
            return False
    
    def verify(self) -> ControlResult:
        """Verify BitLocker is now enabled."""
        return self.audit()


class SMB1DisabledControl(SecurityControl):
    """
    CONF-02: SMB1 Protocol Disabled
    Ensures the legacy SMB1 protocol is disabled.
    """
    
    def __init__(self):
        super().__init__(
            control_id="CONF-02",
            name="SMB1 Protocol Disabled",
            description="Verify SMB1 protocol is disabled to prevent legacy vulnerabilities",
            category=CIACategory.CONFIDENTIALITY,
            risk_level=RiskLevel.HIGH,
            cis_reference="CIS 18.3.2",
            nist_reference="CM-7"
        )
        self._supports_rollback = True
    
    def _capture_current_state(self) -> Optional[Dict[str, Any]]:
        """Capture SMB1 protocol state before remediation."""
        try:
            # Check Windows Optional Feature state
            result = self.runner.run_powershell(
                'Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol | '
                'Select-Object -ExpandProperty State'
            )
            
            smb1_feature_state = result.stdout.strip() if result.success else None
            
            # Check SMB Server Configuration
            result2 = self.runner.run_powershell(
                'Get-SmbServerConfiguration | Select-Object -ExpandProperty EnableSMB1Protocol'
            )
            
            smb1_server_state = result2.stdout.strip() if result2.success else None
            
            # Check registry value
            reg_result = self.runner.run_reg_query(
                r'HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters',
                'SMB1'
            )
            
            smb1_registry = reg_result.stdout.strip() if reg_result.success else None
            
            return {
                'feature_state': smb1_feature_state,
                'server_config': smb1_server_state,
                'registry': smb1_registry
            }
        except Exception as e:
            self._log('warning', f"Failed to capture SMB1 state: {str(e)}")
            return None
    
    def _restore_state(self, state_data: Dict[str, Any]) -> bool:
        """Restore SMB1 protocol to previous state."""
        try:
            success = True
            
            # Restore via server config if it was enabled
            if state_data.get('server_config') == 'True':
                result = self.runner.run_powershell(
                    'Set-SmbServerConfiguration -EnableSMB1Protocol $true -Force'
                )
                if not result.success:
                    self._log('warning', "Failed to restore SMB1 server config")
                    success = False
            
            # Restore via registry if it was set to 1
            if state_data.get('registry') and '0x1' in state_data.get('registry', ''):
                result = self.runner.run_reg_add(
                    r'HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters',
                    'SMB1', 'REG_DWORD', '1'
                )
                if not result.success:
                    success = False
            
            # Note: Re-enabling Windows Optional Feature requires restart
            # and is not done automatically
            if state_data.get('feature_state') == 'Enabled':
                self._log('warning', "SMB1 feature was enabled - manual re-enable may be required")
            
            return success
            
        except Exception as e:
            self._log('error', f"Failed to restore SMB1 state: {str(e)}")
            return False
    
    def audit(self) -> ControlResult:
        """Check if SMB1 protocol is disabled."""
        try:
            result = self.runner.run_powershell(
                'Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol | '
                'Select-Object -ExpandProperty State'
            )
            
            if not result.success:
                # Try alternate method for server
                result = self.runner.run_powershell(
                    'Get-SmbServerConfiguration | Select-Object -ExpandProperty EnableSMB1Protocol'
                )
                
                if 'False' in result.stdout:
                    return ControlResult(
                        control_id=self.control_id,
                        name=self.name,
                        category=self.category,
                        status=ControlStatus.COMPLIANT,
                        risk_level=self.risk_level,
                        evidence="SMB1 Protocol is disabled (Server config)",
                        command_output=result.stdout
                    )
                elif 'True' in result.stdout:
                    return ControlResult(
                        control_id=self.control_id,
                        name=self.name,
                        category=self.category,
                        status=ControlStatus.NON_COMPLIANT,
                        risk_level=self.risk_level,
                        evidence="SMB1 Protocol is enabled",
                        command_output=result.stdout
                    )
            
            output = result.stdout.strip()
            
            if 'Disabled' in output or 'DisabledWithPayloadRemoved' in output:
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.COMPLIANT,
                    risk_level=self.risk_level,
                    evidence=f"SMB1 Protocol State: {output}",
                    command_output=output
                )
            elif 'Enabled' in output:
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.NON_COMPLIANT,
                    risk_level=self.risk_level,
                    evidence=f"SMB1 Protocol State: {output}",
                    details="SMB1 is a legacy protocol with known vulnerabilities",
                    command_output=output
                )
            else:
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.NOT_APPLICABLE,
                    risk_level=self.risk_level,
                    evidence="Unable to determine SMB1 state",
                    command_output=output
                )
                
        except Exception as e:
            return ControlResult(
                control_id=self.control_id,
                name=self.name,
                category=self.category,
                status=ControlStatus.ERROR,
                risk_level=self.risk_level,
                evidence="Error checking SMB1 status",
                error_message=str(e)
            )
    
    def remediate(self) -> bool:
        """Disable SMB1 protocol."""
        try:
            # Try Windows Feature method first
            result = self.runner.run_powershell(
                'Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart'
            )
            
            if result.success:
                self._log('info', "SMB1 disabled via Windows Optional Feature")
                return True
            
            # Fallback to SMB Server Configuration
            result = self.runner.run_powershell(
                'Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force'
            )
            
            if result.success:
                self._log('info', "SMB1 disabled via SMB Server Configuration")
                return True
            
            # Registry fallback
            reg_result = self.runner.run_reg_add(
                r'HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters',
                'SMB1', 'REG_DWORD', '0'
            )
            
            if reg_result.success:
                self._log('info', "SMB1 disabled via registry")
                return True
            
            return False
            
        except Exception as e:
            self._log('error', f"SMB1 remediation error: {str(e)}")
            return False
    
    def verify(self) -> ControlResult:
        """Verify SMB1 is now disabled."""
        return self.audit()


class AdminSharesControl(SecurityControl):
    """
    CONF-03: Administrative Shares Disabled
    Ensures default administrative shares (C$, ADMIN$) are removed or disabled.
    """
    
    def __init__(self):
        super().__init__(
            control_id="CONF-03",
            name="Administrative Shares Disabled",
            description="Verify default administrative shares are disabled",
            category=CIACategory.CONFIDENTIALITY,
            risk_level=RiskLevel.MEDIUM,
            cis_reference="CIS 18.5.1",
            nist_reference="AC-3"
        )
        self._supports_rollback = True
    
    def _capture_current_state(self) -> Optional[Dict[str, Any]]:
        """Capture current admin share configuration."""
        try:
            # Get current shares
            result = self.runner.run_cmd('net share')
            shares_output = result.stdout if result.success else ""
            
            # Get registry settings
            reg_wks = self.runner.run_reg_query(
                r'HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters',
                'AutoShareWks'
            )
            
            reg_srv = self.runner.run_reg_query(
                r'HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters',
                'AutoShareServer'
            )
            
            return {
                'shares_present': shares_output,
                'auto_share_wks': reg_wks.stdout if reg_wks.success else None,
                'auto_share_srv': reg_srv.stdout if reg_srv.success else None
            }
        except Exception as e:
            self._log('warning', f"Failed to capture admin shares state: {str(e)}")
            return None
    
    def _restore_state(self, state_data: Dict[str, Any]) -> bool:
        """Restore admin shares to previous state."""
        try:
            success = True
            
            # Restore AutoShareWks registry if it existed (or was default 1)
            auto_share_wks = state_data.get('auto_share_wks')
            if auto_share_wks is None or '0x1' in str(auto_share_wks):
                result = self.runner.run_reg_add(
                    r'HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters',
                    'AutoShareWks', 'REG_DWORD', '1'
                )
                if not result.success:
                    success = False
            
            auto_share_srv = state_data.get('auto_share_srv')
            if auto_share_srv is None or '0x1' in str(auto_share_srv):
                result = self.runner.run_reg_add(
                    r'HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters',
                    'AutoShareServer', 'REG_DWORD', '1'
                )
                if not result.success:
                    success = False
            
            # Note: Shares themselves will be recreated on next service restart
            self._log('info', "Admin share registry restored - shares will be recreated on restart")
            
            return success
            
        except Exception as e:
            self._log('error', f"Failed to restore admin shares state: {str(e)}")
            return False
    
    def audit(self) -> ControlResult:
        """Check if administrative shares exist."""
        try:
            result = self.runner.run_cmd('net share')
            
            if not result.success:
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.ERROR,
                    risk_level=self.risk_level,
                    evidence="Failed to enumerate shares",
                    error_message=result.stderr
                )
            
            output = result.stdout
            admin_shares = []
            
            # Check for common admin shares
            if 'C$' in output:
                admin_shares.append('C$')
            if 'ADMIN$' in output:
                admin_shares.append('ADMIN$')
            if 'D$' in output:
                admin_shares.append('D$')
            
            if not admin_shares:
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.COMPLIANT,
                    risk_level=self.risk_level,
                    evidence="No administrative shares found",
                    command_output=output
                )
            else:
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.NON_COMPLIANT,
                    risk_level=self.risk_level,
                    evidence=f"Administrative shares found: {', '.join(admin_shares)}",
                    details="These shares can be exploited for lateral movement",
                    command_output=output
                )
                
        except Exception as e:
            return ControlResult(
                control_id=self.control_id,
                name=self.name,
                category=self.category,
                status=ControlStatus.ERROR,
                risk_level=self.risk_level,
                evidence="Error checking administrative shares",
                error_message=str(e)
            )
    
    def remediate(self) -> bool:
        """Disable administrative shares."""
        try:
            success = True
            
            # Delete admin shares
            for share in ['C$', 'D$', 'ADMIN$']:
                result = self.runner.run_cmd(f'net share {share} /delete /y')
                if not result.success and 'does not exist' not in result.stderr:
                    self._log('warning', f"Failed to delete {share}: {result.stderr}")
            
            # Disable automatic recreation via registry
            reg_result = self.runner.run_reg_add(
                r'HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters',
                'AutoShareWks', 'REG_DWORD', '0'
            )
            
            if not reg_result.success:
                self._log('warning', "Failed to set AutoShareWks registry")
                success = False
            
            # Also set for server workstations
            reg_result = self.runner.run_reg_add(
                r'HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters',
                'AutoShareServer', 'REG_DWORD', '0'
            )
            
            return success
            
        except Exception as e:
            self._log('error', f"Admin shares remediation error: {str(e)}")
            return False
    
    def verify(self) -> ControlResult:
        """Verify administrative shares are removed."""
        return self.audit()


class SMBSigningControl(SecurityControl):
    """
    CONF-04: SMB Signing Required
    Ensures SMB signing is required for all connections.
    """
    
    def __init__(self):
        super().__init__(
            control_id="CONF-04",
            name="SMB Signing Required",
            description="Verify SMB signing is required to prevent man-in-the-middle attacks",
            category=CIACategory.CONFIDENTIALITY,
            risk_level=RiskLevel.HIGH,
            cis_reference="CIS 2.3.8.1",
            nist_reference="SC-8"
        )
        self._supports_rollback = True
    
    def _capture_current_state(self) -> Optional[Dict[str, Any]]:
        """Capture current SMB signing configuration."""
        try:
            # Get server RequireSecuritySignature
            server_req = self.runner.run_reg_query(
                r'HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters',
                'RequireSecuritySignature'
            )
            
            # Get server EnableSecuritySignature
            server_en = self.runner.run_reg_query(
                r'HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters',
                'EnableSecuritySignature'
            )
            
            # Get client RequireSecuritySignature
            client_req = self.runner.run_reg_query(
                r'HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters',
                'RequireSecuritySignature'
            )
            
            return {
                'server_require': server_req.stdout if server_req.success else None,
                'server_enable': server_en.stdout if server_en.success else None,
                'client_require': client_req.stdout if client_req.success else None
            }
        except Exception as e:
            self._log('warning', f"Failed to capture SMB signing state: {str(e)}")
            return None
    
    def _restore_state(self, state_data: Dict[str, Any]) -> bool:
        """Restore SMB signing to previous state."""
        try:
            success = True
            
            # Restore server RequireSecuritySignature
            server_req = state_data.get('server_require')
            if server_req and '0x0' in server_req:
                result = self.runner.run_reg_add(
                    r'HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters',
                    'RequireSecuritySignature', 'REG_DWORD', '0'
                )
                if not result.success:
                    success = False
            elif server_req is None:
                # Delete the key if it didn't exist
                self.runner.run_cmd(
                    'reg delete "HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters" '
                    '/v RequireSecuritySignature /f'
                )
            
            # Restore client RequireSecuritySignature
            client_req = state_data.get('client_require')
            if client_req and '0x0' in client_req:
                result = self.runner.run_reg_add(
                    r'HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters',
                    'RequireSecuritySignature', 'REG_DWORD', '0'
                )
                if not result.success:
                    success = False
            elif client_req is None:
                self.runner.run_cmd(
                    'reg delete "HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters" '
                    '/v RequireSecuritySignature /f'
                )
            
            return success
            
        except Exception as e:
            self._log('error', f"Failed to restore SMB signing state: {str(e)}")
            return False
    
    def audit(self) -> ControlResult:
        """Check if SMB signing is required."""
        try:
            result = self.runner.run_reg_query(
                r'HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters',
                'RequireSecuritySignature'
            )
            
            if not result.success:
                # Key might not exist
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.NON_COMPLIANT,
                    risk_level=self.risk_level,
                    evidence="RequireSecuritySignature registry value not set",
                    details="SMB signing is not required",
                    command_output=result.stderr
                )
            
            output = result.stdout
            
            # Parse the registry output for the value
            if 'RequireSecuritySignature' in output:
                # Look for value - format: "RequireSecuritySignature    REG_DWORD    0x1"
                if '0x1' in output or 'REG_DWORD    1' in output:
                    return ControlResult(
                        control_id=self.control_id,
                        name=self.name,
                        category=self.category,
                        status=ControlStatus.COMPLIANT,
                        risk_level=self.risk_level,
                        evidence="RequireSecuritySignature=1",
                        details="SMB signing is required",
                        command_output=output
                    )
                else:
                    return ControlResult(
                        control_id=self.control_id,
                        name=self.name,
                        category=self.category,
                        status=ControlStatus.NON_COMPLIANT,
                        risk_level=self.risk_level,
                        evidence="RequireSecuritySignature=0",
                        details="SMB signing is not required",
                        command_output=output
                    )
            else:
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.NON_COMPLIANT,
                    risk_level=self.risk_level,
                    evidence="RequireSecuritySignature not configured",
                    command_output=output
                )
                
        except Exception as e:
            return ControlResult(
                control_id=self.control_id,
                name=self.name,
                category=self.category,
                status=ControlStatus.ERROR,
                risk_level=self.risk_level,
                evidence="Error checking SMB signing",
                error_message=str(e)
            )
    
    def remediate(self) -> bool:
        """Enable required SMB signing."""
        try:
            # Enable for server
            result = self.runner.run_reg_add(
                r'HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters',
                'RequireSecuritySignature', 'REG_DWORD', '1'
            )
            
            if not result.success:
                self._log('error', f"Failed to set server SMB signing: {result.stderr}")
                return False
            
            # Enable for client
            result = self.runner.run_reg_add(
                r'HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters',
                'RequireSecuritySignature', 'REG_DWORD', '1'
            )
            
            if not result.success:
                self._log('warning', f"Failed to set client SMB signing: {result.stderr}")
            
            # Also enable signing (not just require)
            self.runner.run_reg_add(
                r'HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters',
                'EnableSecuritySignature', 'REG_DWORD', '1'
            )
            
            return True
            
        except Exception as e:
            self._log('error', f"SMB signing remediation error: {str(e)}")
            return False
    
    def verify(self) -> ControlResult:
        """Verify SMB signing is now required."""
        return self.audit()


class GuestAccountControl(SecurityControl):
    """
    CONF-05: Guest Account Disabled
    Ensures the built-in Guest account is disabled.
    """
    
    def __init__(self):
        super().__init__(
            control_id="CONF-05",
            name="Guest Account Disabled",
            description="Verify built-in Guest account is disabled",
            category=CIACategory.CONFIDENTIALITY,
            risk_level=RiskLevel.HIGH,
            cis_reference="CIS 1.1.2",
            nist_reference="AC-6"
        )
        self._supports_rollback = True
    
    def _capture_current_state(self) -> Optional[Dict[str, Any]]:
        try:
            result = self.runner.run_powershell(
                '(Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue).Enabled'
            )
            return {'guest_enabled': result.stdout.strip() if result.success else None}
        except Exception:
            return None
    
    def _restore_state(self, state_data: Dict[str, Any]) -> bool:
        try:
            was_enabled = state_data.get('guest_enabled', '').lower() == 'true'
            if was_enabled:
                self.runner.run_powershell('Enable-LocalUser -Name "Guest"')
            return True
        except Exception:
            return False
    
    def audit(self) -> ControlResult:
        try:
            result = self.runner.run_powershell(
                '(Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue).Enabled'
            )
            
            if not result.success:
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.ERROR,
                    risk_level=self.risk_level,
                    evidence="Failed to query Guest account status",
                    error_message=result.stderr
                )
            
            output = result.stdout.strip().lower()
            
            if output == 'false' or output == '':
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.COMPLIANT,
                    risk_level=self.risk_level,
                    evidence="Guest account is DISABLED",
                    command_output=result.stdout
                )
            else:
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.NON_COMPLIANT,
                    risk_level=self.risk_level,
                    evidence="Guest account is ENABLED",
                    details="Guest account allows anonymous access",
                    command_output=result.stdout
                )
                
        except Exception as e:
            return ControlResult(
                control_id=self.control_id,
                name=self.name,
                category=self.category,
                status=ControlStatus.ERROR,
                risk_level=self.risk_level,
                evidence="Error checking Guest account",
                error_message=str(e)
            )
    
    def remediate(self) -> bool:
        try:
            result = self.runner.run_powershell('Disable-LocalUser -Name "Guest"')
            if result.success:
                self._log('info', "Guest account disabled")
                return True
            else:
                self._log('error', f"Failed to disable Guest: {result.stderr}")
                return False
        except Exception as e:
            self._log('error', f"Guest account remediation error: {str(e)}")
            return False
    
    def verify(self) -> ControlResult:
        return self.audit()


class RDPNLAControl(RegistryControl):
    """
    CONF-06: RDP Network Level Authentication
    Ensures Network Level Authentication is required for RDP connections.
    """
    
    registry_path = r'HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
    registry_value = 'UserAuthentication'
    expected_data = 1
    value_type = 'REG_DWORD'
    
    def __init__(self):
        super().__init__(
            control_id="CONF-06",
            name="RDP Network Level Authentication",
            description="Verify NLA is required for Remote Desktop connections",
            category=CIACategory.CONFIDENTIALITY,
            risk_level=RiskLevel.HIGH,
            cis_reference="CIS 18.9.65.3.9.1",
            nist_reference="IA-2"
        )


class RemoteRegistryControl(ServiceControl):
    """
    CONF-07: Remote Registry Disabled
    Ensures the Remote Registry service is stopped and disabled.
    """
    
    service_name = 'RemoteRegistry'
    compliant_state = 'Stopped'
    compliant_startup = 'disabled'
    
    def __init__(self):
        super().__init__(
            control_id="CONF-07",
            name="Remote Registry Disabled",
            description="Verify Remote Registry service is stopped and disabled",
            category=CIACategory.CONFIDENTIALITY,
            risk_level=RiskLevel.MEDIUM,
            cis_reference="CIS 5.27",
            nist_reference="CM-7"
        )


class AutoPlayControl(RegistryControl):
    """
    CONF-08: AutoPlay Disabled
    Ensures AutoPlay is disabled for all drive types.
    """
    
    registry_path = r'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
    registry_value = 'NoDriveTypeAutoRun'
    expected_data = 255
    value_type = 'REG_DWORD'
    
    def __init__(self):
        super().__init__(
            control_id="CONF-08",
            name="AutoPlay Disabled",
            description="Verify AutoPlay is disabled for all drive types",
            category=CIACategory.CONFIDENTIALITY,
            risk_level=RiskLevel.MEDIUM,
            cis_reference="CIS 18.9.8.3",
            nist_reference="CM-7"
        )


class AnonymousEnumerationControl(RegistryControl):
    """
    CONF-09: Anonymous Enumeration Disabled
    Ensures anonymous enumeration of SAM accounts and shares is restricted.
    """
    
    registry_path = r'HKLM\SYSTEM\CurrentControlSet\Control\Lsa'
    registry_value = 'RestrictAnonymous'
    expected_data = 1
    value_type = 'REG_DWORD'
    comparison = 'greater_equal'
    
    def __init__(self):
        super().__init__(
            control_id="CONF-09",
            name="Anonymous Enumeration Disabled",
            description="Verify anonymous enumeration of SAM accounts is restricted",
            category=CIACategory.CONFIDENTIALITY,
            risk_level=RiskLevel.HIGH,
            cis_reference="CIS 2.3.10.5",
            nist_reference="AC-3"
        )


class NTLMRestrictionControl(RegistryControl):
    """
    CONF-10: NTLM Restriction
    Ensures LAN Manager authentication level is set to send NTLMv2 only.
    """
    
    registry_path = r'HKLM\SYSTEM\CurrentControlSet\Control\Lsa'
    registry_value = 'LMCompatibilityLevel'
    expected_data = 3
    value_type = 'REG_DWORD'
    comparison = 'greater_equal'
    
    def __init__(self):
        super().__init__(
            control_id="CONF-10",
            name="NTLM Restriction",
            description="Verify LAN Manager authentication is set to NTLMv2 only (level >= 3)",
            category=CIACategory.CONFIDENTIALITY,
            risk_level=RiskLevel.HIGH,
            cis_reference="CIS 2.3.11.7",
            nist_reference="IA-5"
        )


class WDigestControl(RegistryControl):
    """
    CONF-11: WDigest Disabled
    Ensures WDigest authentication is disabled to prevent cleartext credential storage.
    """
    
    registry_path = r'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest'
    registry_value = 'UseLogonCredential'
    expected_data = 0
    value_type = 'REG_DWORD'
    
    def __init__(self):
        super().__init__(
            control_id="CONF-11",
            name="WDigest Disabled",
            description="Verify WDigest authentication is disabled (prevents cleartext passwords in memory)",
            category=CIACategory.CONFIDENTIALITY,
            risk_level=RiskLevel.CRITICAL,
            cis_reference="CIS 18.3.6",
            nist_reference="IA-5"
        )


class CachedCredentialsControl(RegistryControl):
    """
    CONF-12: Cached Credentials Limited
    Ensures the number of cached logon credentials is limited.
    """
    
    registry_path = r'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    registry_value = 'CachedLogonsCount'
    expected_data = 2
    value_type = 'REG_SZ'
    comparison = 'less_equal'
    
    def __init__(self):
        super().__init__(
            control_id="CONF-12",
            name="Cached Credentials Limited",
            description="Verify cached logon credentials are limited to 2 or fewer",
            category=CIACategory.CONFIDENTIALITY,
            risk_level=RiskLevel.MEDIUM,
            cis_reference="CIS 2.3.6.5",
            nist_reference="IA-5"
        )
    
    def _compare_values(self, current, expected):
        """Override to handle string to int comparison."""
        try:
            current_int = int(current) if current else 999
            return current_int <= expected
        except (ValueError, TypeError):
            return False


class LMHashControl(RegistryControl):
    """
    CONF-13: LAN Manager Hash Disabled
    Ensures LAN Manager hash is not stored on next password change.
    """
    
    registry_path = r'HKLM\SYSTEM\CurrentControlSet\Control\Lsa'
    registry_value = 'NoLMHash'
    expected_data = 1
    value_type = 'REG_DWORD'
    
    def __init__(self):
        super().__init__(
            control_id="CONF-13",
            name="LAN Manager Hash Disabled",
            description="Verify LM hash is not stored (weak hash algorithm)",
            category=CIACategory.CONFIDENTIALITY,
            risk_level=RiskLevel.HIGH,
            cis_reference="CIS 2.3.11.5",
            nist_reference="IA-5"
        )


class AnonymousSAMControl(RegistryControl):
    """
    CONF-14: Anonymous SAM Access Disabled
    Ensures anonymous access to SAM database is restricted.
    """
    
    registry_path = r'HKLM\SYSTEM\CurrentControlSet\Control\Lsa'
    registry_value = 'RestrictAnonymousSAM'
    expected_data = 1
    value_type = 'REG_DWORD'
    
    def __init__(self):
        super().__init__(
            control_id="CONF-14",
            name="Anonymous SAM Access Disabled",
            description="Verify anonymous access to SAM database is restricted",
            category=CIACategory.CONFIDENTIALITY,
            risk_level=RiskLevel.HIGH,
            cis_reference="CIS 2.3.10.2",
            nist_reference="AC-3"
        )


class NullSessionPipesControl(SecurityControl):
    """
    CONF-15: Null Session Pipes Empty
    Ensures no named pipes are accessible anonymously.
    """
    
    def __init__(self):
        super().__init__(
            control_id="CONF-15",
            name="Null Session Pipes Empty",
            description="Verify no named pipes allow null session access",
            category=CIACategory.CONFIDENTIALITY,
            risk_level=RiskLevel.MEDIUM,
            cis_reference="CIS 2.3.10.7",
            nist_reference="AC-3"
        )
        self._supports_rollback = True
    
    def _capture_current_state(self) -> Optional[Dict[str, Any]]:
        try:
            result = self.runner.run_reg_query(
                r'HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters',
                'NullSessionPipes'
            )
            return {'null_pipes': result.stdout if result.success else None}
        except Exception:
            return None
    
    def _restore_state(self, state_data: Dict[str, Any]) -> bool:
        # Restoring null session pipes is complex, skip for safety
        return False
    
    def audit(self) -> ControlResult:
        try:
            result = self.runner.run_reg_query(
                r'HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters',
                'NullSessionPipes'
            )
            
            if not result.success:
                # Key might not exist, which is good
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.COMPLIANT,
                    risk_level=self.risk_level,
                    evidence="NullSessionPipes not configured (default secure)",
                    command_output=result.stderr
                )
            
            output = result.stdout.strip()
            
            # Check if the value is empty or contains only whitespace
            # Multi-string values show as multiple lines
            lines = [l.strip() for l in output.split('\n') if l.strip() and 'NullSessionPipes' not in l and 'REG_MULTI_SZ' not in l]
            
            if not lines:
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.COMPLIANT,
                    risk_level=self.risk_level,
                    evidence="NullSessionPipes is empty",
                    command_output=output
                )
            else:
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.NON_COMPLIANT,
                    risk_level=self.risk_level,
                    evidence=f"NullSessionPipes contains: {', '.join(lines)}",
                    details="Named pipes accessible anonymously",
                    command_output=output
                )
                
        except Exception as e:
            return ControlResult(
                control_id=self.control_id,
                name=self.name,
                category=self.category,
                status=ControlStatus.ERROR,
                risk_level=self.risk_level,
                evidence="Error checking NullSessionPipes",
                error_message=str(e)
            )
    
    def remediate(self) -> bool:
        try:
            # Set to empty multi-string value
            result = self.runner.run_cmd(
                'reg add "HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters" '
                '/v NullSessionPipes /t REG_MULTI_SZ /d "" /f'
            )
            if result.success:
                self._log('info', "NullSessionPipes cleared")
                return True
            return False
        except Exception as e:
            self._log('error', f"NullSessionPipes remediation error: {str(e)}")
            return False
    
    def verify(self) -> ControlResult:
        return self.audit()


class PrinterDriverControl(RegistryControl):
    """
    CONF-16: Printer Driver Installation Restricted
    Ensures only administrators can install printer drivers.
    """
    
    registry_path = r'HKLM\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers'
    registry_value = 'AddPrinterDrivers'
    expected_data = 1
    value_type = 'REG_DWORD'
    
    def __init__(self):
        super().__init__(
            control_id="CONF-16",
            name="Printer Driver Installation Restricted",
            description="Verify only administrators can install printer drivers",
            category=CIACategory.CONFIDENTIALITY,
            risk_level=RiskLevel.MEDIUM,
            cis_reference="CIS 2.3.4.1",
            nist_reference="CM-7"
        )


class AlwaysInstallElevatedControl(SecurityControl):
    """
    CONF-17: Always Install Elevated Disabled
    Ensures Windows Installer does not always install with elevated privileges.
    """
    
    def __init__(self):
        super().__init__(
            control_id="CONF-17",
            name="Always Install Elevated Disabled",
            description="Verify Windows Installer doesn't always use elevated privileges",
            category=CIACategory.CONFIDENTIALITY,
            risk_level=RiskLevel.HIGH,
            cis_reference="CIS 18.9.85.1",
            nist_reference="AC-6"
        )
        self._supports_rollback = True
    
    def _capture_current_state(self) -> Optional[Dict[str, Any]]:
        try:
            machine = self.runner.run_reg_query(
                r'HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer',
                'AlwaysInstallElevated'
            )
            user = self.runner.run_reg_query(
                r'HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer',
                'AlwaysInstallElevated'
            )
            return {
                'machine': machine.stdout if machine.success else None,
                'user': user.stdout if user.success else None
            }
        except Exception:
            return None
    
    def _restore_state(self, state_data: Dict[str, Any]) -> bool:
        # Don't restore this - security risk
        return False
    
    def audit(self) -> ControlResult:
        try:
            # Check both HKLM and HKCU
            machine_result = self.runner.run_reg_query(
                r'HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer',
                'AlwaysInstallElevated'
            )
            
            user_result = self.runner.run_reg_query(
                r'HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer',
                'AlwaysInstallElevated'
            )
            
            machine_enabled = machine_result.success and '0x1' in machine_result.stdout
            user_enabled = user_result.success and '0x1' in user_result.stdout
            
            if machine_enabled and user_enabled:
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.NON_COMPLIANT,
                    risk_level=self.risk_level,
                    evidence="AlwaysInstallElevated is ENABLED (both HKLM and HKCU)",
                    details="Critical privilege escalation vulnerability",
                    command_output=f"HKLM: {machine_result.stdout}\nHKCU: {user_result.stdout}"
                )
            elif machine_enabled or user_enabled:
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.NON_COMPLIANT,
                    risk_level=self.risk_level,
                    evidence=f"AlwaysInstallElevated partially enabled (HKLM: {machine_enabled}, HKCU: {user_enabled})",
                    details="Potential privilege escalation risk",
                    command_output=f"HKLM: {machine_result.stdout}\nHKCU: {user_result.stdout}"
                )
            else:
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.COMPLIANT,
                    risk_level=self.risk_level,
                    evidence="AlwaysInstallElevated is DISABLED or not configured",
                    command_output="Not enabled in HKLM or HKCU"
                )
                
        except Exception as e:
            return ControlResult(
                control_id=self.control_id,
                name=self.name,
                category=self.category,
                status=ControlStatus.ERROR,
                risk_level=self.risk_level,
                evidence="Error checking AlwaysInstallElevated",
                error_message=str(e)
            )
    
    def remediate(self) -> bool:
        try:
            success = True
            
            # Disable in HKLM
            result = self.runner.run_reg_add(
                r'HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer',
                'AlwaysInstallElevated', 'REG_DWORD', '0'
            )
            if not result.success:
                success = False
            
            # Disable in HKCU
            result = self.runner.run_reg_add(
                r'HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer',
                'AlwaysInstallElevated', 'REG_DWORD', '0'
            )
            if not result.success:
                success = False
            
            if success:
                self._log('info', "AlwaysInstallElevated disabled")
            return success
            
        except Exception as e:
            self._log('error', f"AlwaysInstallElevated remediation error: {str(e)}")
            return False
    
    def verify(self) -> ControlResult:
        return self.audit()


class TelemetryControl(RegistryControl):
    """
    CONF-18: Telemetry Level Restricted
    Ensures Windows telemetry is set to Security (0) or Basic (1).
    """
    
    registry_path = r'HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection'
    registry_value = 'AllowTelemetry'
    expected_data = 1
    value_type = 'REG_DWORD'
    comparison = 'less_equal'
    
    def __init__(self):
        super().__init__(
            control_id="CONF-18",
            name="Telemetry Level Restricted",
            description="Verify Windows telemetry is set to Security (0) or Basic (1)",
            category=CIACategory.CONFIDENTIALITY,
            risk_level=RiskLevel.MEDIUM,
            cis_reference="CIS 18.9.16.3",
            nist_reference="AC-4"
        )


class WindowsHelloControl(SecurityControl):
    """
    CONF-19: Windows Hello for Business
    Verifies passwordless authentication is configured
    to prevent credential theft attacks (Pass-the-Hash, Mimikatz).
    
    Note: Requires TPM 2.0 for full Windows Hello for Business functionality.
    """
    
    def __init__(self):
        super().__init__(
            control_id="CONF-19",
            name="Windows Hello for Business",
            description="Verify Windows Hello passwordless authentication is enabled",
            category=CIACategory.CONFIDENTIALITY,
            risk_level=RiskLevel.HIGH,
            cis_reference="CIS 18.9.28.3",
            nist_reference="IA-2(12)"
        )
        self._supports_rollback = True
    
    def _capture_current_state(self) -> Optional[Dict[str, Any]]:
        """Capture current Windows Hello configuration."""
        try:
            result = self.runner.run_reg_query(
                r'HKLM\SOFTWARE\Policies\Microsoft\PassportForWork',
                'Enabled'
            )
            return {'hello_enabled': result.stdout if result.success else None}
        except Exception:
            return None
    
    def _restore_state(self, state_data: Dict[str, Any]) -> bool:
        """Restore Windows Hello configuration."""
        return False  # Let user manage Hello state
    
    def audit(self) -> ControlResult:
        """Check Windows Hello for Business configuration."""
        try:
            # Check TPM availability first
            tpm_check = self.runner.run_powershell(
                'try { '
                '$tpm = Get-Tpm -ErrorAction Stop; '
                'Write-Output "TPM_PRESENT=$($tpm.TpmPresent)"; '
                'Write-Output "TPM_READY=$($tpm.TpmReady)"; '
                'Write-Output "TPM_ENABLED=$($tpm.TpmEnabled)" '
                '} catch { Write-Output "TPM_ERROR: $_" }'
            )
            
            tpm_present = False
            tpm_ready = False
            if tpm_check.success and tpm_check.stdout:
                output = tpm_check.stdout
                tpm_present = 'TPM_PRESENT=True' in output
                tpm_ready = 'TPM_READY=True' in output
            
            # Check Windows Hello policy settings
            hello_policy = self.runner.run_reg_query(
                r'HKLM\SOFTWARE\Policies\Microsoft\PassportForWork',
                'Enabled'
            )
            
            # Check if Hello is enabled via policy
            hello_enabled_policy = False
            if hello_policy.success and '0x1' in hello_policy.stdout:
                hello_enabled_policy = True
            
            # Check if user has enrolled a Windows Hello credential
            hello_enrolled = self.runner.run_powershell(
                '$ngcPath = "$env:SystemDrive\\Windows\\ServiceProfiles\\LocalService\\AppData\\Local\\Microsoft\\Ngc"; '
                'if (Test-Path $ngcPath) { '
                '$items = Get-ChildItem $ngcPath -Recurse -ErrorAction SilentlyContinue; '
                'if ($items.Count -gt 0) { Write-Output "HELLO_ENROLLED" } '
                'else { Write-Output "HELLO_NOT_ENROLLED" } '
                '} else { Write-Output "HELLO_NOT_ENROLLED" }'
            )
            
            has_enrollment = hello_enrolled.success and 'HELLO_ENROLLED' in hello_enrolled.stdout
            
            # Check biometric hardware availability
            biometric_check = self.runner.run_powershell(
                'Get-WmiObject -Namespace root\\CIMV2 -Class Win32_PnPEntity | '
                'Where-Object { $_.Name -match "fingerprint|biometric|camera|face" } | '
                'Select-Object -First 1 | ForEach-Object { Write-Output "BIOMETRIC_FOUND" }'
            )
            
            has_biometric = biometric_check.success and 'BIOMETRIC_FOUND' in biometric_check.stdout
            
            # Determine compliance status
            if not tpm_present:
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.NOT_APPLICABLE,
                    risk_level=self.risk_level,
                    evidence="TPM not available - Windows Hello for Business requires TPM 2.0",
                    details="Windows Hello for Business requires a Trusted Platform Module (TPM) 2.0 "
                            "for secure credential storage. Standalone Windows Hello (PIN/biometric) "
                            "can work without TPM but offers less security. Consider hardware upgrade "
                            "for enterprise passwordless authentication.",
                    command_output=tpm_check.stdout[:300] if tpm_check.stdout else None
                )
            
            if hello_enabled_policy and has_enrollment:
                auth_methods = []
                if tpm_ready:
                    auth_methods.append("TPM")
                if has_biometric:
                    auth_methods.append("Biometric")
                auth_methods.append("PIN")
                
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.COMPLIANT,
                    risk_level=self.risk_level,
                    evidence=f"Windows Hello configured with {'/'.join(auth_methods)}",
                    details="Windows Hello for Business is enabled and user has enrolled credentials. "
                            "Passwordless authentication protects against credential theft attacks "
                            "(Pass-the-Hash, Mimikatz, phishing).",
                    command_output=f"Policy: Enabled, Enrolled: Yes, TPM: {tpm_ready}, Biometric: {has_biometric}"
                )
            
            if hello_enabled_policy and not has_enrollment:
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.NON_COMPLIANT,
                    risk_level=self.risk_level,
                    evidence="Windows Hello enabled but no credential enrolled",
                    details="Windows Hello for Business is enabled via policy but no user has "
                            "enrolled a Windows Hello credential (PIN/biometric). Users should "
                            "enroll via Settings > Accounts > Sign-in options.",
                    command_output=f"Policy: Enabled, Enrolled: No, TPM: {tpm_ready}"
                )
            
            return ControlResult(
                control_id=self.control_id,
                name=self.name,
                category=self.category,
                status=ControlStatus.NON_COMPLIANT,
                risk_level=self.risk_level,
                evidence="Windows Hello for Business not enabled",
                details="Windows Hello for Business is not configured. Users authenticate with "
                        "passwords which are vulnerable to theft (Pass-the-Hash, Mimikatz, phishing). "
                        "Enable via Group Policy: Computer Configuration > Administrative Templates > "
                        "Windows Components > Windows Hello for Business.",
                command_output=f"Policy: Not Enabled, TPM: {tpm_present}"
            )
                
        except Exception as e:
            return ControlResult(
                control_id=self.control_id,
                name=self.name,
                category=self.category,
                status=ControlStatus.ERROR,
                risk_level=self.risk_level,
                evidence="Error checking Windows Hello status",
                error_message=str(e)
            )
    
    def remediate(self) -> bool:
        """Enable Windows Hello for Business via policy."""
        try:
            # Create PassportForWork key if not exists
            self.runner.run_cmd(
                'reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\PassportForWork" /f'
            )
            
            # Enable Windows Hello for Business
            result1 = self.runner.run_reg_add(
                r'HKLM\SOFTWARE\Policies\Microsoft\PassportForWork',
                'Enabled',
                'REG_DWORD',
                '1'
            )
            
            # Require TPM
            result2 = self.runner.run_reg_add(
                r'HKLM\SOFTWARE\Policies\Microsoft\PassportForWork',
                'RequireSecurityDevice',
                'REG_DWORD',
                '1'
            )
            
            if result1.success:
                self._log('info', "Windows Hello for Business enabled via policy. "
                         "Users must enroll credentials at next sign-in.")
            
            return result1.success
        except Exception:
            return False
    
    def verify(self) -> ControlResult:
        """Verify Windows Hello configuration after remediation."""
        return self.audit()


class WindowsLAPSControl(SecurityControl):
    """
    CONF-20: Windows LAPS (Local Administrator Password Solution)
    Verifies Windows LAPS is configured to automatically manage local admin
    passwords on domain-joined machines. Native Windows LAPS (Win11/Server 2019+).
    """
    
    def __init__(self):
        super().__init__(
            control_id="CONF-20",
            name="Windows LAPS",
            description="Verify Windows LAPS is configured for local admin password management",
            category=CIACategory.CONFIDENTIALITY,
            risk_level=RiskLevel.HIGH,
            cis_reference="CIS 18.2.1",
            nist_reference="IA-5(1)"
        )
        self._supports_rollback = False
    
    def audit(self) -> ControlResult:
        """Check Windows LAPS configuration."""
        try:
            # First check if domain-joined
            domain_check = "(Get-WmiObject Win32_ComputerSystem).PartOfDomain"
            domain_result = self.runner.run_powershell(domain_check)
            
            if domain_result.success and domain_result.stdout.strip().lower() != "true":
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.NOT_APPLICABLE,
                    risk_level=self.risk_level,
                    evidence="System is not domain-joined - Windows LAPS requires Active Directory"
                )
            
            # Check Windows version (LAPS native requires Win11 21H2+ or Server 2019+)
            version_check = """
            $build = [System.Environment]::OSVersion.Version.Build
            $productType = (Get-WmiObject Win32_OperatingSystem).ProductType
            if ($productType -eq 1) {
                # Workstation - needs Win11 (build 22000+)
                if ($build -ge 22000) { "SUPPORTED" } else { "UNSUPPORTED" }
            } else {
                # Server - needs Server 2019+ (build 17763+)
                if ($build -ge 17763) { "SUPPORTED" } else { "UNSUPPORTED" }
            }
            """
            version_result = self.runner.run_powershell(version_check)
            
            if version_result.success and "UNSUPPORTED" in version_result.stdout:
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.NOT_APPLICABLE,
                    risk_level=self.risk_level,
                    evidence="Windows version does not support native Windows LAPS (requires Win11 or Server 2019+)"
                )
            
            # Check Windows LAPS configuration
            laps_check = """
            $lapsConfig = $null
            $backupDir = $null
            
            # Check LAPS policy registry
            $policyPath = 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\LAPS\\Config'
            if (Test-Path $policyPath) {
                $lapsConfig = Get-ItemProperty -Path $policyPath -ErrorAction SilentlyContinue
                $backupDir = $lapsConfig.BackupDirectory
            }
            
            # Also check GPO-delivered settings
            $gpoPath = 'HKLM:\\SOFTWARE\\Microsoft\\Policies\\LAPS'
            if (Test-Path $gpoPath) {
                $gpoConfig = Get-ItemProperty -Path $gpoPath -ErrorAction SilentlyContinue
                if ($gpoConfig.BackupDirectory) { $backupDir = $gpoConfig.BackupDirectory }
            }
            
            if ($backupDir) {
                # BackupDirectory: 0=Disabled, 1=AAD, 2=AD
                Write-Output "CONFIGURED:BackupDir=$backupDir"
            } else {
                Write-Output "NOT_CONFIGURED"
            }
            """
            laps_result = self.runner.run_powershell(laps_check)
            
            if laps_result.success and "CONFIGURED" in laps_result.stdout:
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.COMPLIANT,
                    risk_level=self.risk_level,
                    evidence="Windows LAPS is configured for automatic local admin password management",
                    command_output=laps_result.stdout
                )
            
            return ControlResult(
                control_id=self.control_id,
                name=self.name,
                category=self.category,
                status=ControlStatus.NON_COMPLIANT,
                risk_level=self.risk_level,
                evidence="Windows LAPS is not configured",
                details="Windows LAPS is not configured. Configure via Group Policy: Computer Configuration > "
                        "Administrative Templates > System > LAPS. Requires AD schema extension."
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
        """Windows LAPS requires AD infrastructure - cannot auto-remediate."""
        self.logger.warning(
            "Windows LAPS requires Active Directory configuration (schema extension, GPO). "
            "Cannot auto-remediate. See: https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview"
        )
        return False
    
    def verify(self) -> ControlResult:
        """Verify Windows LAPS configuration."""
        return self.audit()


class KerberosArmoringControl(SecurityControl):
    """
    CONF-21: Kerberos Armoring (Flexible Authentication Secure Tunneling)
    Verifies Kerberos FAST is configured to protect Kerberos pre-authentication
    exchanges from offline dictionary attacks.
    """
    
    def __init__(self):
        super().__init__(
            control_id="CONF-21",
            name="Kerberos Armoring (FAST)",
            description="Verify Kerberos FAST armoring is configured for enhanced authentication security",
            category=CIACategory.CONFIDENTIALITY,
            risk_level=RiskLevel.HIGH,
            cis_reference="CIS 18.3.5",
            nist_reference="IA-2(8)"
        )
        self._supports_rollback = False
    
    def audit(self) -> ControlResult:
        """Check Kerberos armoring configuration."""
        try:
            # First check if domain-joined
            domain_check = "(Get-WmiObject Win32_ComputerSystem).PartOfDomain"
            domain_result = self.runner.run_powershell(domain_check)
            
            if domain_result.success and domain_result.stdout.strip().lower() != "true":
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.NOT_APPLICABLE,
                    risk_level=self.risk_level,
                    evidence="System is not domain-joined - Kerberos FAST requires Active Directory"
                )
            
            # Check Kerberos supported encryption types (must include AES)
            enc_check = """
            $kerberosPath = 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Kerberos\\Parameters'
            $encTypes = $null
            
            if (Test-Path $kerberosPath) {
                $encTypes = (Get-ItemProperty -Path $kerberosPath -ErrorAction SilentlyContinue).SupportedEncryptionTypes
            }
            
            # Also check the standard Kerberos parameters
            $stdPath = 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\Kerberos\\Parameters'
            if (-not $encTypes -and (Test-Path $stdPath)) {
                $encTypes = (Get-ItemProperty -Path $stdPath -ErrorAction SilentlyContinue).SupportedEncryptionTypes
            }
            
            if ($encTypes) {
                # Check if AES is enabled (bit 16 = AES128, bit 8 = AES256)
                # Value >= 16 means AES128 or higher is supported
                if ($encTypes -ge 16) {
                    Write-Output "AES_ENABLED:$encTypes"
                } else {
                    Write-Output "AES_DISABLED:$encTypes"
                }
            } else {
                # Default Windows behavior supports AES
                Write-Output "DEFAULT_CONFIG"
            }
            """
            enc_result = self.runner.run_powershell(enc_check)
            
            # Check for FAST/claims support
            claims_check = """
            $claimsPath = 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\KDC\\Parameters'
            $enableClaims = $null
            
            if (Test-Path $claimsPath) {
                $enableClaims = (Get-ItemProperty -Path $claimsPath -ErrorAction SilentlyContinue).EnableCbacAndArmor
            }
            
            if ($enableClaims -eq 1) {
                Write-Output "FAST_ENABLED"
            } else {
                Write-Output "FAST_NOT_CONFIGURED"
            }
            """
            claims_result = self.runner.run_powershell(claims_check)
            
            aes_ok = enc_result.success and ("AES_ENABLED" in enc_result.stdout or "DEFAULT_CONFIG" in enc_result.stdout)
            fast_ok = claims_result.success and "FAST_ENABLED" in claims_result.stdout
            
            if aes_ok and fast_ok:
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.COMPLIANT,
                    risk_level=self.risk_level,
                    evidence="Kerberos FAST armoring is enabled with AES encryption",
                    command_output=f"Encryption: {enc_result.stdout.strip()}, FAST: {claims_result.stdout.strip()}"
                )
            elif aes_ok:
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.NON_COMPLIANT,
                    risk_level=self.risk_level,
                    evidence="AES encryption enabled but Kerberos FAST armoring not configured",
                    details="Enable Kerberos armoring via Group Policy: Computer Configuration > Administrative Templates > "
                            "System > KDC > KDC support for claims, compound authentication and Kerberos armoring"
                )
            else:
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.NON_COMPLIANT,
                    risk_level=self.risk_level,
                    evidence=f"Kerberos not properly configured. Encryption types: {enc_result.stdout.strip()}",
                    details="Configure Kerberos to use AES encryption and enable FAST armoring via Group Policy"
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
        """Kerberos armoring requires DC configuration - cannot auto-remediate."""
        self.logger.warning(
            "Kerberos FAST armoring requires Domain Controller configuration. "
            "Cannot auto-remediate. Configure via Group Policy on Domain Controllers."
        )
        return False
    
    def verify(self) -> ControlResult:
        """Verify Kerberos armoring configuration."""
        return self.audit()


class ConfidentialityControls(ControlGroup):
    """Collection of all Confidentiality controls."""
    
    def __init__(self):
        super().__init__(
            name="Confidentiality Controls",
            category=CIACategory.CONFIDENTIALITY,
            description="Controls ensuring data confidentiality and protection"
        )
        
        # Add all confidentiality controls (CONF-01 to CONF-19)
        self.add_control(BitLockerControl())           # CONF-01
        self.add_control(SMB1DisabledControl())        # CONF-02
        self.add_control(AdminSharesControl())         # CONF-03
        self.add_control(SMBSigningControl())          # CONF-04
        self.add_control(GuestAccountControl())        # CONF-05
        self.add_control(RDPNLAControl())              # CONF-06
        self.add_control(RemoteRegistryControl())      # CONF-07
        self.add_control(AutoPlayControl())            # CONF-08
        self.add_control(AnonymousEnumerationControl()) # CONF-09
        self.add_control(NTLMRestrictionControl())     # CONF-10
        self.add_control(WDigestControl())             # CONF-11
        self.add_control(CachedCredentialsControl())   # CONF-12
        self.add_control(LMHashControl())              # CONF-13
        self.add_control(AnonymousSAMControl())        # CONF-14
        self.add_control(NullSessionPipesControl())    # CONF-15
        self.add_control(PrinterDriverControl())       # CONF-16
        self.add_control(AlwaysInstallElevatedControl()) # CONF-17
        self.add_control(TelemetryControl())           # CONF-18
        # v2.2: New enterprise control
        self.add_control(WindowsHelloControl())        # CONF-19
        # v2.3: Additional enterprise controls (CONF-20 to CONF-21)
        self.add_control(WindowsLAPSControl())         # CONF-20
        self.add_control(KerberosArmoringControl())    # CONF-21
    
    def initialize(self, runner, logger):
        """Initialize all controls with dependencies."""
        for control in self.controls:
            control.set_dependencies(runner, logger)
