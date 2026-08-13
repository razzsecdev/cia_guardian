"""
Service Hardening Controls
SRVC-01: Print Spooler Disabled
SRVC-02: SSDP Discovery Disabled
SRVC-03: UPnP Host Disabled
SRVC-04: Remote Desktop Services Disabled
SRVC-05: Telnet Client Feature Disabled
SRVC-06: TFTP Client Feature Disabled
SRVC-07: Windows Media Player Network Sharing Disabled
SRVC-08: Xbox Services Disabled
SRVC-09: Fax Service Disabled
SRVC-10: Bluetooth Support Service Disabled
SRVC-11: RD Gateway Requirement (v2.3)
"""

from typing import Dict, Any, Optional
from .base import (
    SecurityControl, ControlResult, ControlStatus,
    RiskLevel, CIACategory, ControlGroup
)
from .service_base import ServiceControl


class PrintSpoolerControl(ServiceControl):
    """
    SRVC-01: Print Spooler Disabled
    Disables the Print Spooler service to prevent PrintNightmare and similar vulnerabilities.
    Only disable if printing is not required.
    """
    
    service_name = 'Spooler'
    compliant_state = 'Stopped'
    compliant_startup = 'disabled'
    
    def __init__(self):
        super().__init__(
            control_id="SRVC-01",
            name="Print Spooler Disabled",
            description="Verify Print Spooler service is disabled (PrintNightmare mitigation)",
            category=CIACategory.SERVICE,
            risk_level=RiskLevel.HIGH,
            cis_reference="CIS 5.2",
            nist_reference="CM-7"
        )


class SSDPDiscoveryControl(ServiceControl):
    """
    SRVC-02: SSDP Discovery Disabled
    Disables the SSDP Discovery service to reduce attack surface.
    Used for UPnP device discovery - unnecessary on most systems.
    """
    
    service_name = 'SSDPSRV'
    compliant_state = 'Stopped'
    compliant_startup = 'disabled'
    
    def __init__(self):
        super().__init__(
            control_id="SRVC-02",
            name="SSDP Discovery Disabled",
            description="Verify SSDP Discovery service is disabled",
            category=CIACategory.SERVICE,
            risk_level=RiskLevel.MEDIUM,
            cis_reference="CIS 5.30",
            nist_reference="CM-7"
        )


class UPnPHostControl(ServiceControl):
    """
    SRVC-03: UPnP Host Disabled
    Disables the UPnP Device Host service to reduce attack surface.
    UPnP can be exploited for network reconnaissance and attacks.
    """
    
    service_name = 'upnphost'
    compliant_state = 'Stopped'
    compliant_startup = 'disabled'
    
    def __init__(self):
        super().__init__(
            control_id="SRVC-03",
            name="UPnP Host Disabled",
            description="Verify UPnP Device Host service is disabled",
            category=CIACategory.SERVICE,
            risk_level=RiskLevel.MEDIUM,
            cis_reference="CIS 5.36",
            nist_reference="CM-7"
        )


class RemoteDesktopServicesControl(ServiceControl):
    """
    SRVC-04: Remote Desktop Services Disabled
    Disables Remote Desktop Services if not required.
    Reduces exposure to RDP-based attacks like BlueKeep.
    """
    
    service_name = 'TermService'
    compliant_state = 'Stopped'
    compliant_startup = 'disabled'
    
    def __init__(self):
        super().__init__(
            control_id="SRVC-04",
            name="Remote Desktop Services Disabled",
            description="Verify Remote Desktop Services is disabled if not needed",
            category=CIACategory.SERVICE,
            risk_level=RiskLevel.HIGH,
            cis_reference="CIS 5.27",
            nist_reference="CM-7"
        )
    
    def audit(self) -> ControlResult:
        """Check RDP service status with additional context."""
        try:
            # First check if RDP is actually in use via registry
            rdp_enabled_result = self.runner.run_reg_query(
                r'HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server',
                'fDenyTSConnections'
            )
            
            rdp_enabled = False
            if rdp_enabled_result.success and '0x0' in rdp_enabled_result.stdout:
                rdp_enabled = True
            
            # Now check service
            result = super().audit()
            
            # If RDP is enabled but service is stopped, provide context
            if rdp_enabled and result.status == ControlStatus.COMPLIANT:
                result.details = "RDP registry allows connections but service is stopped"
            elif rdp_enabled and result.status == ControlStatus.NON_COMPLIANT:
                result.details = "RDP is enabled and accepting connections - high risk if not needed"
            
            return result
            
        except Exception as e:
            return ControlResult(
                control_id=self.control_id,
                name=self.name,
                category=self.category,
                status=ControlStatus.ERROR,
                risk_level=self.risk_level,
                evidence="Error checking Remote Desktop Services",
                error_message=str(e)
            )


class TelnetClientControl(SecurityControl):
    """
    SRVC-05: Telnet Client Feature Disabled
    Ensures the Telnet Client Windows feature is disabled.
    Telnet transmits credentials in plaintext.
    """
    
    def __init__(self):
        super().__init__(
            control_id="SRVC-05",
            name="Telnet Client Disabled",
            description="Verify Telnet Client feature is not installed",
            category=CIACategory.SERVICE,
            risk_level=RiskLevel.MEDIUM,
            cis_reference="CIS 18.9.97.1",
            nist_reference="CM-7"
        )
        self._supports_rollback = False  # Feature uninstall is not easily reversible
    
    def audit(self) -> ControlResult:
        """Check if Telnet Client feature is installed."""
        try:
            result = self.runner.run_powershell(
                'Get-WindowsOptionalFeature -Online -FeatureName TelnetClient | Select-Object -ExpandProperty State'
            )
            
            if not result.success:
                # Try DISM as fallback
                result = self.runner.run_cmd('dism /online /get-featureinfo /featurename:TelnetClient')
            
            output = result.stdout.strip()
            
            if 'Disabled' in output or 'disabled' in output.lower():
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.COMPLIANT,
                    risk_level=self.risk_level,
                    evidence="Telnet Client feature is disabled/not installed",
                    command_output=output
                )
            elif 'Enabled' in output or 'enabled' in output.lower():
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.NON_COMPLIANT,
                    risk_level=self.risk_level,
                    evidence="Telnet Client feature is INSTALLED",
                    details="Telnet transmits credentials in plaintext - security risk",
                    command_output=output
                )
            else:
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.COMPLIANT,
                    risk_level=self.risk_level,
                    evidence="Telnet Client feature not found (not installed)",
                    command_output=output
                )
                
        except Exception as e:
            return ControlResult(
                control_id=self.control_id,
                name=self.name,
                category=self.category,
                status=ControlStatus.ERROR,
                risk_level=self.risk_level,
                evidence="Error checking Telnet Client feature",
                error_message=str(e)
            )
    
    def remediate(self) -> bool:
        """Disable Telnet Client feature."""
        try:
            result = self.runner.run_powershell(
                'Disable-WindowsOptionalFeature -Online -FeatureName TelnetClient -NoRestart'
            )
            
            if result.success or 'disabled' in result.stdout.lower():
                self._log('info', "Telnet Client feature disabled")
                return True
            
            # Try DISM as fallback
            result = self.runner.run_cmd('dism /online /disable-feature /featurename:TelnetClient /norestart')
            return result.success
            
        except Exception as e:
            self._log('error', f"Telnet Client remediation error: {str(e)}")
            return False
    
    def verify(self) -> ControlResult:
        """Verify Telnet Client is disabled."""
        return self.audit()


class TFTPClientControl(SecurityControl):
    """
    SRVC-06: TFTP Client Feature Disabled
    Ensures the TFTP Client Windows feature is disabled.
    TFTP has no authentication and is often used in attacks.
    """
    
    def __init__(self):
        super().__init__(
            control_id="SRVC-06",
            name="TFTP Client Disabled",
            description="Verify TFTP Client feature is not installed",
            category=CIACategory.SERVICE,
            risk_level=RiskLevel.MEDIUM,
            cis_reference="CIS 18.9.97.2",
            nist_reference="CM-7"
        )
        self._supports_rollback = False
    
    def audit(self) -> ControlResult:
        """Check if TFTP Client feature is installed."""
        try:
            result = self.runner.run_powershell(
                'Get-WindowsOptionalFeature -Online -FeatureName TFTP | Select-Object -ExpandProperty State'
            )
            
            if not result.success:
                result = self.runner.run_cmd('dism /online /get-featureinfo /featurename:TFTP')
            
            output = result.stdout.strip()
            
            if 'Disabled' in output or 'disabled' in output.lower() or not output:
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.COMPLIANT,
                    risk_level=self.risk_level,
                    evidence="TFTP Client feature is disabled/not installed",
                    command_output=output if output else "Feature not found"
                )
            elif 'Enabled' in output or 'enabled' in output.lower():
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.NON_COMPLIANT,
                    risk_level=self.risk_level,
                    evidence="TFTP Client feature is INSTALLED",
                    details="TFTP has no authentication - security risk",
                    command_output=output
                )
            else:
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.COMPLIANT,
                    risk_level=self.risk_level,
                    evidence="TFTP Client feature not found",
                    command_output=output
                )
                
        except Exception as e:
            return ControlResult(
                control_id=self.control_id,
                name=self.name,
                category=self.category,
                status=ControlStatus.ERROR,
                risk_level=self.risk_level,
                evidence="Error checking TFTP Client feature",
                error_message=str(e)
            )
    
    def remediate(self) -> bool:
        """Disable TFTP Client feature."""
        try:
            result = self.runner.run_powershell(
                'Disable-WindowsOptionalFeature -Online -FeatureName TFTP -NoRestart'
            )
            
            if result.success or 'disabled' in result.stdout.lower():
                self._log('info', "TFTP Client feature disabled")
                return True
            
            result = self.runner.run_cmd('dism /online /disable-feature /featurename:TFTP /norestart')
            return result.success
            
        except Exception as e:
            self._log('error', f"TFTP Client remediation error: {str(e)}")
            return False
    
    def verify(self) -> ControlResult:
        """Verify TFTP Client is disabled."""
        return self.audit()


class WMPNetworkSharingControl(ServiceControl):
    """
    SRVC-07: Windows Media Player Network Sharing Disabled
    Disables the WMP Network Sharing Service to reduce attack surface.
    """
    
    service_name = 'WMPNetworkSvc'
    compliant_state = 'Stopped'
    compliant_startup = 'disabled'
    
    def __init__(self):
        super().__init__(
            control_id="SRVC-07",
            name="WMP Network Sharing Disabled",
            description="Verify Windows Media Player Network Sharing is disabled",
            category=CIACategory.SERVICE,
            risk_level=RiskLevel.LOW,
            cis_reference="CIS 5.38",
            nist_reference="CM-7"
        )


class XboxServicesControl(SecurityControl):
    """
    SRVC-08: Xbox Services Disabled
    Disables Xbox-related services on enterprise systems.
    """
    
    # Xbox services to check
    XBOX_SERVICES = [
        'XblAuthManager',      # Xbox Live Auth Manager
        'XblGameSave',         # Xbox Live Game Save
        'XboxNetApiSvc',       # Xbox Live Networking Service
        'XboxGipSvc'           # Xbox Accessory Management Service
    ]
    
    def __init__(self):
        super().__init__(
            control_id="SRVC-08",
            name="Xbox Services Disabled",
            description="Verify Xbox-related services are disabled on enterprise systems",
            category=CIACategory.SERVICE,
            risk_level=RiskLevel.LOW,
            cis_reference="CIS 5.39-5.42",
            nist_reference="CM-7"
        )
        self._supports_rollback = True
    
    def _capture_current_state(self) -> Optional[Dict[str, Any]]:
        """Capture current Xbox services state."""
        try:
            states = {}
            for svc in self.XBOX_SERVICES:
                result = self.runner.run_sc(f'query {svc}')
                config = self.runner.run_sc(f'qc {svc}')
                states[svc] = {
                    'state': result.stdout if result.success else None,
                    'config': config.stdout if config.success else None
                }
            return states
        except Exception:
            return None
    
    def _restore_state(self, state_data: Dict[str, Any]) -> bool:
        """Restore Xbox services to previous state."""
        try:
            for svc, data in state_data.items():
                config = data.get('config', '')
                if config:
                    if 'AUTO_START' in config.upper():
                        self.runner.run_sc(f'config {svc} start= auto')
                    elif 'DEMAND_START' in config.upper():
                        self.runner.run_sc(f'config {svc} start= demand')
                    
                    state = data.get('state', '')
                    if 'RUNNING' in state.upper():
                        self.runner.run_sc(f'start {svc}')
            return True
        except Exception:
            return False
    
    def audit(self) -> ControlResult:
        """Check Xbox services status."""
        try:
            services_running = []
            services_stopped = []
            services_not_found = []
            
            for svc in self.XBOX_SERVICES:
                result = self.runner.run_sc(f'query {svc}')
                
                if not result.success:
                    if 'does not exist' in result.stderr.lower() or '1060' in result.stderr:
                        services_not_found.append(svc)
                    continue
                
                output = result.stdout.upper()
                if 'RUNNING' in output or 'STATE              : 4' in result.stdout:
                    services_running.append(svc)
                else:
                    services_stopped.append(svc)
            
            if services_running:
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.NON_COMPLIANT,
                    risk_level=self.risk_level,
                    evidence=f"Xbox services running: {', '.join(services_running)}",
                    details="Unnecessary services increase attack surface"
                )
            else:
                evidence_parts = []
                if services_stopped:
                    evidence_parts.append(f"Stopped: {', '.join(services_stopped)}")
                if services_not_found:
                    evidence_parts.append(f"Not installed: {', '.join(services_not_found)}")
                
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.COMPLIANT,
                    risk_level=self.risk_level,
                    evidence="; ".join(evidence_parts) if evidence_parts else "All Xbox services disabled"
                )
                
        except Exception as e:
            return ControlResult(
                control_id=self.control_id,
                name=self.name,
                category=self.category,
                status=ControlStatus.ERROR,
                risk_level=self.risk_level,
                evidence="Error checking Xbox services",
                error_message=str(e)
            )
    
    def remediate(self) -> bool:
        """Disable Xbox services."""
        try:
            success = True
            for svc in self.XBOX_SERVICES:
                # Stop the service
                self.runner.run_sc(f'stop {svc}')
                # Disable the service
                result = self.runner.run_sc(f'config {svc} start= disabled')
                if not result.success and 'does not exist' not in result.stderr.lower():
                    success = False
            
            self._log('info', "Xbox services disabled")
            return success
            
        except Exception as e:
            self._log('error', f"Xbox services remediation error: {str(e)}")
            return False
    
    def verify(self) -> ControlResult:
        """Verify Xbox services are disabled."""
        return self.audit()


class FaxServiceControl(ServiceControl):
    """
    SRVC-09: Fax Service Disabled
    Disables the Fax service as it's rarely needed and increases attack surface.
    """
    
    service_name = 'Fax'
    compliant_state = 'Stopped'
    compliant_startup = 'disabled'
    
    def __init__(self):
        super().__init__(
            control_id="SRVC-09",
            name="Fax Service Disabled",
            description="Verify Fax service is disabled",
            category=CIACategory.SERVICE,
            risk_level=RiskLevel.LOW,
            cis_reference="CIS 5.12",
            nist_reference="CM-7"
        )


class BluetoothSupportControl(ServiceControl):
    """
    SRVC-10: Bluetooth Support Service Disabled
    Disables Bluetooth service if not needed.
    Bluetooth can be exploited via BlueBorne and similar attacks.
    """
    
    service_name = 'bthserv'
    compliant_state = 'Stopped'
    compliant_startup = 'disabled'
    
    def __init__(self):
        super().__init__(
            control_id="SRVC-10",
            name="Bluetooth Support Disabled",
            description="Verify Bluetooth Support Service is disabled if not needed",
            category=CIACategory.SERVICE,
            risk_level=RiskLevel.MEDIUM,
            cis_reference="CIS 5.3",
            nist_reference="CM-7"
        )
    
    def audit(self) -> ControlResult:
        """Check Bluetooth service with hardware detection."""
        try:
            # Check if Bluetooth hardware exists
            bt_hardware_result = self.runner.run_powershell(
                'Get-PnpDevice -Class Bluetooth -ErrorAction SilentlyContinue | Measure-Object | Select-Object -ExpandProperty Count'
            )
            
            has_bluetooth = False
            if bt_hardware_result.success:
                try:
                    count = int(bt_hardware_result.stdout.strip())
                    has_bluetooth = count > 0
                except ValueError:
                    pass
            
            # Now check the service
            result = super().audit()
            
            if not has_bluetooth:
                if result.status == ControlStatus.NOT_APPLICABLE:
                    result.evidence = "No Bluetooth hardware or service found"
                elif result.status == ControlStatus.COMPLIANT:
                    result.details = "No Bluetooth hardware detected"
            
            return result
            
        except Exception as e:
            return ControlResult(
                control_id=self.control_id,
                name=self.name,
                category=self.category,
                status=ControlStatus.ERROR,
                risk_level=self.risk_level,
                evidence="Error checking Bluetooth service",
                error_message=str(e)
            )


class RDGatewayRequirementControl(SecurityControl):
    """
    SRVC-11: RD Gateway Requirement
    Verifies that if Remote Desktop is enabled, connections are required to go
    through an RD Gateway server for additional security and authentication.
    """
    
    def __init__(self):
        super().__init__(
            control_id="SRVC-11",
            name="RD Gateway Requirement",
            description="Verify RD Gateway is required when RDP is enabled",
            category=CIACategory.SERVICE,
            risk_level=RiskLevel.MEDIUM,
            cis_reference="CIS 18.9.65",
            nist_reference="AC-17(2)"
        )
        self._supports_rollback = False
    
    def audit(self) -> ControlResult:
        """Check RD Gateway requirement configuration."""
        try:
            # First check if RDP is enabled
            rdp_check = """
            $termSvc = Get-Service -Name TermService -ErrorAction SilentlyContinue
            $fDenyTSConnections = (Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server' -Name fDenyTSConnections -ErrorAction SilentlyContinue).fDenyTSConnections
            
            if ($termSvc -and $termSvc.Status -eq 'Running' -and $fDenyTSConnections -eq 0) {
                Write-Output "RDP_ENABLED"
            } else {
                Write-Output "RDP_DISABLED"
            }
            """
            rdp_result = self.runner.run_powershell(rdp_check)
            
            if rdp_result.success and "RDP_DISABLED" in rdp_result.stdout:
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.NOT_APPLICABLE,
                    risk_level=self.risk_level,
                    evidence="Remote Desktop is disabled - RD Gateway check not applicable"
                )
            
            # RDP is enabled, check for RD Gateway configuration
            # Check TS Gateway policy via registry
            gateway_check = """
            $policyPath = 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services'
            $result = @{
                GatewayUsage = $null
                GatewayHostname = $null
            }
            
            if (Test-Path $policyPath) {
                $result.GatewayUsage = (Get-ItemProperty -Path $policyPath -Name 'GatewayUsage' -ErrorAction SilentlyContinue).GatewayUsage
                $result.GatewayHostname = (Get-ItemProperty -Path $policyPath -Name 'GatewayHostname' -ErrorAction SilentlyContinue).GatewayHostname
            }
            
            # GatewayUsage values:
            # 0 = Do not use
            # 1 = Use these settings
            # 2 = Use default settings
            # 3 = Auto detect
            # 4 = Never use
            
            if ($result.GatewayUsage -eq 1 -and $result.GatewayHostname) {
                Write-Output "GATEWAY_CONFIGURED:$($result.GatewayHostname)"
            } elseif ($result.GatewayUsage -in @(0, 4)) {
                Write-Output "GATEWAY_DISABLED"
            } else {
                Write-Output "GATEWAY_NOT_CONFIGURED"
            }
            """
            gateway_result = self.runner.run_powershell(gateway_check)
            
            if gateway_result.success:
                output = gateway_result.stdout.strip()
                
                if output.startswith("GATEWAY_CONFIGURED:"):
                    hostname = output.split(":", 1)[1] if ":" in output else "configured"
                    return ControlResult(
                        control_id=self.control_id,
                        name=self.name,
                        category=self.category,
                        status=ControlStatus.COMPLIANT,
                        risk_level=self.risk_level,
                        evidence=f"RD Gateway is configured: {hostname}",
                        command_output=output
                    )
                else:
                    return ControlResult(
                        control_id=self.control_id,
                        name=self.name,
                        category=self.category,
                        status=ControlStatus.NON_COMPLIANT,
                        risk_level=self.risk_level,
                        evidence="Remote Desktop is enabled but RD Gateway is not configured",
                        details="RDP is exposed without RD Gateway protection. Configure an RD Gateway "
                                "server to provide additional authentication and secure RDP access. "
                                "Configure via Group Policy: Computer Configuration > Administrative Templates > "
                                "Windows Components > Remote Desktop Services > RD Gateway."
                    )
            
            return ControlResult(
                control_id=self.control_id,
                name=self.name,
                category=self.category,
                status=ControlStatus.ERROR,
                risk_level=self.risk_level,
                error_message="Unable to query RD Gateway configuration"
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
        """RD Gateway requires infrastructure - cannot auto-remediate."""
        self.logger.warning(
            "RD Gateway configuration requires RD Gateway server infrastructure. "
            "Cannot auto-remediate. Deploy an RD Gateway server and configure via Group Policy."
        )
        return False
    
    def verify(self) -> ControlResult:
        """Verify RD Gateway configuration."""
        return self.audit()


class ServiceHardeningControls(ControlGroup):
    """Collection of all Service Hardening controls."""
    
    def __init__(self):
        super().__init__(
            name="Service Hardening Controls",
            category=CIACategory.SERVICE,
            description="Controls for disabling unnecessary Windows services"
        )
        
        # Add all service hardening controls
        self.add_control(PrintSpoolerControl())
        self.add_control(SSDPDiscoveryControl())
        self.add_control(UPnPHostControl())
        self.add_control(RemoteDesktopServicesControl())
        self.add_control(TelnetClientControl())
        self.add_control(TFTPClientControl())
        self.add_control(WMPNetworkSharingControl())
        self.add_control(XboxServicesControl())
        self.add_control(FaxServiceControl())
        self.add_control(BluetoothSupportControl())
        # v2.3: Additional enterprise control (SRVC-11)
        self.add_control(RDGatewayRequirementControl())
    
    def initialize(self, runner, logger):
        """Initialize all controls with dependencies."""
        for control in self.controls:
            control.set_dependencies(runner, logger)
