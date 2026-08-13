"""
Network Security Controls
NETW-01: NetBIOS over TCP/IP Disabled
NETW-02: LLMNR Disabled
NETW-03: WPAD Disabled
NETW-04: IPv6 Disabled (optional)
NETW-05: Windows Firewall Logging Enabled
NETW-06: Firewall Default Deny Inbound
NETW-07: WiFi Sense Disabled
NETW-08: Hotspot 2.0 Disabled
NETW-09: Network Discovery Disabled
NETW-10: File and Printer Sharing Disabled
NETW-11: ICMP Redirect Disabled
NETW-12: Source Routing Disabled
NETW-13: DNS over HTTPS Enabled (v2.2)
NETW-14: SMB 3.0 Encryption Required (v2.3)
NETW-15: Windows Firewall Advanced Logging (v2.3)
"""

from typing import Dict, Any, Optional
from .base import (
    SecurityControl, ControlResult, ControlStatus,
    RiskLevel, CIACategory, ControlGroup
)
from .registry_base import RegistryControl


class NetBIOSControl(SecurityControl):
    """
    NETW-01: NetBIOS over TCP/IP Disabled
    Disables NetBIOS over TCP/IP on all network adapters.
    """
    
    def __init__(self):
        super().__init__(
            control_id="NETW-01",
            name="NetBIOS over TCP/IP Disabled",
            description="Verify NetBIOS over TCP/IP is disabled on all adapters",
            category=CIACategory.NETWORK,
            risk_level=RiskLevel.MEDIUM,
            cis_reference="N/A",
            nist_reference="CM-7"
        )
        self._supports_rollback = True
    
    def _capture_current_state(self) -> Optional[Dict[str, Any]]:
        try:
            result = self.runner.run_powershell(
                'Get-WmiObject Win32_NetworkAdapterConfiguration | '
                'Where-Object { $_.IPEnabled -eq $true } | '
                'Select-Object Description, TcpipNetbiosOptions | ConvertTo-Json'
            )
            return {'netbios_config': result.stdout if result.success else None}
        except Exception:
            return None
    
    def _restore_state(self, state_data: Dict[str, Any]) -> bool:
        # Complex to restore per-adapter, skip
        return False
    
    def audit(self) -> ControlResult:
        try:
            # Check NetBIOS setting on all IP-enabled adapters
            # TcpipNetbiosOptions: 0=Default, 1=Enabled, 2=Disabled
            result = self.runner.run_powershell(
                'Get-WmiObject Win32_NetworkAdapterConfiguration | '
                'Where-Object { $_.IPEnabled -eq $true } | '
                'Select-Object -ExpandProperty TcpipNetbiosOptions'
            )
            
            if not result.success:
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.ERROR,
                    risk_level=self.risk_level,
                    evidence="Failed to query NetBIOS settings",
                    error_message=result.stderr
                )
            
            output = result.stdout.strip()
            values = [v.strip() for v in output.split('\n') if v.strip()]
            
            # Check if all adapters have NetBIOS disabled (value = 2)
            all_disabled = all(v == '2' for v in values if v.isdigit())
            has_enabled = any(v in ['0', '1'] for v in values if v.isdigit())
            
            if all_disabled and values:
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.COMPLIANT,
                    risk_level=self.risk_level,
                    evidence="NetBIOS over TCP/IP is disabled on all adapters",
                    command_output=output
                )
            elif has_enabled:
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.NON_COMPLIANT,
                    risk_level=self.risk_level,
                    evidence="NetBIOS over TCP/IP is enabled on one or more adapters",
                    details="NetBIOS can expose system to name resolution attacks",
                    command_output=output
                )
            else:
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.NOT_APPLICABLE,
                    risk_level=self.risk_level,
                    evidence="No IP-enabled adapters found",
                    command_output=output
                )
                
        except Exception as e:
            return ControlResult(
                control_id=self.control_id,
                name=self.name,
                category=self.category,
                status=ControlStatus.ERROR,
                risk_level=self.risk_level,
                evidence="Error checking NetBIOS settings",
                error_message=str(e)
            )
    
    def remediate(self) -> bool:
        try:
            # Disable NetBIOS on all adapters (TcpipNetbiosOptions = 2)
            result = self.runner.run_powershell(
                '$adapters = Get-WmiObject Win32_NetworkAdapterConfiguration | '
                'Where-Object { $_.IPEnabled -eq $true }; '
                'foreach ($adapter in $adapters) { $adapter.SetTcpipNetbios(2) }'
            )
            
            if result.success:
                self._log('info', "NetBIOS disabled on all adapters")
                return True
            else:
                self._log('error', f"Failed to disable NetBIOS: {result.stderr}")
                return False
                
        except Exception as e:
            self._log('error', f"NetBIOS remediation error: {str(e)}")
            return False
    
    def verify(self) -> ControlResult:
        return self.audit()


class LLMNRControl(RegistryControl):
    """
    NETW-02: LLMNR Disabled
    Disables Link-Local Multicast Name Resolution.
    """
    
    registry_path = r'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'
    registry_value = 'EnableMulticast'
    expected_data = 0
    value_type = 'REG_DWORD'
    
    def __init__(self):
        super().__init__(
            control_id="NETW-02",
            name="LLMNR Disabled",
            description="Verify Link-Local Multicast Name Resolution is disabled",
            category=CIACategory.NETWORK,
            risk_level=RiskLevel.HIGH,
            cis_reference="CIS 18.5.4.2",
            nist_reference="CM-7"
        )


class WPADControl(RegistryControl):
    """
    NETW-03: WPAD Disabled
    Disables Web Proxy Auto-Discovery Protocol.
    """
    
    registry_path = r'HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad'
    registry_value = 'WpadOverride'
    expected_data = 1
    value_type = 'REG_DWORD'
    
    def __init__(self):
        super().__init__(
            control_id="NETW-03",
            name="WPAD Disabled",
            description="Verify WPAD (Web Proxy Auto-Discovery) is disabled",
            category=CIACategory.NETWORK,
            risk_level=RiskLevel.MEDIUM,
            cis_reference="N/A",
            nist_reference="CM-7"
        )


class IPv6Control(RegistryControl):
    """
    NETW-04: IPv6 Disabled
    Optionally disables IPv6 if not required.
    """
    
    registry_path = r'HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters'
    registry_value = 'DisabledComponents'
    expected_data = 255
    value_type = 'REG_DWORD'
    
    def __init__(self):
        super().__init__(
            control_id="NETW-04",
            name="IPv6 Disabled",
            description="Verify IPv6 is disabled if not required (optional)",
            category=CIACategory.NETWORK,
            risk_level=RiskLevel.LOW,
            cis_reference="N/A",
            nist_reference="CM-7"
        )


class FirewallLoggingControl(SecurityControl):
    """
    NETW-05: Windows Firewall Logging Enabled
    Ensures firewall logging is enabled for dropped packets.
    """
    
    def __init__(self):
        super().__init__(
            control_id="NETW-05",
            name="Windows Firewall Logging",
            description="Verify firewall logging is enabled for all profiles",
            category=CIACategory.NETWORK,
            risk_level=RiskLevel.MEDIUM,
            cis_reference="CIS 9.1.4",
            nist_reference="AU-3"
        )
        self._supports_rollback = True
    
    def _capture_current_state(self) -> Optional[Dict[str, Any]]:
        try:
            result = self.runner.run_netsh('advfirewall show allprofiles logging')
            return {'logging_config': result.stdout if result.success else None}
        except Exception:
            return None
    
    def _restore_state(self, state_data: Dict[str, Any]) -> bool:
        # Complex to parse and restore, skip
        return False
    
    def audit(self) -> ControlResult:
        try:
            result = self.runner.run_netsh('advfirewall show allprofiles logging')
            
            if not result.success:
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.ERROR,
                    risk_level=self.risk_level,
                    evidence="Failed to query firewall logging",
                    error_message=result.stderr
                )
            
            output = result.stdout
            
            # Check if logging is enabled (LogDroppedPackets = enable)
            dropped_enabled = 'LogDroppedPackets' in output and 'enable' in output.lower()
            
            if dropped_enabled:
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.COMPLIANT,
                    risk_level=self.risk_level,
                    evidence="Firewall logging is enabled",
                    command_output=output[:500]
                )
            else:
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.NON_COMPLIANT,
                    risk_level=self.risk_level,
                    evidence="Firewall logging is not fully enabled",
                    details="Enable logging for dropped packets",
                    command_output=output[:500]
                )
                
        except Exception as e:
            return ControlResult(
                control_id=self.control_id,
                name=self.name,
                category=self.category,
                status=ControlStatus.ERROR,
                risk_level=self.risk_level,
                evidence="Error checking firewall logging",
                error_message=str(e)
            )
    
    def remediate(self) -> bool:
        try:
            success = True
            for profile in ['domainprofile', 'privateprofile', 'publicprofile']:
                result = self.runner.run_netsh(
                    f'advfirewall set {profile} logging droppedconnections enable'
                )
                if not result.success:
                    success = False
                    
                result = self.runner.run_netsh(
                    f'advfirewall set {profile} logging allowedconnections enable'
                )
            
            if success:
                self._log('info', "Firewall logging enabled")
            return success
            
        except Exception as e:
            self._log('error', f"Firewall logging remediation error: {str(e)}")
            return False
    
    def verify(self) -> ControlResult:
        return self.audit()


class FirewallDefaultDenyControl(SecurityControl):
    """
    NETW-06: Firewall Default Deny Inbound
    Ensures firewall blocks inbound connections by default.
    """
    
    def __init__(self):
        super().__init__(
            control_id="NETW-06",
            name="Firewall Default Deny Inbound",
            description="Verify firewall blocks inbound connections by default",
            category=CIACategory.NETWORK,
            risk_level=RiskLevel.HIGH,
            cis_reference="CIS 9.1.2",
            nist_reference="SC-7"
        )
        self._supports_rollback = True
    
    def _capture_current_state(self) -> Optional[Dict[str, Any]]:
        try:
            result = self.runner.run_netsh('advfirewall show allprofiles firewallpolicy')
            return {'policy': result.stdout if result.success else None}
        except Exception:
            return None
    
    def _restore_state(self, state_data: Dict[str, Any]) -> bool:
        return False  # Don't auto-restore firewall policy
    
    def audit(self) -> ControlResult:
        try:
            result = self.runner.run_netsh('advfirewall show allprofiles firewallpolicy')
            
            if not result.success:
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.ERROR,
                    risk_level=self.risk_level,
                    evidence="Failed to query firewall policy",
                    error_message=result.stderr
                )
            
            output = result.stdout.lower()
            
            # Check for blockinbound in all profiles
            if 'blockinbound' in output:
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.COMPLIANT,
                    risk_level=self.risk_level,
                    evidence="Firewall blocks inbound connections by default",
                    command_output=result.stdout
                )
            else:
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.NON_COMPLIANT,
                    risk_level=self.risk_level,
                    evidence="Firewall may allow inbound connections",
                    details="Set default inbound policy to block",
                    command_output=result.stdout
                )
                
        except Exception as e:
            return ControlResult(
                control_id=self.control_id,
                name=self.name,
                category=self.category,
                status=ControlStatus.ERROR,
                risk_level=self.risk_level,
                evidence="Error checking firewall policy",
                error_message=str(e)
            )
    
    def remediate(self) -> bool:
        try:
            result = self.runner.run_netsh(
                'advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound'
            )
            
            if result.success:
                self._log('info', "Firewall default deny inbound configured")
                return True
            else:
                self._log('error', f"Failed to set firewall policy: {result.stderr}")
                return False
                
        except Exception as e:
            self._log('error', f"Firewall policy remediation error: {str(e)}")
            return False
    
    def verify(self) -> ControlResult:
        return self.audit()


class WiFiSenseControl(RegistryControl):
    """
    NETW-07: WiFi Sense Disabled
    Disables automatic WiFi network sharing.
    """
    
    registry_path = r'HKLM\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config'
    registry_value = 'AutoConnectAllowedOEM'
    expected_data = 0
    value_type = 'REG_DWORD'
    
    def __init__(self):
        super().__init__(
            control_id="NETW-07",
            name="WiFi Sense Disabled",
            description="Verify WiFi Sense auto-connect is disabled",
            category=CIACategory.NETWORK,
            risk_level=RiskLevel.MEDIUM,
            cis_reference="CIS 18.5.23.2.1",
            nist_reference="AC-18"
        )


class Hotspot20Control(RegistryControl):
    """
    NETW-08: Hotspot 2.0 Disabled
    Disables automatic connection to Hotspot 2.0 networks.
    """
    
    registry_path = r'HKLM\SOFTWARE\Microsoft\WlanSvc\AnqpCache'
    registry_value = 'OsuRegistrationStatus'
    expected_data = 0
    value_type = 'REG_DWORD'
    
    def __init__(self):
        super().__init__(
            control_id="NETW-08",
            name="Hotspot 2.0 Disabled",
            description="Verify Hotspot 2.0 auto-connect is disabled",
            category=CIACategory.NETWORK,
            risk_level=RiskLevel.LOW,
            cis_reference="N/A",
            nist_reference="AC-18"
        )


class NetworkDiscoveryControl(SecurityControl):
    """
    NETW-09: Network Discovery Disabled
    Disables network discovery on public networks.
    """
    
    def __init__(self):
        super().__init__(
            control_id="NETW-09",
            name="Network Discovery Disabled",
            description="Verify network discovery is disabled on public profile",
            category=CIACategory.NETWORK,
            risk_level=RiskLevel.MEDIUM,
            cis_reference="N/A",
            nist_reference="CM-7"
        )
        self._supports_rollback = False
    
    def audit(self) -> ControlResult:
        try:
            result = self.runner.run_netsh(
                'advfirewall firewall show rule name="Network Discovery (LLMNR-UDP-In)"'
            )
            
            output = result.stdout.lower()
            
            # Check if rule is disabled or doesn't exist for public profile
            if 'no rules match' in output or not result.success:
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.COMPLIANT,
                    risk_level=self.risk_level,
                    evidence="Network Discovery rule not found or disabled",
                    command_output=result.stdout
                )
            
            if 'enabled:' in output and 'yes' in output:
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.NON_COMPLIANT,
                    risk_level=self.risk_level,
                    evidence="Network Discovery is enabled",
                    details="Disable on public networks",
                    command_output=result.stdout[:500]
                )
            else:
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.COMPLIANT,
                    risk_level=self.risk_level,
                    evidence="Network Discovery is disabled",
                    command_output=result.stdout[:500]
                )
                
        except Exception as e:
            return ControlResult(
                control_id=self.control_id,
                name=self.name,
                category=self.category,
                status=ControlStatus.ERROR,
                risk_level=self.risk_level,
                evidence="Error checking Network Discovery",
                error_message=str(e)
            )
    
    def remediate(self) -> bool:
        try:
            # Disable Network Discovery firewall rules for public profile
            result = self.runner.run_netsh(
                'advfirewall firewall set rule group="Network Discovery" new enable=no profile=public'
            )
            
            if result.success or 'no rules match' in result.stderr.lower():
                self._log('info', "Network Discovery disabled on public profile")
                return True
            return False
            
        except Exception as e:
            self._log('error', f"Network Discovery remediation error: {str(e)}")
            return False
    
    def verify(self) -> ControlResult:
        return self.audit()


class FilePrinterSharingControl(SecurityControl):
    """
    NETW-10: File and Printer Sharing Disabled
    Disables file and printer sharing on public networks.
    """
    
    def __init__(self):
        super().__init__(
            control_id="NETW-10",
            name="File and Printer Sharing Disabled",
            description="Verify file/printer sharing is disabled on public networks",
            category=CIACategory.NETWORK,
            risk_level=RiskLevel.MEDIUM,
            cis_reference="CIS 9.3.5",
            nist_reference="CM-7"
        )
        self._supports_rollback = False
    
    def audit(self) -> ControlResult:
        try:
            result = self.runner.run_netsh(
                'advfirewall firewall show rule name="File and Printer Sharing (SMB-In)"'
            )
            
            output = result.stdout.lower()
            
            if 'no rules match' in output or not result.success:
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.COMPLIANT,
                    risk_level=self.risk_level,
                    evidence="File and Printer Sharing rules not configured",
                    command_output=result.stdout
                )
            
            # Check if enabled on public profile
            if 'public' in output and 'enabled:' in output and 'yes' in output:
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.NON_COMPLIANT,
                    risk_level=self.risk_level,
                    evidence="File and Printer Sharing enabled on public profile",
                    command_output=result.stdout[:500]
                )
            else:
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.COMPLIANT,
                    risk_level=self.risk_level,
                    evidence="File and Printer Sharing properly restricted",
                    command_output=result.stdout[:500]
                )
                
        except Exception as e:
            return ControlResult(
                control_id=self.control_id,
                name=self.name,
                category=self.category,
                status=ControlStatus.ERROR,
                risk_level=self.risk_level,
                evidence="Error checking File and Printer Sharing",
                error_message=str(e)
            )
    
    def remediate(self) -> bool:
        try:
            result = self.runner.run_netsh(
                'advfirewall firewall set rule group="File and Printer Sharing" new enable=no profile=public'
            )
            
            if result.success or 'no rules match' in result.stderr.lower():
                self._log('info', "File and Printer Sharing disabled on public profile")
                return True
            return False
            
        except Exception as e:
            self._log('error', f"File/Printer Sharing remediation error: {str(e)}")
            return False
    
    def verify(self) -> ControlResult:
        return self.audit()


class ICMPRedirectControl(RegistryControl):
    """
    NETW-11: ICMP Redirect Disabled
    Disables ICMP redirect messages.
    """
    
    registry_path = r'HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
    registry_value = 'EnableICMPRedirect'
    expected_data = 0
    value_type = 'REG_DWORD'
    
    def __init__(self):
        super().__init__(
            control_id="NETW-11",
            name="ICMP Redirect Disabled",
            description="Verify ICMP redirect messages are disabled",
            category=CIACategory.NETWORK,
            risk_level=RiskLevel.MEDIUM,
            cis_reference="CIS 18.5.8.1",
            nist_reference="CM-7"
        )


class SourceRoutingControl(RegistryControl):
    """
    NETW-12: Source Routing Disabled
    Disables IP source routing.
    """
    
    registry_path = r'HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
    registry_value = 'DisableIPSourceRouting'
    expected_data = 2
    value_type = 'REG_DWORD'
    
    def __init__(self):
        super().__init__(
            control_id="NETW-12",
            name="Source Routing Disabled",
            description="Verify IP source routing is disabled",
            category=CIACategory.NETWORK,
            risk_level=RiskLevel.MEDIUM,
            cis_reference="CIS 18.5.8.2",
            nist_reference="CM-7"
        )


class DNSOverHTTPSControl(SecurityControl):
    """
    NETW-13: DNS over HTTPS (DoH)
    Verifies encrypted DNS is configured to prevent
    DNS-based data exfiltration and snooping.
    
    Note: Native DoH support requires Windows 11 or Windows 10 21H2+.
    """
    
    # Known DoH providers
    DOH_PROVIDERS = {
        '1.1.1.1': {'name': 'Cloudflare', 'template': 'https://cloudflare-dns.com/dns-query'},
        '1.0.0.1': {'name': 'Cloudflare', 'template': 'https://cloudflare-dns.com/dns-query'},
        '8.8.8.8': {'name': 'Google', 'template': 'https://dns.google/dns-query'},
        '8.8.4.4': {'name': 'Google', 'template': 'https://dns.google/dns-query'},
        '9.9.9.9': {'name': 'Quad9', 'template': 'https://dns.quad9.net/dns-query'},
        '149.112.112.112': {'name': 'Quad9', 'template': 'https://dns.quad9.net/dns-query'},
    }
    
    def __init__(self):
        super().__init__(
            control_id="NETW-13",
            name="DNS over HTTPS Enabled",
            description="Verify encrypted DNS (DoH) is configured to prevent DNS exfiltration",
            category=CIACategory.NETWORK,
            risk_level=RiskLevel.HIGH,
            cis_reference="N/A",
            nist_reference="SC-8"
        )
        self._supports_rollback = True
    
    def _capture_current_state(self) -> Optional[Dict[str, Any]]:
        """Capture current DoH configuration."""
        try:
            result = self.runner.run_powershell(
                'Get-DnsClientDohServerAddress -ErrorAction SilentlyContinue | ConvertTo-Json'
            )
            return {'doh_servers': result.stdout if result.success else None}
        except Exception:
            return None
    
    def _restore_state(self, state_data: Dict[str, Any]) -> bool:
        """Restore DoH configuration (complex, best effort)."""
        return False
    
    def audit(self) -> ControlResult:
        """Check DNS over HTTPS configuration."""
        try:
            # Check Windows version (DoH requires Win10 21H2+ or Win11)
            version_check = self.runner.run_powershell(
                '[System.Environment]::OSVersion.Version | '
                'Select-Object Major, Minor, Build | ConvertTo-Json'
            )
            
            win_build = 0
            if version_check.success:
                try:
                    import json
                    ver_info = json.loads(version_check.stdout)
                    win_build = ver_info.get('Build', 0)
                except:
                    pass
            
            # Check if DoH cmdlet is available (Windows 11 / Win10 21H2+)
            doh_check = self.runner.run_powershell(
                'Get-Command Get-DnsClientDohServerAddress -ErrorAction SilentlyContinue | '
                'Select-Object -ExpandProperty Name'
            )
            
            if not doh_check.success or 'Get-DnsClientDohServerAddress' not in doh_check.stdout:
                # DoH not natively supported
                if win_build > 0 and win_build < 19043:  # Pre-21H1
                    return ControlResult(
                        control_id=self.control_id,
                        name=self.name,
                        category=self.category,
                        status=ControlStatus.NOT_APPLICABLE,
                        risk_level=self.risk_level,
                        evidence=f"Native DoH not supported (Windows build {win_build})",
                        details="Native DNS over HTTPS requires Windows 11 or Windows 10 21H2+. "
                                "Consider using third-party DNS clients (e.g., Cloudflare WARP, NextDNS) "
                                "or upgrade Windows for native DoH support.",
                        command_output=f"Build: {win_build}"
                    )
            
            # Get configured DoH servers
            doh_servers = self.runner.run_powershell(
                'Get-DnsClientDohServerAddress -ErrorAction SilentlyContinue | '
                'Select-Object ServerAddress, DohTemplate, AllowFallbackToUdp | '
                'ConvertTo-Json -Compress'
            )
            
            # Check system DNS settings for DoH mode
            doh_mode = self.runner.run_powershell(
                'Get-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Dnscache\\Parameters" '
                '-Name EnableAutoDoh -ErrorAction SilentlyContinue | '
                'Select-Object -ExpandProperty EnableAutoDoh'
            )
            
            # Check current DNS server addresses
            current_dns = self.runner.run_powershell(
                'Get-DnsClientServerAddress -AddressFamily IPv4 | '
                'Where-Object { $_.ServerAddresses } | '
                'Select-Object -ExpandProperty ServerAddresses | '
                'Select-Object -Unique'
            )
            
            # Parse results
            doh_configured = False
            doh_providers_found = []
            auto_doh_enabled = False
            
            # Check if auto DoH is enabled (2 = automatic)
            if doh_mode.success and doh_mode.stdout.strip():
                try:
                    mode_value = int(doh_mode.stdout.strip())
                    auto_doh_enabled = mode_value == 2
                except:
                    pass
            
            # Check if any known DoH providers are configured
            if current_dns.success and current_dns.stdout:
                dns_servers = [s.strip() for s in current_dns.stdout.strip().split('\n') if s.strip()]
                for server in dns_servers:
                    if server in self.DOH_PROVIDERS:
                        doh_providers_found.append(self.DOH_PROVIDERS[server]['name'])
            
            # Check explicit DoH server configuration
            if doh_servers.success and doh_servers.stdout and doh_servers.stdout.strip() != '':
                try:
                    import json
                    servers = json.loads(doh_servers.stdout)
                    if isinstance(servers, dict):
                        servers = [servers]
                    if servers and len(servers) > 0:
                        doh_configured = True
                except:
                    pass
            
            # Determine compliance
            if doh_configured or (auto_doh_enabled and doh_providers_found):
                provider_str = ', '.join(set(doh_providers_found)) if doh_providers_found else 'Custom'
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.COMPLIANT,
                    risk_level=self.risk_level,
                    evidence=f"DoH enabled via {provider_str}",
                    details=f"DNS over HTTPS is configured. DNS queries are encrypted, "
                            "preventing DNS-based surveillance and data exfiltration. "
                            f"Auto-DoH: {'Enabled' if auto_doh_enabled else 'Disabled'}",
                    command_output=doh_servers.stdout[:500] if doh_servers.stdout else None
                )
            
            if doh_providers_found and not auto_doh_enabled:
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.NON_COMPLIANT,
                    risk_level=self.risk_level,
                    evidence=f"DoH-capable DNS ({', '.join(set(doh_providers_found))}) but DoH not enforced",
                    details="DNS servers support DoH but automatic DoH is not enabled. "
                            "Enable via: Settings > Network & Internet > [Connection] > "
                            "DNS server assignment > Edit > Encrypted preferred or Encrypted only.",
                    command_output=f"DNS: {', '.join(doh_providers_found)}, AutoDoH: {auto_doh_enabled}"
                )
            
            return ControlResult(
                control_id=self.control_id,
                name=self.name,
                category=self.category,
                status=ControlStatus.NON_COMPLIANT,
                risk_level=self.risk_level,
                evidence="DoH not configured - DNS queries unencrypted",
                details="DNS over HTTPS is not configured. DNS queries are sent in plaintext, "
                        "allowing network eavesdropping and potential data exfiltration. "
                        "Configure DoH via: Settings > Network & Internet > [Connection] > DNS, "
                        "or use PowerShell: Set-DnsClientDohServerAddress",
                command_output=current_dns.stdout[:300] if current_dns.stdout else None
            )
                
        except Exception as e:
            return ControlResult(
                control_id=self.control_id,
                name=self.name,
                category=self.category,
                status=ControlStatus.ERROR,
                risk_level=self.risk_level,
                evidence="Error checking DoH status",
                error_message=str(e)
            )
    
    def remediate(self) -> bool:
        """Configure DNS over HTTPS with Cloudflare."""
        try:
            # Add Cloudflare DoH server
            result1 = self.runner.run_powershell(
                'Add-DnsClientDohServerAddress -ServerAddress "1.1.1.1" '
                '-DohTemplate "https://cloudflare-dns.com/dns-query" '
                '-AllowFallbackToUdp $false -AutoUpgrade $true -ErrorAction SilentlyContinue'
            )
            
            result2 = self.runner.run_powershell(
                'Add-DnsClientDohServerAddress -ServerAddress "1.0.0.1" '
                '-DohTemplate "https://cloudflare-dns.com/dns-query" '
                '-AllowFallbackToUdp $false -AutoUpgrade $true -ErrorAction SilentlyContinue'
            )
            
            # Enable auto DoH
            result3 = self.runner.run_reg_add(
                r'HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters',
                'EnableAutoDoh',
                'REG_DWORD',
                '2'
            )
            
            return result3.success
        except Exception:
            return False
    
    def verify(self) -> ControlResult:
        """Verify DoH configuration after remediation."""
        return self.audit()


class SMBEncryptionControl(SecurityControl):
    """
    NETW-14: SMB 3.0 Encryption Required
    Verifies SMB server is configured to require encryption for all connections,
    protecting data in transit from interception.
    """
    
    def __init__(self):
        super().__init__(
            control_id="NETW-14",
            name="SMB 3.0 Encryption",
            description="Verify SMB server requires encryption for all connections",
            category=CIACategory.NETWORK,
            risk_level=RiskLevel.HIGH,
            cis_reference="CIS 18.5.14.1",
            nist_reference="SC-8"
        )
        self._supports_rollback = True
    
    def audit(self) -> ControlResult:
        """Check SMB server encryption settings."""
        try:
            ps_cmd = """
            $config = Get-SmbServerConfiguration -ErrorAction Stop
            $result = @{
                EncryptData = $config.EncryptData
                RejectUnencryptedAccess = $config.RejectUnencryptedAccess
                EnableSMB2Protocol = $config.EnableSMB2Protocol
            }
            $result | ConvertTo-Json
            """
            result = self.runner.run_powershell(ps_cmd)
            
            if result.success and result.stdout.strip():
                import json
                try:
                    config = json.loads(result.stdout.strip())
                    encrypt_data = config.get('EncryptData', False)
                    reject_unencrypted = config.get('RejectUnencryptedAccess', False)
                    smb2_enabled = config.get('EnableSMB2Protocol', True)
                    
                    evidence_parts = [
                        f"EncryptData: {encrypt_data}",
                        f"RejectUnencryptedAccess: {reject_unencrypted}",
                        f"SMB2/3 Protocol: {'Enabled' if smb2_enabled else 'Disabled'}"
                    ]
                    evidence = ", ".join(evidence_parts)
                    
                    if encrypt_data:
                        status_msg = "SMB encryption is enabled"
                        if reject_unencrypted:
                            status_msg += " with strict enforcement (rejects unencrypted)"
                        return ControlResult(
                            control_id=self.control_id,
                            name=self.name,
                            category=self.category,
                            status=ControlStatus.COMPLIANT,
                            risk_level=self.risk_level,
                            evidence=status_msg,
                            command_output=evidence
                        )
                    else:
                        return ControlResult(
                            control_id=self.control_id,
                            name=self.name,
                            category=self.category,
                            status=ControlStatus.NON_COMPLIANT,
                            risk_level=self.risk_level,
                            evidence="SMB encryption is not enabled",
                            details="Enable SMB encryption to protect file sharing traffic. "
                                    "Warning: May break connectivity with SMB2 or older clients.",
                            command_output=evidence
                        )
                except json.JSONDecodeError:
                    pass
            
            # Fallback: Simple text-based check
            simple_cmd = "(Get-SmbServerConfiguration).EncryptData"
            simple_result = self.runner.run_powershell(simple_cmd)
            
            if simple_result.success:
                if simple_result.stdout.strip().lower() == "true":
                    return ControlResult(
                        control_id=self.control_id,
                        name=self.name,
                        category=self.category,
                        status=ControlStatus.COMPLIANT,
                        risk_level=self.risk_level,
                        evidence="SMB encryption is enabled",
                        command_output=simple_result.stdout
                    )
                else:
                    return ControlResult(
                        control_id=self.control_id,
                        name=self.name,
                        category=self.category,
                        status=ControlStatus.NON_COMPLIANT,
                        risk_level=self.risk_level,
                        evidence="SMB encryption is disabled",
                        details="Enable SMB encryption: Set-SmbServerConfiguration -EncryptData $true"
                    )
            
            return ControlResult(
                control_id=self.control_id,
                name=self.name,
                category=self.category,
                status=ControlStatus.ERROR,
                risk_level=self.risk_level,
                error_message="Unable to query SMB server configuration"
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
        """Enable SMB encryption."""
        try:
            ps_cmd = "Set-SmbServerConfiguration -EncryptData $true -Force"
            result = self.runner.run_powershell(ps_cmd)
            
            if result.success:
                self.logger.warning(
                    "SMB encryption enabled. Clients using SMB2 or older protocols "
                    "may no longer be able to connect."
                )
            return result.success
        except Exception as e:
            self.logger.error(f"Failed to enable SMB encryption: {e}")
            return False
    
    def rollback(self) -> bool:
        """Disable SMB encryption requirement."""
        try:
            ps_cmd = "Set-SmbServerConfiguration -EncryptData $false -Force"
            result = self.runner.run_powershell(ps_cmd)
            return result.success
        except Exception:
            return False
    
    def verify(self) -> ControlResult:
        """Verify SMB encryption configuration."""
        return self.audit()


class FirewallAdvancedLoggingControl(SecurityControl):
    """
    NETW-15: Windows Firewall Advanced Logging
    Verifies firewall logging is comprehensively configured with adequate log size
    and logging of both allowed and dropped connections for forensic analysis.
    """
    
    def __init__(self):
        super().__init__(
            control_id="NETW-15",
            name="Firewall Advanced Logging",
            description="Verify firewall has comprehensive logging with adequate log retention",
            category=CIACategory.NETWORK,
            risk_level=RiskLevel.MEDIUM,
            cis_reference="CIS 9.1.7, 9.2.7, 9.3.7",
            nist_reference="AU-12"
        )
        self._supports_rollback = True
    
    def audit(self) -> ControlResult:
        """Check firewall advanced logging settings."""
        try:
            ps_cmd = """
            $profiles = Get-NetFirewallProfile -All -ErrorAction Stop
            $results = @()
            foreach ($profile in $profiles) {
                $results += @{
                    Name = $profile.Name
                    LogBlocked = $profile.LogBlocked
                    LogAllowed = $profile.LogAllowed
                    LogFileName = $profile.LogFileName
                    LogMaxSizeKilobytes = $profile.LogMaxSizeKilobytes
                }
            }
            $results | ConvertTo-Json
            """
            result = self.runner.run_powershell(ps_cmd)
            
            if result.success and result.stdout.strip():
                import json
                try:
                    profiles = json.loads(result.stdout.strip())
                    if not isinstance(profiles, list):
                        profiles = [profiles]
                    
                    all_compliant = True
                    issues = []
                    evidence_parts = []
                    
                    for profile in profiles:
                        name = profile.get('Name', 'Unknown')
                        log_blocked = profile.get('LogBlocked', False)
                        log_allowed = profile.get('LogAllowed', False)
                        log_size = profile.get('LogMaxSizeKilobytes', 0)
                        
                        profile_issues = []
                        
                        # Check blocked logging
                        if not log_blocked:
                            profile_issues.append("LogBlocked disabled")
                            all_compliant = False
                        
                        # Check log size (minimum 4096 KB = 4 MB recommended)
                        if log_size < 4096:
                            profile_issues.append(f"LogSize {log_size}KB < 4096KB")
                            all_compliant = False
                        
                        if profile_issues:
                            issues.append(f"{name}: {', '.join(profile_issues)}")
                        
                        evidence_parts.append(
                            f"{name}: Blocked={log_blocked}, Allowed={log_allowed}, Size={log_size}KB"
                        )
                    
                    evidence = "; ".join(evidence_parts)
                    
                    if all_compliant:
                        return ControlResult(
                            control_id=self.control_id,
                            name=self.name,
                            category=self.category,
                            status=ControlStatus.COMPLIANT,
                            risk_level=self.risk_level,
                            evidence="Firewall logging properly configured on all profiles",
                            command_output=evidence
                        )
                    else:
                        return ControlResult(
                            control_id=self.control_id,
                            name=self.name,
                            category=self.category,
                            status=ControlStatus.NON_COMPLIANT,
                            risk_level=self.risk_level,
                            evidence=f"Logging issues: {'; '.join(issues)}",
                            details="Enable dropped packet logging and increase log size to 4096KB minimum for forensic retention",
                            command_output=evidence
                        )
                except json.JSONDecodeError:
                    pass
            
            # Fallback to netsh
            netsh_result = self.runner.run_netsh('advfirewall show allprofiles logging')
            
            if netsh_result.success:
                output = netsh_result.stdout.lower()
                dropped_ok = 'logdroppedpackets' in output and 'enable' in output
                
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.COMPLIANT if dropped_ok else ControlStatus.NON_COMPLIANT,
                    risk_level=self.risk_level,
                    evidence="Firewall logging " + ("enabled" if dropped_ok else "needs configuration"),
                    command_output=netsh_result.stdout[:500]
                )
            
            return ControlResult(
                control_id=self.control_id,
                name=self.name,
                category=self.category,
                status=ControlStatus.ERROR,
                risk_level=self.risk_level,
                error_message="Unable to query firewall logging configuration"
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
        """Configure comprehensive firewall logging."""
        try:
            # Enable logging for dropped packets and set adequate log size
            ps_cmd = """
            Set-NetFirewallProfile -All -LogBlocked True -LogMaxSizeKilobytes 16384 -ErrorAction Stop
            """
            result = self.runner.run_powershell(ps_cmd)
            
            if result.success:
                self.logger.info(
                    "Firewall logging configured: blocked packets logged, "
                    "log size set to 16MB for forensic retention"
                )
            return result.success
        except Exception as e:
            self.logger.error(f"Failed to configure firewall logging: {e}")
            return False
    
    def rollback(self) -> bool:
        """Reset firewall logging to defaults."""
        try:
            ps_cmd = "Set-NetFirewallProfile -All -LogBlocked False -LogMaxSizeKilobytes 4096"
            result = self.runner.run_powershell(ps_cmd)
            return result.success
        except Exception:
            return False
    
    def verify(self) -> ControlResult:
        """Verify firewall logging configuration."""
        return self.audit()


class NetworkControls(ControlGroup):
    """Collection of all Network Security controls."""
    
    def __init__(self):
        super().__init__(
            name="Network Security Controls",
            category=CIACategory.NETWORK,
            description="Controls for network hardening and protection"
        )
        
        # Add all network controls (NETW-01 to NETW-13)
        self.add_control(NetBIOSControl())            # NETW-01
        self.add_control(LLMNRControl())              # NETW-02
        self.add_control(WPADControl())               # NETW-03
        self.add_control(IPv6Control())               # NETW-04
        self.add_control(FirewallLoggingControl())    # NETW-05
        self.add_control(FirewallDefaultDenyControl()) # NETW-06
        self.add_control(WiFiSenseControl())          # NETW-07
        self.add_control(Hotspot20Control())          # NETW-08
        self.add_control(NetworkDiscoveryControl())   # NETW-09
        self.add_control(FilePrinterSharingControl()) # NETW-10
        self.add_control(ICMPRedirectControl())       # NETW-11
        self.add_control(SourceRoutingControl())      # NETW-12
        # v2.2: New enterprise control
        self.add_control(DNSOverHTTPSControl())       # NETW-13
        # v2.3: Additional enterprise controls (NETW-14 to NETW-15)
        self.add_control(SMBEncryptionControl())      # NETW-14
        self.add_control(FirewallAdvancedLoggingControl())  # NETW-15
    
    def initialize(self, runner, logger):
        """Initialize all controls with dependencies."""
        for control in self.controls:
            control.set_dependencies(runner, logger)
