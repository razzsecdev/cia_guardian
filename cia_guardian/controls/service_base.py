"""
Service Control Base Class
Base class for controls that manage Windows services.
"""

from typing import Dict, Any, Optional
from .base import (
    SecurityControl, ControlResult, ControlStatus,
    RiskLevel, CIACategory
)


class ServiceControl(SecurityControl):
    """
    Base class for controls that manage Windows services.
    
    Subclasses must set:
        - service_name: Windows service name (e.g., 'vss', 'w32time')
        - compliant_state: Expected state ('Running' or 'Stopped')
        - compliant_startup: Expected startup type ('auto', 'demand', 'disabled')
    """
    
    service_name: str = ''
    compliant_state: str = 'Running'
    compliant_startup: str = 'auto'
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._supports_rollback = True
        if not self.service_name:
            raise ValueError(f"service_name must be set in subclass {self.__class__.__name__}")
    
    def _capture_current_state(self) -> Optional[Dict[str, Any]]:
        """Capture current service state and startup type."""
        try:
            state_result = self.runner.run_sc(f'query {self.service_name}')
            config_result = self.runner.run_sc(f'qc {self.service_name}')
            
            return {
                'service_state': state_result.stdout if state_result.success else None,
                'service_config': config_result.stdout if config_result.success else None
            }
        except Exception:
            return None
    
    def _restore_state(self, state_data: Dict[str, Any]) -> bool:
        """Restore service to previous state."""
        try:
            state_output = state_data.get('service_state', '')
            config_output = state_data.get('service_config', '')
            
            # Determine original startup type
            original_start = self._parse_startup_type(config_output)
            
            # Restore startup type
            self.runner.run_sc(f'config {self.service_name} start= {original_start}')
            
            # Restore running state
            was_stopped = 'STOPPED' in state_output.upper() or 'STATE              : 1' in state_output
            was_running = 'RUNNING' in state_output.upper() or 'STATE              : 4' in state_output
            
            if was_stopped:
                self.runner.run_sc(f'stop {self.service_name}')
            elif was_running:
                self.runner.run_sc(f'start {self.service_name}')
            
            return True
        except Exception:
            return False
    
    def _parse_startup_type(self, config_output: str) -> str:
        """Parse startup type from sc qc output."""
        if not config_output:
            return 'demand'
        
        config_upper = config_output.upper()
        if 'AUTO_START' in config_upper:
            return 'auto'
        elif 'DISABLED' in config_upper:
            return 'disabled'
        return 'demand'
    
    def _parse_service_state(self, state_output: str) -> str:
        """Parse running state from sc query output."""
        if not state_output:
            return 'unknown'
        
        state_upper = state_output.upper()
        if 'RUNNING' in state_upper or 'STATE              : 4' in state_output:
            return 'Running'
        elif 'STOPPED' in state_upper or 'STATE              : 1' in state_output:
            return 'Stopped'
        return 'unknown'
    
    def audit(self) -> ControlResult:
        """Check service status."""
        try:
            result = self.runner.run_sc(f'query {self.service_name}')
            
            if not result.success:
                # Service may not exist
                if 'does not exist' in result.stderr.lower() or '1060' in result.stderr:
                    return ControlResult(
                        control_id=self.control_id,
                        name=self.name,
                        category=self.category,
                        status=ControlStatus.NOT_APPLICABLE,
                        risk_level=self.risk_level,
                        evidence=f"Service '{self.service_name}' not found on this system",
                        command_output=result.stderr
                    )
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.ERROR,
                    risk_level=self.risk_level,
                    evidence=f"Failed to query {self.service_name} service",
                    error_message=result.stderr
                )
            
            current_state = self._parse_service_state(result.stdout)
            
            if current_state == self.compliant_state:
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.COMPLIANT,
                    risk_level=self.risk_level,
                    evidence=f"Service '{self.service_name}' is {current_state}",
                    command_output=result.stdout
                )
            elif current_state == 'unknown':
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.PENDING,
                    risk_level=self.risk_level,
                    evidence=f"Service '{self.service_name}' state unclear",
                    command_output=result.stdout
                )
            else:
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.NON_COMPLIANT,
                    risk_level=self.risk_level,
                    evidence=f"Service '{self.service_name}' is {current_state}",
                    details=f"Expected: {self.compliant_state}",
                    command_output=result.stdout
                )
                
        except Exception as e:
            return ControlResult(
                control_id=self.control_id,
                name=self.name,
                category=self.category,
                status=ControlStatus.ERROR,
                risk_level=self.risk_level,
                evidence=f"Error checking {self.service_name} service",
                error_message=str(e)
            )
    
    def remediate(self) -> bool:
        """Start/stop and configure service to compliant state."""
        try:
            # Set startup type
            config_result = self.runner.run_sc(f'config {self.service_name} start= {self.compliant_startup}')
            
            # Start or stop based on compliant_state
            if self.compliant_state == 'Running':
                result = self.runner.run_sc(f'start {self.service_name}')
                success_msg = 'started'
            else:
                result = self.runner.run_sc(f'stop {self.service_name}')
                success_msg = 'stopped'
            
            if result.success or 'already' in result.stderr.lower():
                self._log('info', f"Service '{self.service_name}' {success_msg} and configured")
                return True
            else:
                self._log('warning', f"Service '{self.service_name}' result: {result.stderr}")
                return config_result.success
                
        except Exception as e:
            self._log('error', f"Service '{self.service_name}' remediation error: {str(e)}")
            return False
    
    def verify(self) -> ControlResult:
        """Verify service is in compliant state."""
        return self.audit()
