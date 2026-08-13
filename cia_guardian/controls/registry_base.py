"""
Registry Control Base Class
Base class for controls that check/modify Windows registry values.
"""

import re
from typing import Dict, Any, Optional, Union, List
from .base import (
    SecurityControl, ControlResult, ControlStatus,
    RiskLevel, CIACategory
)


class RegistryControl(SecurityControl):
    """
    Base class for controls that manage Windows registry values.
    
    Subclasses must set:
        - registry_path: Full registry path (e.g., 'HKLM\\SOFTWARE\\...')
        - registry_value: Value name to check
        - expected_data: Expected value data (int for DWORD, str for SZ)
        - value_type: Registry value type ('REG_DWORD', 'REG_SZ', 'REG_QWORD')
    
    Optional:
        - comparison: 'equal', 'greater_equal', 'less_equal', 'not_equal'
        - create_if_missing: Whether to create the value if it doesn't exist
    """
    
    registry_path: str = ''
    registry_value: str = ''
    expected_data: Union[int, str] = 0
    value_type: str = 'REG_DWORD'
    comparison: str = 'equal'  # 'equal', 'greater_equal', 'less_equal', 'not_equal'
    create_if_missing: bool = True
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._supports_rollback = True
        if not self.registry_path or not self.registry_value:
            raise ValueError(f"registry_path and registry_value must be set in subclass {self.__class__.__name__}")
    
    def _capture_current_state(self) -> Optional[Dict[str, Any]]:
        """Capture current registry value."""
        try:
            result = self.runner.run_reg_query(self.registry_path, self.registry_value)
            return {
                'registry_output': result.stdout if result.success else None,
                'existed': result.success
            }
        except Exception:
            return None
    
    def _restore_state(self, state_data: Dict[str, Any]) -> bool:
        """Restore registry to previous state."""
        try:
            existed = state_data.get('existed', False)
            output = state_data.get('registry_output', '')
            
            if not existed:
                # Value didn't exist before, delete it
                self.runner.run_cmd(f'reg delete "{self.registry_path}" /v "{self.registry_value}" /f')
                return True
            
            # Parse original value and restore
            original_value = self._parse_registry_value(output)
            if original_value is not None:
                result = self.runner.run_reg_add(
                    self.registry_path,
                    self.registry_value,
                    self.value_type,
                    str(original_value)
                )
                return result.success
            
            return False
        except Exception:
            return False
    
    def _parse_registry_value(self, output: str) -> Optional[Union[int, str]]:
        """Parse registry value from reg query output."""
        if not output:
            return None
        
        # Try to parse DWORD value (hex format: 0x1)
        dword_match = re.search(r'REG_DWORD\s+0x([0-9a-fA-F]+)', output)
        if dword_match:
            return int(dword_match.group(1), 16)
        
        # Try to parse QWORD value
        qword_match = re.search(r'REG_QWORD\s+0x([0-9a-fA-F]+)', output)
        if qword_match:
            return int(qword_match.group(1), 16)
        
        # Try to parse string value
        sz_match = re.search(r'REG_(?:EXPAND_)?SZ\s+(.+?)(?:\r?\n|$)', output)
        if sz_match:
            return sz_match.group(1).strip()
        
        return None
    
    def _compare_values(self, current: Union[int, str, None], expected: Union[int, str]) -> bool:
        """Compare current value against expected value."""
        if current is None:
            return False
        
        # Convert to same type for comparison
        if isinstance(expected, int) and isinstance(current, str):
            try:
                current = int(current)
            except ValueError:
                return False
        
        if self.comparison == 'equal':
            return current == expected
        elif self.comparison == 'greater_equal':
            return current >= expected
        elif self.comparison == 'less_equal':
            return current <= expected
        elif self.comparison == 'not_equal':
            return current != expected
        
        return current == expected
    
    def audit(self) -> ControlResult:
        """Check registry value."""
        try:
            result = self.runner.run_reg_query(self.registry_path, self.registry_value)
            
            if not result.success:
                # Value doesn't exist
                if 'unable to find' in result.stderr.lower() or 'error' in result.stderr.lower():
                    if self.create_if_missing:
                        return ControlResult(
                            control_id=self.control_id,
                            name=self.name,
                            category=self.category,
                            status=ControlStatus.NON_COMPLIANT,
                            risk_level=self.risk_level,
                            evidence=f"Registry value '{self.registry_value}' not found",
                            details=f"Expected: {self.expected_data}",
                            command_output=result.stderr
                        )
                    else:
                        return ControlResult(
                            control_id=self.control_id,
                            name=self.name,
                            category=self.category,
                            status=ControlStatus.COMPLIANT,
                            risk_level=self.risk_level,
                            evidence=f"Registry value '{self.registry_value}' not set (acceptable)",
                            command_output=result.stderr
                        )
                
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.ERROR,
                    risk_level=self.risk_level,
                    evidence=f"Failed to query registry",
                    error_message=result.stderr
                )
            
            current_value = self._parse_registry_value(result.stdout)
            is_compliant = self._compare_values(current_value, self.expected_data)
            
            if is_compliant:
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.COMPLIANT,
                    risk_level=self.risk_level,
                    evidence=f"{self.registry_value} = {current_value}",
                    command_output=result.stdout
                )
            else:
                comparison_text = {
                    'equal': f"Expected: {self.expected_data}",
                    'greater_equal': f"Expected: >= {self.expected_data}",
                    'less_equal': f"Expected: <= {self.expected_data}",
                    'not_equal': f"Expected: != {self.expected_data}"
                }.get(self.comparison, f"Expected: {self.expected_data}")
                
                return ControlResult(
                    control_id=self.control_id,
                    name=self.name,
                    category=self.category,
                    status=ControlStatus.NON_COMPLIANT,
                    risk_level=self.risk_level,
                    evidence=f"{self.registry_value} = {current_value}",
                    details=comparison_text,
                    command_output=result.stdout
                )
                
        except Exception as e:
            return ControlResult(
                control_id=self.control_id,
                name=self.name,
                category=self.category,
                status=ControlStatus.ERROR,
                risk_level=self.risk_level,
                evidence=f"Error checking registry",
                error_message=str(e)
            )
    
    def remediate(self) -> bool:
        """Set registry value to expected data."""
        try:
            result = self.runner.run_reg_add(
                self.registry_path,
                self.registry_value,
                self.value_type,
                str(self.expected_data)
            )
            
            if result.success:
                self._log('info', f"Registry '{self.registry_value}' set to {self.expected_data}")
                return True
            else:
                self._log('error', f"Failed to set registry: {result.stderr}")
                return False
                
        except Exception as e:
            self._log('error', f"Registry remediation error: {str(e)}")
            return False
    
    def verify(self) -> ControlResult:
        """Verify registry value is set correctly."""
        return self.audit()


class MultiRegistryControl(SecurityControl):
    """
    Base class for controls that check multiple registry values.
    
    Subclasses must set:
        - registry_checks: List of dicts with 'path', 'value', 'expected', 'type', 'comparison'
    """
    
    registry_checks: List[Dict[str, Any]] = []
    require_all: bool = True  # If True, all checks must pass; if False, any one passing is enough
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._supports_rollback = True
        if not self.registry_checks:
            raise ValueError(f"registry_checks must be set in subclass {self.__class__.__name__}")
    
    def _capture_current_state(self) -> Optional[Dict[str, Any]]:
        """Capture all registry values."""
        try:
            states = {}
            for check in self.registry_checks:
                result = self.runner.run_reg_query(check['path'], check['value'])
                states[f"{check['path']}\\{check['value']}"] = {
                    'output': result.stdout if result.success else None,
                    'existed': result.success
                }
            return states
        except Exception:
            return None
    
    def _restore_state(self, state_data: Dict[str, Any]) -> bool:
        """Restore all registry values."""
        try:
            success = True
            for check in self.registry_checks:
                key = f"{check['path']}\\{check['value']}"
                if key in state_data:
                    state = state_data[key]
                    if not state.get('existed', False):
                        # Delete value that didn't exist
                        self.runner.run_cmd(f'reg delete "{check["path"]}" /v "{check["value"]}" /f')
                    else:
                        # Restore original value
                        output = state.get('output', '')
                        original = self._parse_value(output, check.get('type', 'REG_DWORD'))
                        if original is not None:
                            self.runner.run_reg_add(
                                check['path'],
                                check['value'],
                                check.get('type', 'REG_DWORD'),
                                str(original)
                            )
            return success
        except Exception:
            return False
    
    def _parse_value(self, output: str, value_type: str) -> Optional[Union[int, str]]:
        """Parse registry value from output."""
        if not output:
            return None
        
        if 'DWORD' in value_type or 'QWORD' in value_type:
            match = re.search(r'REG_(?:D|Q)WORD\s+0x([0-9a-fA-F]+)', output)
            if match:
                return int(match.group(1), 16)
        else:
            match = re.search(r'REG_(?:EXPAND_)?SZ\s+(.+?)(?:\r?\n|$)', output)
            if match:
                return match.group(1).strip()
        
        return None
    
    def _check_single(self, check: Dict[str, Any]) -> tuple:
        """Check a single registry value. Returns (is_compliant, current_value, output)."""
        result = self.runner.run_reg_query(check['path'], check['value'])
        
        if not result.success:
            return (False, None, result.stderr)
        
        current = self._parse_value(result.stdout, check.get('type', 'REG_DWORD'))
        expected = check['expected']
        comparison = check.get('comparison', 'equal')
        
        if current is None:
            return (False, None, result.stdout)
        
        if comparison == 'equal':
            compliant = current == expected
        elif comparison == 'greater_equal':
            compliant = current >= expected
        elif comparison == 'less_equal':
            compliant = current <= expected
        elif comparison == 'not_equal':
            compliant = current != expected
        else:
            compliant = current == expected
        
        return (compliant, current, result.stdout)
    
    def audit(self) -> ControlResult:
        """Check all registry values."""
        try:
            results = []
            all_compliant = True
            any_compliant = False
            evidence_parts = []
            
            for check in self.registry_checks:
                compliant, current, output = self._check_single(check)
                results.append({
                    'check': check,
                    'compliant': compliant,
                    'current': current
                })
                
                if compliant:
                    any_compliant = True
                    evidence_parts.append(f"✓ {check['value']}={current}")
                else:
                    all_compliant = False
                    evidence_parts.append(f"✗ {check['value']}={current} (expected {check['expected']})")
            
            is_compliant = all_compliant if self.require_all else any_compliant
            
            return ControlResult(
                control_id=self.control_id,
                name=self.name,
                category=self.category,
                status=ControlStatus.COMPLIANT if is_compliant else ControlStatus.NON_COMPLIANT,
                risk_level=self.risk_level,
                evidence="; ".join(evidence_parts),
                command_output=str(results)
            )
            
        except Exception as e:
            return ControlResult(
                control_id=self.control_id,
                name=self.name,
                category=self.category,
                status=ControlStatus.ERROR,
                risk_level=self.risk_level,
                evidence="Error checking registry values",
                error_message=str(e)
            )
    
    def remediate(self) -> bool:
        """Set all registry values."""
        try:
            success = True
            for check in self.registry_checks:
                result = self.runner.run_reg_add(
                    check['path'],
                    check['value'],
                    check.get('type', 'REG_DWORD'),
                    str(check['expected'])
                )
                if not result.success:
                    self._log('warning', f"Failed to set {check['value']}: {result.stderr}")
                    success = False
            
            return success
            
        except Exception as e:
            self._log('error', f"Multi-registry remediation error: {str(e)}")
            return False
    
    def verify(self) -> ControlResult:
        """Verify all registry values."""
        return self.audit()
