"""
Base Security Control Class
Defines the Check-Fix-Verify pattern for all security controls.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional, List, Any, Dict, TYPE_CHECKING
from datetime import datetime
from enum import Enum

if TYPE_CHECKING:
    from ..utils.command_runner import WindowsCommandRunner
    from ..utils.logger import GuardianLogger


class ControlStatus(Enum):
    """Status of a security control."""
    COMPLIANT = "Compliant"
    NON_COMPLIANT = "Non-Compliant"
    PENDING = "Pending"
    ERROR = "Error"
    NOT_APPLICABLE = "N/A"
    REMEDIATED = "Remediated"
    TIMEOUT = "Timeout"       # Control execution exceeded time limit
    RUNNING = "Running"       # Control is currently executing (transient state)


class RiskLevel(Enum):
    """Risk level classification."""
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


class CIACategory(Enum):
    """CIA Triad category plus extended security categories."""
    CONFIDENTIALITY = "Confidentiality"
    INTEGRITY = "Integrity"
    AVAILABILITY = "Availability"
    NETWORK = "Network Security"
    APPLICATION = "Application Security"
    SERVICE = "Service Hardening"


@dataclass
class BackupState:
    """Stores the backup state of a security control before remediation."""
    control_id: str
    timestamp: datetime
    state_data: Dict[str, Any]
    description: str = ""
    can_rollback: bool = True
    
    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return {
            'control_id': self.control_id,
            'timestamp': self.timestamp.isoformat(),
            'state_data': self.state_data,
            'description': self.description,
            'can_rollback': self.can_rollback
        }


@dataclass
class ControlResult:
    """Result of a security control audit or remediation."""
    control_id: str
    name: str
    category: CIACategory
    status: ControlStatus
    risk_level: RiskLevel
    evidence: str
    details: str = ""
    initial_state: Optional[str] = None
    post_fix_state: Optional[str] = None
    remediation_applied: bool = False
    remediation_success: bool = False
    timestamp: datetime = field(default_factory=datetime.now)
    error_message: Optional[str] = None
    command_output: Optional[str] = None
    execution_time_ms: int = 0  # Execution time in milliseconds for performance tracking
    
    def to_dict(self) -> dict:
        """Convert to dictionary for reporting."""
        return {
            'control_id': self.control_id,
            'name': self.name,
            'category': self.category.value,
            'status': self.status.value,
            'risk_level': self.risk_level.value,
            'evidence': self.evidence,
            'details': self.details,
            'initial_state': self.initial_state,
            'post_fix_state': self.post_fix_state,
            'remediation_applied': self.remediation_applied,
            'remediation_success': self.remediation_success,
            'timestamp': self.timestamp.isoformat(),
            'error_message': self.error_message,
            'command_output': self.command_output,
            'execution_time_ms': self.execution_time_ms,
        }
    
    @property
    def is_passing(self) -> bool:
        """Check if this result indicates a passing/compliant state."""
        return self.status in (ControlStatus.COMPLIANT, ControlStatus.REMEDIATED)
    
    @property
    def is_failing(self) -> bool:
        """Check if this result indicates a failing/non-compliant state."""
        return self.status in (ControlStatus.NON_COMPLIANT, ControlStatus.ERROR, ControlStatus.TIMEOUT)
    
    @property
    def is_actionable(self) -> bool:
        """Check if this result requires attention/action."""
        return self.status in (ControlStatus.NON_COMPLIANT, ControlStatus.ERROR, ControlStatus.TIMEOUT)
    
    @property  
    def is_skipped(self) -> bool:
        """Check if this control was skipped or not applicable."""
        return self.status == ControlStatus.NOT_APPLICABLE


class SecurityControl(ABC):
    """
    Abstract base class for all security controls.
    Implements the mandatory Check-Fix-Verify pattern with backup/rollback support.
    """
    
    def __init__(self, control_id: str, name: str, description: str,
                 category: CIACategory, risk_level: RiskLevel,
                 cis_reference: Optional[str] = None,
                 nist_reference: Optional[str] = None):
        """
        Initialize a security control.
        
        Args:
            control_id: Unique control identifier (e.g., CONF-01)
            name: Human-readable control name
            description: Detailed description of what this control checks
            category: CIA category (Confidentiality, Integrity, Availability)
            risk_level: Risk level if non-compliant
            cis_reference: CIS Benchmark reference (optional)
            nist_reference: NIST 800-53 reference (optional)
        """
        self.control_id = control_id
        self.name = name
        self.description = description
        self.category = category
        self.risk_level = risk_level
        self.cis_reference = cis_reference
        self.nist_reference = nist_reference
        self.runner: Optional['WindowsCommandRunner'] = None
        self.logger: Optional['GuardianLogger'] = None
        self._last_result: Optional[ControlResult] = None
        self._backup_state: Optional[BackupState] = None
        self._supports_rollback: bool = True  # Override in subclass if rollback not possible
    
    def set_dependencies(self, runner: 'WindowsCommandRunner', logger: 'GuardianLogger'):
        """Set the command runner and logger dependencies."""
        self.runner = runner
        self.logger = logger
    
    def _log(self, level: str, message: str):
        """Log a message if logger is available."""
        if self.logger:
            getattr(self.logger, level.lower(), self.logger.info)(message)
    
    @property
    def supports_rollback(self) -> bool:
        """Check if this control supports rollback."""
        return self._supports_rollback
    
    @property
    def has_backup(self) -> bool:
        """Check if a backup exists for this control."""
        return self._backup_state is not None
    
    def get_backup_info(self) -> Optional[Dict[str, Any]]:
        """Get information about the current backup state."""
        if self._backup_state:
            return self._backup_state.to_dict()
        return None
    
    def backup(self) -> Optional[BackupState]:
        """
        Backup the current state before remediation.
        Override this method in subclasses to implement control-specific backup.
        
        Returns:
            BackupState object if backup successful, None otherwise
        """
        if not self._supports_rollback:
            self._log('debug', f"[{self.control_id}] Rollback not supported for this control")
            return None
        
        try:
            state_data = self._capture_current_state()
            if state_data is not None:
                self._backup_state = BackupState(
                    control_id=self.control_id,
                    timestamp=datetime.now(),
                    state_data=state_data,
                    description=f"Backup of {self.name} before remediation",
                    can_rollback=True
                )
                self._log('debug', f"[{self.control_id}] State backed up successfully")
                return self._backup_state
        except Exception as e:
            self._log('warning', f"[{self.control_id}] Backup failed: {str(e)}")
        
        return None
    
    def rollback(self) -> bool:
        """
        Rollback to the previous state from backup.
        Override this method in subclasses to implement control-specific rollback.
        
        Returns:
            True if rollback successful, False otherwise
        """
        if not self._backup_state:
            self._log('warning', f"[{self.control_id}] No backup state available for rollback")
            return False
        
        if not self._backup_state.can_rollback:
            self._log('warning', f"[{self.control_id}] Backup state cannot be rolled back")
            return False
        
        try:
            success = self._restore_state(self._backup_state.state_data)
            if success:
                self._log('info', f"[{self.control_id}] Rollback successful")
                # Clear backup after successful rollback
                self._backup_state = None
            return success
        except Exception as e:
            self._log('error', f"[{self.control_id}] Rollback failed: {str(e)}")
            return False
    
    def _capture_current_state(self) -> Optional[Dict[str, Any]]:
        """
        Capture the current state for backup.
        Override this method in subclasses to implement control-specific state capture.
        
        Returns:
            Dictionary containing the current state data, or None if capture failed
        """
        # Default implementation - subclasses should override
        return None
    
    def _restore_state(self, state_data: Dict[str, Any]) -> bool:
        """
        Restore a previous state from backup data.
        Override this method in subclasses to implement control-specific restoration.
        
        Args:
            state_data: Dictionary containing the state to restore
            
        Returns:
            True if restoration successful, False otherwise
        """
        # Default implementation - subclasses should override
        return False
    
    @abstractmethod
    def audit(self) -> ControlResult:
        """
        Audit the current state of this security control.
        
        Returns:
            ControlResult with status 'Compliant' or 'Non-Compliant'
        """
        pass
    
    @abstractmethod
    def remediate(self) -> bool:
        """
        Apply remediation to fix a non-compliant control.
        
        Returns:
            True if remediation was successfully applied, False otherwise
        """
        pass
    
    @abstractmethod
    def verify(self) -> ControlResult:
        """
        Verify that remediation was successful.
        
        Returns:
            ControlResult confirming the post-remediation state
        """
        pass
    
    def check_fix_verify(self, dry_run: bool = False, enable_backup: bool = True) -> ControlResult:
        """
        Execute the full Check-Fix-Verify pattern.
        
        Args:
            dry_run: If True, only audit without remediation
            enable_backup: If True, backup state before remediation (for rollback)
            
        Returns:
            Final ControlResult after the complete cycle
        """
        self._log('info', f"[{self.control_id}] Starting audit: {self.name}")
        
        # Step 1: Audit
        audit_result = self.audit()
        initial_state = audit_result.status.value
        
        if audit_result.status == ControlStatus.COMPLIANT:
            self._log('info', f"[{self.control_id}] Already compliant")
            return audit_result
        
        if audit_result.status == ControlStatus.ERROR:
            self._log('error', f"[{self.control_id}] Audit failed: {audit_result.error_message}")
            return audit_result
        
        if dry_run:
            self._log('info', f"[{self.control_id}] Dry run - skipping remediation")
            audit_result.details = "Dry run - remediation skipped"
            return audit_result
        
        # Step 1.5: Backup current state before remediation
        if enable_backup and self._supports_rollback:
            self._log('debug', f"[{self.control_id}] Backing up current state...")
            backup = self.backup()
            if backup:
                self._log('debug', f"[{self.control_id}] Backup created successfully")
            else:
                self._log('debug', f"[{self.control_id}] Backup not available for this control")
        
        # Step 2: Remediate
        self._log('info', f"[{self.control_id}] Applying remediation...")
        try:
            remediation_success = self.remediate()
        except Exception as e:
            self._log('error', f"[{self.control_id}] Remediation error: {str(e)}")
            audit_result.error_message = str(e)
            audit_result.remediation_applied = True
            audit_result.remediation_success = False
            return audit_result
        
        # Step 3: Verify
        self._log('info', f"[{self.control_id}] Verifying remediation...")
        verify_result = self.verify()
        verify_result.initial_state = initial_state
        verify_result.post_fix_state = verify_result.status.value
        verify_result.remediation_applied = True
        verify_result.remediation_success = (
            remediation_success and verify_result.status == ControlStatus.COMPLIANT
        )
        
        if verify_result.remediation_success:
            self._log('info', f"[{self.control_id}] Remediation successful")
            verify_result.status = ControlStatus.REMEDIATED
        else:
            self._log('warning', f"[{self.control_id}] Remediation verification failed")
        
        self._last_result = verify_result
        return verify_result
    
    def get_last_result(self) -> Optional[ControlResult]:
        """Get the last audit/verification result."""
        return self._last_result
    
    def __repr__(self) -> str:
        return f"<{self.__class__.__name__}({self.control_id}: {self.name})>"


class ControlGroup:
    """A group of related security controls."""
    
    def __init__(self, name: str, category: CIACategory, description: str = ""):
        self.name = name
        self.category = category
        self.description = description
        self.controls: List[SecurityControl] = []
    
    def add_control(self, control: SecurityControl):
        """Add a control to this group."""
        self.controls.append(control)
    
    def get_controls(self) -> List[SecurityControl]:
        """Get all controls in this group."""
        return self.controls
    
    def audit_all(self, dry_run: bool = False) -> List[ControlResult]:
        """Audit all controls in this group."""
        results = []
        for control in self.controls:
            result = control.check_fix_verify(dry_run=dry_run)
            results.append(result)
        return results
    
    def __repr__(self) -> str:
        return f"<ControlGroup({self.name}, {len(self.controls)} controls)>"
