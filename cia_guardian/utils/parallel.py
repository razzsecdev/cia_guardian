"""
Parallel Execution Infrastructure for CIA-Guardian v2.1
Provides thread-safe parallel control execution with background SFC support.

Features:
- Thread pool execution with configurable worker count
- Background SFC (INTG-05) execution with async wait
- Thread-safe result collection
- Progress reporting callbacks
- Timeout handling with TIMEOUT status
"""

import threading
import queue
import time
from concurrent.futures import ThreadPoolExecutor, as_completed, Future, TimeoutError as FuturesTimeoutError
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Dict, Optional, Callable, Any, TYPE_CHECKING

if TYPE_CHECKING:
    from ..controls.base import SecurityControl, ControlResult, ControlStatus
    from ..utils.logger import GuardianLogger


@dataclass
class ControlTask:
    """
    Wrapper for executing a single control with timeout and result capture.
    Provides execution context and timing information.
    """
    control: 'SecurityControl'
    timeout: int = 120  # Default 2 minute timeout
    dry_run: bool = True
    enable_backup: bool = False
    result: Optional['ControlResult'] = None
    start_time: Optional[float] = None
    end_time: Optional[float] = None
    error: Optional[str] = None
    
    @property
    def execution_time_ms(self) -> int:
        """Get execution time in milliseconds."""
        if self.start_time and self.end_time:
            return int((self.end_time - self.start_time) * 1000)
        return 0
    
    def execute(self) -> 'ControlResult':
        """
        Execute the control and capture the result.
        
        Returns:
            ControlResult from the control execution
        """
        from ..controls.base import ControlResult, ControlStatus
        
        self.start_time = time.time()
        
        try:
            # Execute the control's check-fix-verify pattern
            self.result = self.control.check_fix_verify(
                dry_run=self.dry_run,
                enable_backup=self.enable_backup
            )
            self.end_time = time.time()
            
            # Add execution time to result
            if self.result:
                self.result.execution_time_ms = self.execution_time_ms
            
            return self.result
            
        except Exception as e:
            self.end_time = time.time()
            self.error = str(e)
            
            # Create error result
            self.result = ControlResult(
                control_id=self.control.control_id,
                name=self.control.name,
                category=self.control.category,
                status=ControlStatus.ERROR,
                risk_level=self.control.risk_level,
                evidence=f"Execution error: {str(e)}",
                error_message=str(e),
                execution_time_ms=self.execution_time_ms
            )
            return self.result


class ResultCollector:
    """
    Thread-safe collection of control results.
    Supports concurrent writes from multiple worker threads.
    """
    
    def __init__(self):
        self._results: List['ControlResult'] = []
        self._lock = threading.Lock()
        self._results_by_id: Dict[str, 'ControlResult'] = {}
        self._results_by_category: Dict[str, List['ControlResult']] = {}
    
    def add_result(self, result: 'ControlResult') -> None:
        """
        Add a result to the collection (thread-safe).
        
        Args:
            result: ControlResult to add
        """
        with self._lock:
            self._results.append(result)
            self._results_by_id[result.control_id] = result
            
            # Group by category
            category = result.category.value
            if category not in self._results_by_category:
                self._results_by_category[category] = []
            self._results_by_category[category].append(result)
    
    def get_results(self) -> List['ControlResult']:
        """Get all collected results (thread-safe copy)."""
        with self._lock:
            return list(self._results)
    
    def get_result_by_id(self, control_id: str) -> Optional['ControlResult']:
        """Get a specific result by control ID."""
        with self._lock:
            return self._results_by_id.get(control_id)
    
    def get_results_by_category(self) -> Dict[str, List['ControlResult']]:
        """Get results grouped by category (thread-safe copy)."""
        with self._lock:
            return {k: list(v) for k, v in self._results_by_category.items()}
    
    def get_count(self) -> int:
        """Get total number of results collected."""
        with self._lock:
            return len(self._results)
    
    def get_category_counts(self) -> Dict[str, int]:
        """Get count of results per category."""
        with self._lock:
            return {k: len(v) for k, v in self._results_by_category.items()}
    
    def clear(self) -> None:
        """Clear all collected results."""
        with self._lock:
            self._results.clear()
            self._results_by_id.clear()
            self._results_by_category.clear()


class BackgroundSFCTask:
    """
    Dedicated handler for INTG-05 (SFC) background execution.
    Runs SFC in a separate thread while other controls proceed.
    """
    
    def __init__(self, logger: Optional['GuardianLogger'] = None):
        self._thread: Optional[threading.Thread] = None
        self._result: Optional['ControlResult'] = None
        self._completed = threading.Event()
        self._started = threading.Event()
        self._error: Optional[str] = None
        self._start_time: Optional[float] = None
        self._logger = logger
        self._control: Optional['SecurityControl'] = None
        self._timeout: int = 2700  # Default 45 minutes
    
    def _log(self, level: str, message: str):
        """Log a message if logger is available."""
        if self._logger:
            getattr(self._logger, level.lower(), self._logger.info)(message)
    
    def start(self, control: 'SecurityControl', timeout: int = 2700, dry_run: bool = True) -> None:
        """
        Start SFC execution in a background thread.
        
        Args:
            control: The SFC SecurityControl instance (INTG-05)
            timeout: Maximum execution time in seconds (default: 45 min)
            dry_run: Whether this is a dry run (audit only)
        """
        if self._thread is not None and self._thread.is_alive():
            self._log('warning', "SFC task already running")
            return
        
        self._control = control
        self._timeout = timeout
        self._result = None
        self._error = None
        self._completed.clear()
        self._started.clear()
        self._start_time = time.time()
        
        def _run_sfc():
            """Internal thread function to run SFC."""
            try:
                self._started.set()
                self._log('info', f"[INTG-05] SFC background task started (timeout: {timeout}s)")
                
                # Execute the control
                task = ControlTask(
                    control=control,
                    timeout=timeout,
                    dry_run=dry_run,
                    enable_backup=False  # SFC doesn't support rollback
                )
                
                self._result = task.execute()
                
                if self._result:
                    elapsed = int(time.time() - self._start_time)
                    self._log('info', f"[INTG-05] SFC completed in {elapsed}s with status: {self._result.status.value}")
                
            except Exception as e:
                self._error = str(e)
                self._log('error', f"[INTG-05] SFC background task error: {str(e)}")
            finally:
                self._completed.set()
        
        self._thread = threading.Thread(target=_run_sfc, name="SFC-Background", daemon=True)
        self._thread.start()
    
    def wait(self, timeout: Optional[int] = None) -> Optional['ControlResult']:
        """
        Wait for SFC to complete with optional timeout.
        
        Args:
            timeout: Maximum wait time in seconds (None = use configured timeout)
            
        Returns:
            ControlResult if completed, None if timed out
        """
        from ..controls.base import ControlResult, ControlStatus, CIACategory, RiskLevel
        
        wait_timeout = timeout if timeout is not None else self._timeout
        
        # Wait for completion
        completed = self._completed.wait(timeout=wait_timeout)
        
        if completed and self._result:
            return self._result
        
        if not completed:
            # Timeout occurred
            elapsed = int(time.time() - self._start_time) if self._start_time else 0
            self._log('warning', f"[INTG-05] SFC timed out after {elapsed}s (limit: {wait_timeout}s)")
            
            # Create timeout result
            return ControlResult(
                control_id="INTG-05",
                name="System File Integrity",
                category=CIACategory.INTEGRITY,
                status=ControlStatus.TIMEOUT,
                risk_level=RiskLevel.HIGH,
                evidence=f"SFC scan exceeded {wait_timeout}s timeout limit",
                details=f"Scan was still running after {elapsed}s. Consider running manually: sfc /verifyonly",
                error_message=f"Timeout after {elapsed}s",
                execution_time_ms=elapsed * 1000
            )
        
        # Completed but no result (error case)
        if self._error:
            return ControlResult(
                control_id="INTG-05",
                name="System File Integrity",
                category=CIACategory.INTEGRITY,
                status=ControlStatus.ERROR,
                risk_level=RiskLevel.HIGH,
                evidence="SFC background task failed",
                error_message=self._error
            )
        
        return None
    
    def is_running(self) -> bool:
        """Check if SFC is currently running."""
        return self._thread is not None and self._thread.is_alive() and not self._completed.is_set()
    
    def is_completed(self) -> bool:
        """Check if SFC has completed."""
        return self._completed.is_set()
    
    def get_result(self) -> Optional['ControlResult']:
        """Get the result if available (non-blocking)."""
        return self._result
    
    def get_elapsed_time(self) -> int:
        """Get elapsed time in seconds since start."""
        if self._start_time:
            return int(time.time() - self._start_time)
        return 0
    
    def cancel(self) -> None:
        """
        Signal cancellation (note: cannot forcibly stop SFC process).
        The thread will complete naturally but result will be marked.
        """
        self._log('warning', "[INTG-05] SFC cancellation requested (will complete naturally)")
        # We can't forcibly stop the sfc.exe process safely
        # Just mark that we're done waiting
        self._completed.set()


class ParallelExecutor:
    """
    Main orchestrator for parallel control execution.
    Manages thread pool, background SFC, and result aggregation.
    """
    
    # Controls that should not run in parallel with others
    EXCLUSIVE_CONTROLS = {'INTG-05'}  # SFC runs in background
    
    # Default timeouts by control type
    DEFAULT_TIMEOUTS = {
        'INTG-05': 2700,  # 45 minutes for SFC
        'default': 120     # 2 minutes for most controls
    }
    
    def __init__(
        self,
        max_workers: int = 8,
        logger: Optional['GuardianLogger'] = None,
        progress_callback: Optional[Callable[['ControlResult'], None]] = None
    ):
        """
        Initialize the parallel executor.
        
        Args:
            max_workers: Maximum number of parallel worker threads (default: 8)
            logger: Optional logger instance
            progress_callback: Optional callback for progress updates
        """
        self.max_workers = max_workers
        self.logger = logger
        self.progress_callback = progress_callback
        self.results_collector = ResultCollector()
        self.sfc_task: Optional[BackgroundSFCTask] = None
        self._executor: Optional[ThreadPoolExecutor] = None
        self._start_time: Optional[float] = None
    
    def _log(self, level: str, message: str):
        """Log a message if logger is available."""
        if self.logger:
            getattr(self.logger, level.lower(), self.logger.info)(message)
    
    def _get_timeout(self, control_id: str) -> int:
        """Get the appropriate timeout for a control."""
        return self.DEFAULT_TIMEOUTS.get(control_id, self.DEFAULT_TIMEOUTS['default'])
    
    def _run_single_control(
        self,
        control: 'SecurityControl',
        dry_run: bool,
        enable_backup: bool
    ) -> 'ControlResult':
        """
        Execute a single control (called by worker threads).
        
        Args:
            control: SecurityControl to execute
            dry_run: Whether this is audit-only
            enable_backup: Whether to backup before remediation
            
        Returns:
            ControlResult from execution
        """
        timeout = self._get_timeout(control.control_id)
        
        task = ControlTask(
            control=control,
            timeout=timeout,
            dry_run=dry_run,
            enable_backup=enable_backup
        )
        
        result = task.execute()
        
        # Add to collector
        self.results_collector.add_result(result)
        
        # Fire progress callback
        if self.progress_callback:
            try:
                self.progress_callback(result)
            except Exception as e:
                self._log('debug', f"Progress callback error: {str(e)}")
        
        return result
    
    def execute_controls_parallel(
        self,
        controls: List['SecurityControl'],
        dry_run: bool = True,
        enable_backup: bool = False,
        sfc_background: bool = True,
        sfc_timeout: int = 2700
    ) -> List['ControlResult']:
        """
        Execute controls in parallel using thread pool.
        SFC (INTG-05) is optionally run in background.
        
        Args:
            controls: List of SecurityControl instances to execute
            dry_run: If True, audit only (no remediation)
            enable_backup: If True, backup state before remediation
            sfc_background: If True, run SFC in background thread
            sfc_timeout: Timeout for SFC in seconds
            
        Returns:
            List of ControlResult from all executions
        """
        self._start_time = time.time()
        self.results_collector.clear()
        
        # Separate SFC from other controls if background mode
        sfc_control = None
        regular_controls = []
        
        for ctrl in controls:
            if ctrl.control_id == 'INTG-05' and sfc_background:
                sfc_control = ctrl
            else:
                regular_controls.append(ctrl)
        
        # Start SFC in background if found
        if sfc_control:
            self._log('info', "Starting SFC (INTG-05) in background thread...")
            self.sfc_task = BackgroundSFCTask(logger=self.logger)
            self.sfc_task.start(sfc_control, timeout=sfc_timeout, dry_run=dry_run)
        
        # Execute regular controls in parallel
        if regular_controls:
            self._log('info', f"Executing {len(regular_controls)} controls with {self.max_workers} workers...")
            
            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                # Submit all control tasks
                future_to_control: Dict[Future, 'SecurityControl'] = {
                    executor.submit(
                        self._run_single_control,
                        ctrl,
                        dry_run,
                        enable_backup
                    ): ctrl
                    for ctrl in regular_controls
                }
                
                # Collect results as they complete
                for future in as_completed(future_to_control):
                    control = future_to_control[future]
                    try:
                        result = future.result(timeout=self._get_timeout(control.control_id))
                        self._log('debug', f"[{control.control_id}] Completed: {result.status.value}")
                    except FuturesTimeoutError:
                        self._log('error', f"[{control.control_id}] Execution timed out")
                    except Exception as e:
                        self._log('error', f"[{control.control_id}] Execution error: {str(e)}")
        
        # Wait for SFC if it was started
        if self.sfc_task:
            self._log('info', "Waiting for SFC background task...")
            sfc_result = self.sfc_task.wait(timeout=sfc_timeout)
            if sfc_result:
                self.results_collector.add_result(sfc_result)
                if sfc_result.status.value == "Timeout":
                    self._log('warning', "SFC timed out - marked as TIMEOUT in report")
                else:
                    self._log('info', f"SFC completed with status: {sfc_result.status.value}")
        
        elapsed = time.time() - self._start_time
        self._log('info', f"Parallel execution completed in {elapsed:.1f}s")
        
        return self.results_collector.get_results()
    
    def execute_category_parallel(
        self,
        category: str,
        controls: List['SecurityControl'],
        dry_run: bool = True,
        enable_backup: bool = False
    ) -> List['ControlResult']:
        """
        Execute all controls in a category in parallel.
        
        Args:
            category: Category name for logging
            controls: Controls in this category
            dry_run: Audit only mode
            enable_backup: Backup before remediation
            
        Returns:
            List of results for this category
        """
        if not controls:
            return []
        
        self._log('info', f"[{category}] Executing {len(controls)} controls in parallel...")
        
        category_results = []
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_control = {
                executor.submit(
                    self._run_single_control,
                    ctrl,
                    dry_run,
                    enable_backup
                ): ctrl
                for ctrl in controls
            }
            
            for future in as_completed(future_to_control):
                control = future_to_control[future]
                try:
                    result = future.result(timeout=self._get_timeout(control.control_id))
                    category_results.append(result)
                except Exception as e:
                    self._log('error', f"[{control.control_id}] Error: {str(e)}")
        
        return category_results
    
    def wait_for_sfc(self, timeout: Optional[int] = None) -> Optional['ControlResult']:
        """
        Wait for background SFC task to complete.
        
        Args:
            timeout: Maximum wait time in seconds
            
        Returns:
            SFC ControlResult or None
        """
        if self.sfc_task:
            return self.sfc_task.wait(timeout)
        return None
    
    def is_sfc_running(self) -> bool:
        """Check if SFC is still running in background."""
        return self.sfc_task is not None and self.sfc_task.is_running()
    
    def get_sfc_elapsed(self) -> int:
        """Get SFC elapsed time in seconds."""
        if self.sfc_task:
            return self.sfc_task.get_elapsed_time()
        return 0
    
    def get_total_elapsed(self) -> float:
        """Get total elapsed time since execution started."""
        if self._start_time:
            return time.time() - self._start_time
        return 0.0
