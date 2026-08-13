"""
Guardian Engine - Main Orchestrator
Coordinates all security controls, audits, and reporting.

v2.1: Parallel execution support with background SFC
"""

import os
import platform
import socket
import time
import threading
from datetime import datetime
from typing import List, Optional, Dict, Any, Set
from dataclasses import dataclass, field

from .utils.command_runner import WindowsCommandRunner
from .utils.logger import GuardianLogger
from .utils.preflight import PreflightChecker, PreflightResult
from .utils.progress import (
    ProgressIndicator, ControlProgressTracker, 
    is_long_running, get_control_timing,
    ParallelProgressReporter, ProgressStyle  # v2.1 parallel progress
)
from .utils.parallel import (
    ParallelExecutor, ResultCollector, BackgroundSFCTask, ControlTask
)
from .controls import (
    ControlResult, ControlStatus, SecurityControl,
    ConfidentialityControls, IntegrityControls, AvailabilityControls,
    NetworkControls, ApplicationSecurityControls, ServiceHardeningControls
)


@dataclass
class SystemInfo:
    """System information collected during audit."""
    hostname: str = ""
    os_name: str = ""
    os_version: str = ""
    os_build: str = ""
    architecture: str = ""
    domain: str = ""
    ip_address: str = ""
    username: str = ""
    is_admin: bool = False
    audit_timestamp: datetime = field(default_factory=datetime.now)
    
    def to_dict(self) -> dict:
        return {
            'hostname': self.hostname,
            'os_name': self.os_name,
            'os_version': self.os_version,
            'os_build': self.os_build,
            'architecture': self.architecture,
            'domain': self.domain,
            'ip_address': self.ip_address,
            'username': self.username,
            'is_admin': self.is_admin,
            'audit_timestamp': self.audit_timestamp.isoformat()
        }


@dataclass
class AuditSummary:
    """Summary of the complete audit."""
    total_controls: int = 0
    compliant: int = 0
    non_compliant: int = 0
    remediated: int = 0
    errors: int = 0
    timeouts: int = 0  # v2.1: Track TIMEOUT status separately
    not_applicable: int = 0
    security_score: float = 0.0
    compliance_percentage: float = 0.0
    letter_grade: str = "F"
    risk_summary: Dict[str, int] = field(default_factory=dict)
    category_scores: Dict[str, float] = field(default_factory=dict)
    execution_mode: str = "sequential"  # v2.1: Track parallel vs sequential
    execution_time_seconds: float = 0.0  # v2.1: Total audit duration
    
    def calculate_score(self, results: List[ControlResult]):
        """Calculate security score and compliance metrics."""
        self.total_controls = len(results)
        
        if self.total_controls == 0:
            return
        
        # Risk weights for scoring
        risk_weights = {
            'Critical': 25,
            'High': 15,
            'Medium': 10,
            'Low': 5,
            'Info': 2
        }
        
        total_weight = 0
        earned_weight = 0
        
        category_weights: Dict[str, int] = {}
        category_earned: Dict[str, int] = {}
        
        for result in results:
            risk_level = result.risk_level.value
            weight = risk_weights.get(risk_level, 5)
            total_weight += weight
            
            # Track by category
            category = result.category.value
            if category not in category_weights:
                category_weights[category] = 0
                category_earned[category] = 0
            category_weights[category] += weight
            
            # Count statuses
            if result.status == ControlStatus.COMPLIANT:
                self.compliant += 1
                earned_weight += weight
                category_earned[category] += weight
            elif result.status == ControlStatus.REMEDIATED:
                self.remediated += 1
                earned_weight += weight
                category_earned[category] += weight
            elif result.status == ControlStatus.NON_COMPLIANT:
                self.non_compliant += 1
            elif result.status == ControlStatus.TIMEOUT:
                # v2.1: TIMEOUT counts as non-compliant for scoring
                self.timeouts += 1
            elif result.status == ControlStatus.ERROR:
                self.errors += 1
            elif result.status == ControlStatus.NOT_APPLICABLE:
                self.not_applicable += 1
                # N/A controls don't count against score
                total_weight -= weight
                category_weights[category] -= weight
            
            # Risk summary - include TIMEOUT in risk tracking
            if result.status in [ControlStatus.NON_COMPLIANT, ControlStatus.ERROR, ControlStatus.TIMEOUT]:
                self.risk_summary[risk_level] = self.risk_summary.get(risk_level, 0) + 1
        
        # Calculate overall score
        if total_weight > 0:
            self.security_score = (earned_weight / total_weight) * 100
        
        # Calculate category scores
        for category, weight in category_weights.items():
            if weight > 0:
                self.category_scores[category] = (category_earned[category] / weight) * 100
        
        # Calculate compliance percentage (simple count-based)
        applicable_controls = self.total_controls - self.not_applicable
        if applicable_controls > 0:
            self.compliance_percentage = ((self.compliant + self.remediated) / applicable_controls) * 100
        
        # Assign letter grade
        self.letter_grade = self._get_letter_grade(self.security_score)
    
    def _get_letter_grade(self, score: float) -> str:
        """Convert score to letter grade."""
        if score >= 90:
            return "A"
        elif score >= 80:
            return "B"
        elif score >= 70:
            return "C"
        elif score >= 60:
            return "D"
        else:
            return "F"
    
    def to_dict(self) -> dict:
        return {
            'total_controls': self.total_controls,
            'compliant': self.compliant,
            'non_compliant': self.non_compliant,
            'remediated': self.remediated,
            'errors': self.errors,
            'timeouts': self.timeouts,  # v2.1
            'not_applicable': self.not_applicable,
            'security_score': round(self.security_score, 1),
            'compliance_percentage': round(self.compliance_percentage, 1),
            'letter_grade': self.letter_grade,
            'risk_summary': self.risk_summary,
            'category_scores': {k: round(v, 1) for k, v in self.category_scores.items()},
            'execution_mode': self.execution_mode,  # v2.1
            'execution_time_seconds': round(self.execution_time_seconds, 2)  # v2.1
        }


class GuardianEngine:
    """
    Main orchestration engine for CIA-Guardian.
    Manages all security controls and coordinates auditing/remediation.
    """
    
    def __init__(self, output_dir: str = "./reports", log_dir: str = "./logs"):
        """
        Initialize the Guardian Engine.
        
        Args:
            output_dir: Directory for report output
            log_dir: Directory for log files
        """
        self.output_dir = os.path.abspath(output_dir)
        self.log_dir = os.path.abspath(log_dir)
        
        # Create directories
        os.makedirs(self.output_dir, exist_ok=True)
        os.makedirs(self.log_dir, exist_ok=True)
        
        # Initialize components
        self.logger = GuardianLogger(log_dir=self.log_dir)
        self.runner = WindowsCommandRunner(logger=self.logger)
        self.preflight = PreflightChecker(runner=self.runner)
        
        # Initialize control groups
        self.confidentiality = ConfidentialityControls()
        self.integrity = IntegrityControls()
        self.availability = AvailabilityControls()
        self.network = NetworkControls()
        self.application = ApplicationSecurityControls()
        self.services = ServiceHardeningControls()
        
        # Set dependencies for all control groups
        self.confidentiality.initialize(self.runner, self.logger)
        self.integrity.initialize(self.runner, self.logger)
        self.availability.initialize(self.runner, self.logger)
        self.network.initialize(self.runner, self.logger)
        self.application.initialize(self.runner, self.logger)
        self.services.initialize(self.runner, self.logger)
        
        # Build control registry for individual control access
        self._control_registry: Dict[str, SecurityControl] = {}
        self._build_control_registry()
        
        # Results storage
        self.results: List[ControlResult] = []
        self.system_info: Optional[SystemInfo] = None
        self.summary: Optional[AuditSummary] = None
        self.preflight_results: List[PreflightResult] = []
        
        # Progress tracking
        self.progress_tracker: Optional[ControlProgressTracker] = None
        self.show_progress: bool = True
        
        # Backup/Rollback tracking
        self.controls_with_backups: List[str] = []
        
        self.logger.debug("GuardianEngine initialized")
    
    def _build_control_registry(self):
        """Build a registry of all controls indexed by control_id."""
        for control in self.confidentiality.get_controls():
            self._control_registry[control.control_id] = control
        for control in self.integrity.get_controls():
            self._control_registry[control.control_id] = control
        for control in self.availability.get_controls():
            self._control_registry[control.control_id] = control
        for control in self.network.get_controls():
            self._control_registry[control.control_id] = control
        for control in self.application.get_controls():
            self._control_registry[control.control_id] = control
        for control in self.services.get_controls():
            self._control_registry[control.control_id] = control
    
    def get_all_control_ids(self) -> List[str]:
        """Get list of all available control IDs."""
        return list(self._control_registry.keys())
    
    def get_control_by_id(self, control_id: str) -> Optional[SecurityControl]:
        """Get a specific control by its ID."""
        return self._control_registry.get(control_id)
    
    def get_controls_by_category(self, category: str) -> List[SecurityControl]:
        """Get all controls for a specific category."""
        category_lower = category.lower()
        if category_lower == 'confidentiality':
            return self.confidentiality.get_controls()
        elif category_lower == 'integrity':
            return self.integrity.get_controls()
        elif category_lower == 'availability':
            return self.availability.get_controls()
        elif category_lower == 'network':
            return self.network.get_controls()
        elif category_lower == 'application':
            return self.application.get_controls()
        elif category_lower in ['service', 'services']:
            return self.services.get_controls()
        return []
    
    def get_control_info(self) -> List[Dict[str, Any]]:
        """Get information about all available controls."""
        info = []
        for control_id, control in self._control_registry.items():
            info.append({
                'id': control_id,
                'name': control.name,
                'description': control.description,
                'category': control.category.value,
                'risk_level': control.risk_level.value,
                'supports_rollback': control.supports_rollback
            })
        return info
    
    def run_preflight_checks(self, print_results: bool = True) -> bool:
        """
        Run pre-flight system checks before audit.
        
        Args:
            print_results: Whether to print results to console
            
        Returns:
            True if all critical checks pass, False otherwise
        """
        self.logger.section("Pre-flight System Checks")
        
        all_passed, self.preflight_results = self.preflight.run_all_checks()
        
        if print_results:
            self.preflight.print_results()
        
        if not all_passed:
            self.logger.error("Critical pre-flight checks failed. Please resolve issues before continuing.")
        else:
            self.logger.success("All pre-flight checks passed")
        
        return all_passed
    
    def collect_system_info(self) -> SystemInfo:
        """Collect system information for the report."""
        info = SystemInfo()
        
        try:
            info.hostname = socket.gethostname()
            info.os_name = platform.system()
            info.os_version = platform.version()
            info.os_build = platform.win32_ver()[1] if hasattr(platform, 'win32_ver') else ""
            info.architecture = platform.machine()
            info.username = os.environ.get('USERNAME', 'Unknown')
            info.domain = os.environ.get('USERDOMAIN', 'Unknown')
            
            # Get IP address
            try:
                info.ip_address = socket.gethostbyname(socket.gethostname())
            except socket.error:
                info.ip_address = "Unknown"
            
            # Check admin status
            info.is_admin = self.runner.is_admin()
            
            # Get detailed Windows version
            ver_result = self.runner.run_cmd('ver')
            if ver_result.success:
                info.os_build = ver_result.stdout.strip()
            
        except Exception as e:
            self.logger.error(f"Error collecting system info: {str(e)}")
        
        self.system_info = info
        return info
    
    def run_audit(
        self, 
        dry_run: bool = False, 
        categories: Optional[List[str]] = None,
        control_ids: Optional[List[str]] = None,
        skip_preflight: bool = False,
        enable_backup: bool = True,
        show_progress: bool = True,
        skip_long_running: bool = False,
        # v2.1 Parallel execution parameters
        parallel: bool = True,
        max_workers: int = 8,
        sfc_background: bool = True,
        sfc_timeout: int = 2700,
        skip_sfc: bool = False,
        progress_style: Optional[str] = None  # v2.1: box|simple|minimal|ascii|auto
    ) -> List[ControlResult]:
        """
        Run the complete security audit.
        
        Args:
            dry_run: If True, only audit without remediation
            categories: List of categories to audit (default: all)
            control_ids: Specific control IDs to audit (overrides categories if provided)
            skip_preflight: Skip pre-flight checks
            enable_backup: Enable backup before remediation (for rollback support)
            show_progress: Show progress indicator for long-running operations
            skip_long_running: Skip long-running controls like SFC (INTG-05)
            parallel: If True, run controls in parallel (v2.1, default: True)
            max_workers: Number of parallel worker threads (v2.1, default: 8)
            sfc_background: If True, run SFC in background thread (v2.1, default: True)
            sfc_timeout: SFC timeout in seconds (v2.1, default: 2700 = 45 min)
            skip_sfc: If True, skip SFC control (INTG-05) entirely (v2.1)
            progress_style: Progress display style (v2.1): box|simple|minimal|ascii|auto
            
        Returns:
            List of ControlResult objects
        """
        self.logger.banner()
        self.show_progress = show_progress
        self._skip_long_running = skip_long_running
        self._audit_start_time = time.time()
        
        # Run pre-flight checks unless skipped
        if not skip_preflight:
            preflight_passed = self.run_preflight_checks()
            if not preflight_passed:
                self.logger.warn("Continuing despite pre-flight check failures...")
        
        self.logger.section("System Information Collection")
        
        # Collect system info
        self.collect_system_info()
        if self.system_info:
            self.logger.info(f"Hostname: {self.system_info.hostname}")
            self.logger.info(f"OS: {self.system_info.os_name} {self.system_info.os_version}")
            self.logger.info(f"User: {self.system_info.domain}\\{self.system_info.username}")
            self.logger.info(f"Administrator: {'Yes' if self.system_info.is_admin else 'No'}")
            
            if not self.system_info.is_admin:
                self.logger.warn("Running without administrator privileges - some checks may fail")
        
        # Clear previous results
        self.results = []
        self.controls_with_backups = []
        
        # Determine which controls to run
        controls_to_run: List[SecurityControl] = []
        
        if control_ids:
            # Individual control selection mode
            for cid in control_ids:
                control = self.get_control_by_id(cid)
                if control:
                    controls_to_run.append(control)
                else:
                    self.logger.warn(f"Unknown control ID: {cid}")
        else:
            # Category-based selection (default)
            if categories is None:
                categories = ['confidentiality', 'integrity', 'availability', 'network', 'application', 'services']
            
            for category in categories:
                controls_to_run.extend(self.get_controls_by_category(category))
        
        if not controls_to_run:
            self.logger.error("No controls selected for audit")
            return self.results
        
        # v2.1: Filter out SFC control if skip_sfc is True
        if skip_sfc:
            original_count = len(controls_to_run)
            controls_to_run = [c for c in controls_to_run if c.control_id != 'INTG-05']
            if len(controls_to_run) < original_count:
                self.logger.info("Skipping SFC scan (INTG-05) as requested")
        
        mode = "DRY RUN (Audit Only)" if dry_run else "FULL AUDIT + REMEDIATION"
        exec_mode = "parallel" if parallel else "sequential"
        self.logger.status(f"Mode: {mode}")
        self.logger.info(f"Controls to audit: {len(controls_to_run)}")
        self.logger.info(f"Execution: {exec_mode} ({max_workers} workers)" if parallel else f"Execution: {exec_mode}")
        
        if enable_backup and not dry_run:
            self.logger.info("Backup enabled: Settings will be backed up before remediation")
        
        if sfc_background and parallel and not skip_sfc:
            self.logger.info(f"SFC (INTG-05) will run in background with {sfc_timeout//60} min timeout")
        
        # v2.1: Choose execution mode
        if parallel and dry_run:
            # Parallel audit mode (safe for read-only operations)
            self.results = self._run_parallel_audit(
                controls_to_run,
                dry_run=dry_run,
                enable_backup=enable_backup,
                max_workers=max_workers,
                sfc_background=sfc_background,
                sfc_timeout=sfc_timeout,
                show_progress=show_progress,
                progress_style=progress_style  # v2.1: Pass style to reporter
            )
        else:
            # Sequential mode (default for remediation, or when --sequential flag used)
            if not dry_run and parallel:
                self.logger.info("Note: Using sequential execution for remediation (safer)")
            self.results = self._run_sequential_audit(
                controls_to_run,
                dry_run=dry_run,
                enable_backup=enable_backup,
                show_progress=show_progress
            )
        
        # Calculate execution time
        execution_time = time.time() - self._audit_start_time
        
        # Calculate summary
        self.summary = AuditSummary()
        self.summary.calculate_score(self.results)
        self.summary.execution_mode = exec_mode
        self.summary.execution_time_seconds = execution_time
        
        # Print summary
        self._print_audit_summary()
        
        # Show rollback information if backups were created
        if self.controls_with_backups:
            self.logger.info(f"Backups available for rollback: {', '.join(self.controls_with_backups)}")
        
        return self.results
    
    def _run_parallel_audit(
        self,
        controls: List[SecurityControl],
        dry_run: bool,
        enable_backup: bool,
        max_workers: int,
        sfc_background: bool,
        sfc_timeout: int,
        show_progress: bool,
        progress_style: Optional[str] = None  # v2.1: Progress display style
    ) -> List[ControlResult]:
        """
        Run controls in parallel using ParallelExecutor.
        
        Args:
            controls: List of controls to execute
            dry_run: Audit only mode
            enable_backup: Backup before remediation
            max_workers: Number of worker threads
            sfc_background: Run SFC in background
            sfc_timeout: SFC timeout in seconds
            show_progress: Show progress display
            progress_style: Progress style (box|simple|minimal|ascii|auto)
            
        Returns:
            List of ControlResult
        """
        self.logger.section("Parallel Security Audit")
        
        # Group controls by category for progress tracking
        controls_by_category = self._group_controls_by_category(controls)
        
        # Parse progress style to ProgressStyle enum
        style_enum = None
        if progress_style:
            style_map = {
                'box': ProgressStyle.BOX,
                'simple': ProgressStyle.SIMPLE,
                'minimal': ProgressStyle.MINIMAL,
                'ascii': ProgressStyle.ASCII,
                'auto': ProgressStyle.AUTO
            }
            style_enum = style_map.get(progress_style.lower())
        
        # Initialize parallel progress reporter if showing progress
        parallel_reporter = None
        if show_progress:
            parallel_reporter = ParallelProgressReporter(
                style=style_enum,  # v2.1: Pass style to reporter
                bar_width=20,
                update_interval=0.5,  # 500ms debounce (approved)
                use_colors=True
            )
            parallel_reporter.initialize(controls_by_category)
            
            # v2.1: Suppress logger console output during parallel execution
            # Progress bars will be the only visual feedback (clean CISO dashboard)
            # File logging continues normally
            self.logger.suppress_console()
            
            parallel_reporter.start()
        
        # Progress callback to update the reporter
        # v2.1: Logger console already suppressed - results logged to file only
        def on_control_complete(result: ControlResult):
            if parallel_reporter:
                parallel_reporter.complete_control(result)
            # Track backups
            control = self.get_control_by_id(result.control_id)
            if control and control.has_backup:
                self.controls_with_backups.append(result.control_id)
        
        # Create executor
        executor = ParallelExecutor(
            max_workers=max_workers,
            logger=self.logger,
            progress_callback=on_control_complete
        )
        
        # v2.1: Background thread to periodically update SFC elapsed time
        sfc_update_stop = threading.Event()
        
        def sfc_timer_updater():
            """Update SFC elapsed time every 500ms while it's running."""
            while not sfc_update_stop.is_set():
                if parallel_reporter and executor.is_sfc_running():
                    parallel_reporter.update_sfc_status(
                        "running",
                        elapsed_seconds=executor.get_sfc_elapsed()
                    )
                sfc_update_stop.wait(0.5)  # Update every 500ms
        
        sfc_timer_thread = None
        if parallel_reporter and sfc_background:
            sfc_timer_thread = threading.Thread(
                target=sfc_timer_updater,
                name="SFC-Timer-Updater",
                daemon=True
            )
            sfc_timer_thread.start()
        
        # Execute all controls
        results = executor.execute_controls_parallel(
            controls=controls,
            dry_run=dry_run,
            enable_backup=enable_backup,
            sfc_background=sfc_background,
            sfc_timeout=sfc_timeout
        )
        
        # Stop SFC timer updater
        if sfc_timer_thread:
            sfc_update_stop.set()
            sfc_timer_thread.join(timeout=1.0)
        
        # Stop progress reporter
        if parallel_reporter:
            # Update final SFC status
            if executor.sfc_task:
                sfc_result = executor.sfc_task.get_result()
                if sfc_result:
                    status = "done" if sfc_result.status.value != "Timeout" else "timeout"
                    parallel_reporter.update_sfc_status(
                        status,
                        elapsed_seconds=executor.get_sfc_elapsed(),
                        result_status=sfc_result.status.value
                    )
            parallel_reporter.stop()
            
            # v2.1: Restore logger console output after parallel execution
            self.logger.restore_console()
        
        return results
    
    def _run_sequential_audit(
        self,
        controls: List[SecurityControl],
        dry_run: bool,
        enable_backup: bool,
        show_progress: bool
    ) -> List[ControlResult]:
        """
        Run controls sequentially (original behavior).
        
        Args:
            controls: List of controls to execute
            dry_run: Audit only mode
            enable_backup: Backup before remediation
            show_progress: Show progress indicators
            
        Returns:
            List of ControlResult
        """
        results = []
        
        # Initialize progress tracker
        if show_progress:
            self.progress_tracker = ControlProgressTracker(len(controls))
        
        # Group controls by category for organized output
        current_category = None
        
        for control in controls:
            # Print category header when it changes
            if control.category.value != current_category:
                current_category = control.category.value
                self.logger.section(f"{current_category} Controls")
            
            try:
                # Check if this is a long-running control
                timing_info = get_control_timing(control.control_id)
                is_long = is_long_running(control.control_id)
                
                # Skip long-running controls if requested
                if is_long and self._skip_long_running:
                    self.logger.info(f"[{control.control_id}] Skipping long-running control: {control.name}")
                    # Create a skipped result
                    skipped_result = ControlResult(
                        control_id=control.control_id,
                        name=control.name,
                        category=control.category,
                        status=ControlStatus.NOT_APPLICABLE,
                        risk_level=control.risk_level,
                        evidence="Skipped due to --skip-long-running flag",
                        details=f"This control typically takes {timing_info.get('estimated_seconds', 300)//60}+ minutes"
                    )
                    results.append(skipped_result)
                    if self.progress_tracker:
                        self.progress_tracker.finish_control(skipped_result.status.value, skipped_result.evidence)
                    continue
                
                # Start progress tracking for this control
                if self.progress_tracker:
                    self.progress_tracker.start_control(
                        control.control_id,
                        control.name,
                        has_long_operation=is_long,
                        estimated_seconds=timing_info.get('estimated_seconds', 0)
                    )
                
                # Show warning for long-running controls
                if is_long and not dry_run:
                    self.logger.warn(
                        f"[{control.control_id}] {timing_info.get('description', 'This may take several minutes')}"
                    )
                
                # Run the control
                result = control.check_fix_verify(dry_run=dry_run, enable_backup=enable_backup)
                results.append(result)
                
                # Track which controls have backups
                if control.has_backup:
                    self.controls_with_backups.append(control.control_id)
                
                # Finish progress for this control
                if self.progress_tracker:
                    self.progress_tracker.finish_control(
                        result.status.value,
                        result.evidence
                    )
                
                # Log result
                self.logger.control_result(
                    result.control_id, result.name,
                    result.status.value, result.evidence
                )
                
            except Exception as e:
                self.logger.error(f"Error in {control.control_id}: {str(e)}")
                if self.progress_tracker:
                    self.progress_tracker.finish_control("Error", str(e))
        
        # Finish overall progress tracking
        if self.progress_tracker:
            self.progress_tracker.finish_audit()
        
        return results
    
    def _group_controls_by_category(self, controls: List[SecurityControl]) -> Dict[str, List[SecurityControl]]:
        """
        Group controls by their category.
        
        Args:
            controls: List of controls to group
            
        Returns:
            Dictionary mapping category name to list of controls
        """
        grouped: Dict[str, List[SecurityControl]] = {}
        for control in controls:
            category = control.category.value
            if category not in grouped:
                grouped[category] = []
            grouped[category].append(control)
        return grouped
    
    def _print_audit_summary(self):
        """Print the audit summary to console."""
        if not self.summary:
            return
        
        self.logger.section("Audit Summary")
        self.logger.info(f"Total Controls: {self.summary.total_controls}")
        self.logger.success(f"Compliant: {self.summary.compliant}")
        if self.summary.remediated > 0:
            self.logger.success(f"Remediated: {self.summary.remediated}")
        if self.summary.non_compliant > 0:
            self.logger.fail(f"Non-Compliant: {self.summary.non_compliant}")
        if self.summary.timeouts > 0:
            self.logger.warn(f"Timeouts: {self.summary.timeouts}")
        if self.summary.errors > 0:
            self.logger.warn(f"Errors: {self.summary.errors}")
        if self.summary.not_applicable > 0:
            self.logger.status(f"Not Applicable: {self.summary.not_applicable}")
        
        self.logger.info(f"Security Score: {self.summary.security_score:.1f}% (Grade: {self.summary.letter_grade})")
        self.logger.info(f"Compliance: {self.summary.compliance_percentage:.1f}%")
        
        # v2.1: Show execution info
        if self.summary.execution_time_seconds > 0:
            exec_time = self.summary.execution_time_seconds
            if exec_time >= 60:
                self.logger.info(f"Execution Time: {exec_time/60:.1f} minutes ({self.summary.execution_mode} mode)")
            else:
                self.logger.info(f"Execution Time: {exec_time:.1f} seconds ({self.summary.execution_mode} mode)")
    
    def rollback_control(self, control_id: str) -> bool:
        """
        Rollback a specific control to its pre-remediation state.
        
        Args:
            control_id: The control ID to rollback
            
        Returns:
            True if rollback successful, False otherwise
        """
        control = self.get_control_by_id(control_id)
        if not control:
            self.logger.error(f"Unknown control ID: {control_id}")
            return False
        
        if not control.has_backup:
            self.logger.error(f"No backup available for {control_id}")
            return False
        
        self.logger.info(f"Rolling back {control_id}: {control.name}...")
        
        success = control.rollback()
        
        if success:
            self.logger.success(f"Rollback successful for {control_id}")
            if control_id in self.controls_with_backups:
                self.controls_with_backups.remove(control_id)
        else:
            self.logger.error(f"Rollback failed for {control_id}")
        
        return success
    
    def rollback_all(self) -> Dict[str, bool]:
        """
        Rollback all controls that have backups.
        
        Returns:
            Dictionary of control_id: success status
        """
        results = {}
        
        if not self.controls_with_backups:
            self.logger.info("No backups available for rollback")
            return results
        
        self.logger.section("Rolling Back Changes")
        
        for control_id in list(self.controls_with_backups):
            results[control_id] = self.rollback_control(control_id)
        
        # Summary
        success_count = sum(1 for v in results.values() if v)
        fail_count = len(results) - success_count
        
        self.logger.info(f"Rollback complete: {success_count} successful, {fail_count} failed")
        
        return results
    
    def get_rollback_info(self) -> List[Dict[str, Any]]:
        """Get information about available rollbacks."""
        info = []
        for control_id in self.controls_with_backups:
            control = self.get_control_by_id(control_id)
            if control and control.has_backup:
                backup_info = control.get_backup_info()
                if backup_info:
                    info.append({
                        'control_id': control_id,
                        'name': control.name,
                        'backup_timestamp': backup_info.get('timestamp'),
                        'description': backup_info.get('description')
                    })
        return info
    
    def get_audit_data(self) -> Dict[str, Any]:
        """Get complete audit data for reporting."""
        return {
            'system_info': self.system_info.to_dict() if self.system_info else {},
            'summary': self.summary.to_dict() if self.summary else {},
            'results': [r.to_dict() for r in self.results],
            'preflight_results': [
                {
                    'name': r.name,
                    'passed': r.passed,
                    'message': r.message,
                    'details': r.details,
                    'is_critical': r.is_critical
                } for r in self.preflight_results
            ],
            'generated_at': datetime.now().isoformat(),
            'tool_version': '1.0.0'
        }
    
    def generate_reports(self, formats: Optional[List[str]] = None) -> Dict[str, str]:
        """
        Generate reports in specified formats.
        
        Args:
            formats: List of formats ['html', 'pdf', 'json', 'csv']
            
        Returns:
            Dictionary of format: filepath
        """
        from .reporter import HTMLDashboard, PDFCertificate
        import json
        import csv
        
        if formats is None:
            formats = ['html', 'pdf']
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        generated_files = {}
        
        audit_data = self.get_audit_data()
        
        self.logger.section("Generating Reports")
        
        # HTML Dashboard
        if 'html' in formats:
            try:
                html_path = os.path.join(self.output_dir, f'cia_guardian_report_{timestamp}.html')
                dashboard = HTMLDashboard()
                dashboard.generate(audit_data, html_path)
                generated_files['html'] = html_path
                self.logger.success(f"HTML Report: {html_path}")
            except Exception as e:
                self.logger.error(f"HTML generation failed: {str(e)}")
        
        # PDF Certificate
        if 'pdf' in formats:
            try:
                pdf_path = os.path.join(self.output_dir, f'cia_guardian_certificate_{timestamp}.pdf')
                certificate = PDFCertificate()
                certificate.generate(audit_data, pdf_path)
                generated_files['pdf'] = pdf_path
                self.logger.success(f"PDF Certificate: {pdf_path}")
            except Exception as e:
                self.logger.error(f"PDF generation failed: {str(e)}")
        
        # JSON Export
        if 'json' in formats:
            try:
                json_path = os.path.join(self.output_dir, f'cia_guardian_data_{timestamp}.json')
                with open(json_path, 'w', encoding='utf-8') as f:
                    json.dump(audit_data, f, indent=2, default=str)
                generated_files['json'] = json_path
                self.logger.success(f"JSON Export: {json_path}")
            except Exception as e:
                self.logger.error(f"JSON export failed: {str(e)}")
        
        # CSV Export
        if 'csv' in formats:
            try:
                csv_path = os.path.join(self.output_dir, f'cia_guardian_results_{timestamp}.csv')
                with open(csv_path, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    writer.writerow([
                        'Control ID', 'Name', 'Category', 'Risk Level',
                        'Status', 'Evidence', 'Initial State', 'Post-Fix State',
                        'Remediation Applied', 'Timestamp'
                    ])
                    for result in self.results:
                        writer.writerow([
                            result.control_id, result.name, result.category.value,
                            result.risk_level.value, result.status.value,
                            result.evidence, result.initial_state or '',
                            result.post_fix_state or '', result.remediation_applied,
                            result.timestamp.isoformat()
                        ])
                generated_files['csv'] = csv_path
                self.logger.success(f"CSV Export: {csv_path}")
            except Exception as e:
                self.logger.error(f"CSV export failed: {str(e)}")
        
        return generated_files
