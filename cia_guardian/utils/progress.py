"""
Progress Indicator Module
Provides visual progress feedback for long-running operations.

v2.1 Additions:
- ParallelProgressReporter for category-based parallel progress bars
- Thread-safe progress updates with single writer thread
- Background SFC status tracking
"""

import sys
import time
import threading
import queue
from typing import Optional, Callable, Dict, List, Any
from dataclasses import dataclass, field
from datetime import datetime, timedelta

# Import ControlResult type for type hints (avoid circular import)
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from ..controls.base import ControlResult, ControlStatus


@dataclass
class ProgressState:
    """Current state of progress indicator."""
    current: int = 0
    total: int = 100
    message: str = ""
    start_time: Optional[datetime] = None
    is_running: bool = False
    is_indeterminate: bool = False


class ProgressIndicator:
    """
    Progress indicator for long-running operations.
    Supports both determinate (with percentage) and indeterminate (spinner) modes.
    """
    
    # Progress bar characters
    FILLED = "\u2588"  # Full block
    EMPTY = "\u2591"   # Light shade
    SPINNER_CHARS = ["|", "/", "-", "\\"]
    
    def __init__(self, total: int = 100, width: int = 30, show_eta: bool = True):
        """
        Initialize progress indicator.
        
        Args:
            total: Total number of steps (100 for percentage)
            width: Width of progress bar in characters
            show_eta: Whether to show estimated time remaining
        """
        self.total = total
        self.width = width
        self.show_eta = show_eta
        
        self.state = ProgressState()
        self._lock = threading.Lock()
        self._spinner_thread: Optional[threading.Thread] = None
        self._stop_spinner = threading.Event()
        self._last_output_length = 0
    
    def start(self, message: str = "Processing...", indeterminate: bool = False):
        """
        Start the progress indicator.
        
        Args:
            message: Message to display with progress
            indeterminate: If True, show spinner instead of progress bar
        """
        with self._lock:
            self.state = ProgressState(
                current=0,
                total=self.total,
                message=message,
                start_time=datetime.now(),
                is_running=True,
                is_indeterminate=indeterminate
            )
        
        if indeterminate:
            self._start_spinner()
        else:
            self._render()
    
    def update(self, current: Optional[int] = None, message: Optional[str] = None, 
               increment: int = 0):
        """
        Update progress.
        
        Args:
            current: Set current progress value
            message: Update message
            increment: Increment current by this amount
        """
        with self._lock:
            if current is not None:
                self.state.current = min(current, self.state.total)
            elif increment:
                self.state.current = min(self.state.current + increment, self.state.total)
            
            if message is not None:
                self.state.message = message
        
        if not self.state.is_indeterminate:
            self._render()
    
    def finish(self, message: Optional[str] = None, success: bool = True):
        """
        Finish the progress indicator.
        
        Args:
            message: Final message to display
            success: Whether operation completed successfully
        """
        # Stop spinner if running
        if self._spinner_thread and self._spinner_thread.is_alive():
            self._stop_spinner.set()
            self._spinner_thread.join(timeout=1.0)
        
        with self._lock:
            self.state.is_running = False
            self.state.current = self.state.total
            if message:
                self.state.message = message
        
        # Clear the progress line and print final message
        self._clear_line()
        
        status = "[DONE]" if success else "[FAIL]"
        final_msg = message or self.state.message
        elapsed = self._get_elapsed_str()
        
        print(f"\r  {status} {final_msg} ({elapsed})")
    
    def _render(self):
        """Render the progress bar to console."""
        if not self.state.is_running:
            return
        
        with self._lock:
            # Calculate percentage
            if self.state.total > 0:
                percentage = (self.state.current / self.state.total) * 100
            else:
                percentage = 0
            
            # Build progress bar
            filled_width = int(self.width * self.state.current / max(self.state.total, 1))
            empty_width = self.width - filled_width
            bar = self.FILLED * filled_width + self.EMPTY * empty_width
            
            # Calculate ETA
            eta_str = ""
            if self.show_eta and self.state.start_time and self.state.current > 0:
                elapsed = (datetime.now() - self.state.start_time).total_seconds()
                if self.state.current < self.state.total:
                    remaining = (elapsed / self.state.current) * (self.state.total - self.state.current)
                    eta_str = f" ETA: {self._format_time(remaining)}"
                else:
                    eta_str = f" ({self._format_time(elapsed)})"
            
            # Build output line
            output = f"\r  [{bar}] {percentage:5.1f}% {self.state.message}{eta_str}"
            
            # Pad with spaces to clear previous content
            if len(output) < self._last_output_length:
                output += " " * (self._last_output_length - len(output))
            
            self._last_output_length = len(output)
            
            # Print without newline
            sys.stdout.write(output)
            sys.stdout.flush()
    
    def _start_spinner(self):
        """Start the indeterminate spinner in a background thread."""
        self._stop_spinner.clear()
        self._spinner_thread = threading.Thread(target=self._spinner_loop, daemon=True)
        self._spinner_thread.start()
    
    def _spinner_loop(self):
        """Background thread loop for spinner animation."""
        spinner_idx = 0
        
        while not self._stop_spinner.is_set():
            with self._lock:
                if not self.state.is_running:
                    break
                
                char = self.SPINNER_CHARS[spinner_idx % len(self.SPINNER_CHARS)]
                elapsed = self._get_elapsed_str()
                
                output = f"\r  [{char}] {self.state.message} ({elapsed})"
                
                if len(output) < self._last_output_length:
                    output += " " * (self._last_output_length - len(output))
                
                self._last_output_length = len(output)
                
                sys.stdout.write(output)
                sys.stdout.flush()
            
            spinner_idx += 1
            time.sleep(0.2)
    
    def _get_elapsed_str(self) -> str:
        """Get formatted elapsed time string."""
        if self.state.start_time:
            elapsed = (datetime.now() - self.state.start_time).total_seconds()
            return self._format_time(elapsed)
        return "0:00"
    
    def _format_time(self, seconds: float) -> str:
        """Format seconds into MM:SS or H:MM:SS."""
        seconds = int(seconds)
        if seconds < 3600:
            return f"{seconds // 60}:{seconds % 60:02d}"
        else:
            hours = seconds // 3600
            minutes = (seconds % 3600) // 60
            secs = seconds % 60
            return f"{hours}:{minutes:02d}:{secs:02d}"
    
    def _clear_line(self):
        """Clear the current line."""
        sys.stdout.write("\r" + " " * self._last_output_length + "\r")
        sys.stdout.flush()


class ControlProgressTracker:
    """
    Track progress across multiple security controls.
    Provides overall audit progress and per-control status.
    """
    
    def __init__(self, total_controls: int):
        """
        Initialize control progress tracker.
        
        Args:
            total_controls: Total number of controls to audit
        """
        self.total_controls = total_controls
        self.current_control = 0
        self.control_progress = ProgressIndicator(total=total_controls, width=25)
        self.operation_progress: Optional[ProgressIndicator] = None
        self.start_time = datetime.now()
    
    def start_audit(self):
        """Start tracking the overall audit."""
        self.start_time = datetime.now()
        print("\n  Auditing security controls...")
        self.control_progress.start(
            f"Controls: 0/{self.total_controls}",
            indeterminate=False
        )
    
    def start_control(self, control_id: str, control_name: str, 
                      has_long_operation: bool = False,
                      estimated_seconds: int = 0):
        """
        Start tracking a specific control.
        
        Args:
            control_id: Control identifier (e.g., CONF-01)
            control_name: Human-readable control name
            has_long_operation: Whether this control has a long-running operation
            estimated_seconds: Estimated time for completion
        """
        self.current_control += 1
        
        # Update overall progress
        self.control_progress.update(
            current=self.current_control - 1,
            message=f"[{control_id}] {control_name}"
        )
        
        # Create operation progress if this is a long operation
        if has_long_operation:
            self.operation_progress = ProgressIndicator(
                total=100,
                width=20,
                show_eta=True
            )
            # Estimate based on provided seconds
            if estimated_seconds > 0:
                self.operation_progress.start(
                    f"{control_name} (est. {estimated_seconds // 60}:{estimated_seconds % 60:02d})",
                    indeterminate=True
                )
            else:
                self.operation_progress.start(control_name, indeterminate=True)
    
    def update_operation(self, percentage: int = 0, message: str = ""):
        """Update the current operation progress."""
        if self.operation_progress:
            self.operation_progress.update(current=percentage, message=message)
    
    def finish_control(self, status: str, evidence: str = ""):
        """
        Mark the current control as finished.
        
        Args:
            status: Status string (Compliant, Non-Compliant, etc.)
            evidence: Brief evidence message
        """
        # Finish operation progress if active
        if self.operation_progress:
            self.operation_progress.finish(success=(status in ["Compliant", "Remediated"]))
            self.operation_progress = None
        
        # Update overall progress
        self.control_progress.update(
            current=self.current_control,
            message=f"Controls: {self.current_control}/{self.total_controls}"
        )
    
    def finish_audit(self):
        """Finish the overall audit tracking."""
        self.control_progress.finish(
            f"Completed {self.total_controls} controls",
            success=True
        )


# Long-running control configuration
LONG_RUNNING_CONTROLS = {
    'INTG-05': {
        'name': 'System File Integrity (SFC)',
        'estimated_seconds': 1200,  # 20 minutes typical, can be 30+ on slow/large systems
        'description': 'SFC scan can take 15-30+ minutes depending on disk speed and system size'
    }
}


def get_control_timing(control_id: str) -> dict:
    """
    Get timing information for a control.
    
    Args:
        control_id: Control identifier
        
    Returns:
        Dictionary with timing info or empty dict if not a long-running control
    """
    return LONG_RUNNING_CONTROLS.get(control_id, {})


def is_long_running(control_id: str) -> bool:
    """Check if a control is known to be long-running."""
    return control_id in LONG_RUNNING_CONTROLS


# =============================================================================
# v2.1 Parallel Progress Reporting - Enterprise UX
# =============================================================================

from enum import Enum
import os


class ProgressStyle(Enum):
    """Progress display style options."""
    BOX = "box"         # ╭╮╰╯ Unicode box drawing
    SIMPLE = "simple"   # Plain lines, Unicode bars ████
    MINIMAL = "minimal" # Single line compact
    ASCII = "ascii"     # +--+ ASCII fallback for legacy CMD
    AUTO = "auto"       # Auto-detect terminal capabilities


# Character sets for different terminal capabilities
UNICODE_CHARS = {
    'bar_filled': '█',
    'bar_empty': '░',
    'check': '✓',
    'cross': '✗',
    'clock': '⧗',
    'spinner': ['◐', '◓', '◑', '◒'],
    'box_tl': '╭', 'box_tr': '╮',
    'box_bl': '╰', 'box_br': '╯',
    'box_h': '─', 'box_v': '│',
}

ASCII_CHARS = {
    'bar_filled': '#',
    'bar_empty': '-',
    'check': '*',
    'cross': 'X',
    'clock': '@',
    'spinner': ['|', '/', '-', '\\'],
    'box_tl': '+', 'box_tr': '+',
    'box_bl': '+', 'box_br': '+',
    'box_h': '-', 'box_v': '|',
}

# ANSI color codes
ANSI_COLORS = {
    'reset': '\033[0m',
    'green': '\033[32m',
    'red': '\033[31m',
    'orange': '\033[33m',  # Actually yellow/orange
    'gray': '\033[90m',
    'bold': '\033[1m',
    'cyan': '\033[36m',
}


def enable_windows_ansi() -> bool:
    """
    Enable Windows virtual terminal processing for ANSI escape codes.
    Returns True if successful, False otherwise.
    """
    try:
        import platform
        if platform.system() != 'Windows':
            return True  # Not Windows, assume ANSI works
        
        import ctypes
        kernel32 = ctypes.windll.kernel32
        
        # Get handle to stdout
        STD_OUTPUT_HANDLE = -11
        ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
        
        handle = kernel32.GetStdHandle(STD_OUTPUT_HANDLE)
        
        # Get current mode
        mode = ctypes.c_ulong()
        kernel32.GetConsoleMode(handle, ctypes.byref(mode))
        
        # Enable virtual terminal processing
        mode.value |= ENABLE_VIRTUAL_TERMINAL_PROCESSING
        kernel32.SetConsoleMode(handle, mode)
        
        return True
    except Exception:
        return False


def detect_terminal_capabilities() -> dict:
    """
    Auto-detect terminal Unicode/ANSI support.
    
    Returns:
        dict with 'unicode', 'ansi', 'style' keys
    """
    capabilities = {
        'unicode': False,
        'ansi': False,
        'style': ProgressStyle.ASCII
    }
    
    # CRITICAL: If stdout is not a TTY (e.g., piped output), disable ANSI
    # ANSI escape codes won't work when output is piped/redirected
    try:
        if not sys.stdout.isatty():
            # Not a TTY - use minimal style with no ANSI
            capabilities['unicode'] = True  # Unicode chars are fine in files
            capabilities['ansi'] = False
            capabilities['style'] = ProgressStyle.MINIMAL
            return capabilities
    except:
        pass
    
    # Check for Windows Terminal (best support)
    if os.environ.get('WT_SESSION'):
        capabilities['unicode'] = True
        capabilities['ansi'] = True
        capabilities['style'] = ProgressStyle.BOX
        return capabilities
    
    # Check for VS Code integrated terminal
    if os.environ.get('TERM_PROGRAM') == 'vscode':
        capabilities['unicode'] = True
        capabilities['ansi'] = True
        capabilities['style'] = ProgressStyle.BOX
        return capabilities
    
    # Check for ConEmu
    if os.environ.get('ConEmuANSI') == 'ON':
        capabilities['unicode'] = True
        capabilities['ansi'] = True
        capabilities['style'] = ProgressStyle.BOX
        return capabilities
    
    # Check for modern PowerShell (PSReadLine implies modern terminal)
    if os.environ.get('PSModulePath') and 'WindowsPowerShell' not in os.environ.get('PSModulePath', ''):
        capabilities['unicode'] = True
        capabilities['ansi'] = True
        capabilities['style'] = ProgressStyle.SIMPLE
        return capabilities
    
    # Check stdout encoding for Unicode support
    try:
        if sys.stdout.encoding and 'utf' in sys.stdout.encoding.lower():
            capabilities['unicode'] = True
            capabilities['style'] = ProgressStyle.SIMPLE
    except:
        pass
    
    # Check for ANSI support via environment
    if os.environ.get('ANSICON') or os.environ.get('TERM'):
        capabilities['ansi'] = True
    
    # Windows 10+ has native ANSI support in CMD
    try:
        import platform
        if platform.system() == 'Windows':
            version = platform.version()
            # Windows 10 build 10586+ has ANSI support
            if version and int(version.split('.')[0]) >= 10:
                capabilities['ansi'] = True
    except:
        pass
    
    return capabilities


@dataclass
class CategoryProgress:
    """Progress state for a single category."""
    name: str
    total: int
    completed: int = 0
    current_controls: List[str] = field(default_factory=list)
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    compliant: int = 0
    non_compliant: int = 0
    errors: int = 0
    timeouts: int = 0
    
    @property
    def is_complete(self) -> bool:
        return self.completed >= self.total
    
    @property
    def elapsed_seconds(self) -> float:
        if not self.start_time:
            return 0.0
        end = self.end_time or datetime.now()
        return (end - self.start_time).total_seconds()
    
    @property
    def percentage(self) -> float:
        if self.total == 0:
            return 100.0
        return (self.completed / self.total) * 100


@dataclass
class SFCStatus:
    """Status of background SFC task."""
    status: str = "pending"  # pending, running, done, timeout, error
    start_time: Optional[datetime] = None
    elapsed_seconds: int = 0
    result_status: Optional[str] = None
    
    @property
    def is_running(self) -> bool:
        return self.status == "running"
    
    @property
    def is_complete(self) -> bool:
        return self.status in ("done", "timeout", "error")


class ParallelProgressReporter:
    """
    Enterprise-grade progress reporting for parallel control execution.
    
    Features:
    - Single-writer thread architecture (no spam/duplicates)
    - 500ms debounced updates (professional refresh rate)
    - Auto-detect terminal + ASCII fallback
    - ANSI colors (green ✓, orange ⧗ for SFC)
    - Animated spinners for active categories
    - Clean SFC background status display
    
    Styles:
    - BOX: Unicode box drawing (modern terminals)
    - SIMPLE: Unicode bars without borders
    - MINIMAL: Single-line compact (CI/CD friendly)
    - ASCII: Legacy CMD/PowerShell fallback
    
    Target Output (BOX style):
    ╭─────────────────────────────────────────────────────────╮
    │ CONF [████████████████████] 18/18 ✓                 0.2s│
    │ INTG [██████████████████░░] 17/18 ⧗ SFC: 12:34 elapsed │
    │ AVBL [████████████████████] 17/17 ✓                 0.1s│
    │ NETW [████████████████████] 12/12 ✓                 0.3s│
    │ APPS [████████████████████] 10/10 ✓                 0.1s│
    │ SRVC [████████████████████] 10/10 ✓                 0.2s│
    ╰─────────────────────────────────────────────────────────╯
                  Progress: 84/85 controls | Elapsed: 00:46
    """
    
    # Category abbreviations (approved)
    CATEGORY_ABBREV = {
        "Confidentiality": "CONF",
        "Integrity": "INTG",
        "Availability": "AVBL",
        "Network Security": "NETW",
        "Application Security": "APPS",
        "Service Hardening": "SRVC"
    }
    
    # Category display order
    CATEGORY_ORDER = [
        "Confidentiality",
        "Integrity", 
        "Availability",
        "Network Security",
        "Application Security",
        "Service Hardening"
    ]
    
    def __init__(
        self,
        style: Optional[ProgressStyle] = None,
        bar_width: int = 20,
        update_interval: float = 0.5,  # 500ms debounce (approved)
        use_colors: bool = True
    ):
        """
        Initialize parallel progress reporter.
        
        Args:
            style: Display style (None = auto-detect)
            bar_width: Width of progress bars in characters
            update_interval: Minimum seconds between console updates (500ms default)
            use_colors: Enable ANSI colors when supported
        """
        # Enable Windows virtual terminal processing for ANSI support
        enable_windows_ansi()
        
        # Detect terminal capabilities
        self._capabilities = detect_terminal_capabilities()
        
        # Set style (auto-detect if not specified)
        if style is None or style == ProgressStyle.AUTO:
            self._style = self._capabilities['style']
        else:
            self._style = style
        
        # Select character set based on unicode capability (not just style)
        # Unicode chars are readable in any file/terminal that supports UTF-8
        if self._capabilities.get('unicode', False) or self._style in (ProgressStyle.BOX, ProgressStyle.SIMPLE):
            self._chars = UNICODE_CHARS
        else:
            self._chars = ASCII_CHARS
        
        # Enable colors if supported and requested
        self._use_colors = use_colors and self._capabilities.get('ansi', False)
        
        self.bar_width = bar_width
        self.update_interval = update_interval
        
        # Thread safety - single writer architecture
        self._lock = threading.Lock()
        self._render_lock = threading.Lock()  # Separate lock for rendering
        self._update_queue: queue.Queue = queue.Queue(maxsize=100)
        self._writer_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._dirty = False  # Only render when state changed
        
        # Progress state
        self._categories: Dict[str, CategoryProgress] = {}
        self._sfc_status = SFCStatus()
        self._total_controls = 0
        self._completed_controls = 0
        self._start_time: Optional[datetime] = None
        self._last_render_time: float = 0
        self._spinner_idx = 0
        
        # Console state
        self._lines_printed = 0
        self._is_started = False
        self._header_printed = False
        self._first_render = True  # For cursor save/restore approach
        self._last_printed_count = -1  # Track last printed control count for non-TTY mode
    
    def _color(self, text: str, color: str) -> str:
        """Apply ANSI color to text if colors are enabled."""
        if not self._use_colors:
            return text
        return f"{ANSI_COLORS.get(color, '')}{text}{ANSI_COLORS['reset']}"
    
    def initialize(self, controls_by_category: Dict[str, List[Any]]) -> None:
        """
        Initialize progress tracking with control counts per category.
        
        Args:
            controls_by_category: Dict mapping category name to list of controls
        """
        with self._lock:
            self._categories.clear()
            self._total_controls = 0
            
            for category, controls in controls_by_category.items():
                self._categories[category] = CategoryProgress(
                    name=category,
                    total=len(controls)
                )
                self._total_controls += len(controls)
            
            self._completed_controls = 0
            self._start_time = datetime.now()
            self._sfc_status = SFCStatus()
            self._dirty = True
    
    def start(self) -> None:
        """Start the progress display and writer thread."""
        if self._is_started:
            return
        
        self._is_started = True
        self._stop_event.clear()
        self._header_printed = False
        self._first_render = True  # Reset for fresh start
        
        # Print header once
        self._print_header()
        
        # Start background writer thread (single writer)
        self._writer_thread = threading.Thread(
            target=self._writer_loop,
            name="ProgressWriter",
            daemon=True
        )
        self._writer_thread.start()
    
    def stop(self) -> None:
        """Stop the progress display."""
        if not self._is_started:
            return
        
        self._stop_event.set()
        
        if self._writer_thread and self._writer_thread.is_alive():
            self._writer_thread.join(timeout=2.0)
        
        self._is_started = False
        
        # Final render with lock
        with self._render_lock:
            self._render(final=True)
        
        # Ensure cursor is visible after we're done
        if self._capabilities.get('ansi', False):
            sys.stdout.write("\033[?25h")  # Show cursor
            sys.stdout.flush()
        
        # Print newlines after progress for clean transition to summary
        # For MINIMAL style, we need one newline (line was written with \r)
        # For BOX/SIMPLE styles, we also need a newline after the last line
        print()
        print()  # Extra blank line for visual separation
    
    def _print_header(self) -> None:
        """Print the header line once at start."""
        if self._header_printed:
            return
        
        header = "CIA-Guardian v2.1 | Parallel Audit"
        if self._style == ProgressStyle.BOX:
            print(f"\n{header}")
        elif self._style == ProgressStyle.MINIMAL:
            pass  # No header in minimal mode
        else:
            print(f"\n{header}")
        
        self._header_printed = True
    
    def start_category(self, category: str) -> None:
        """Mark a category as started."""
        with self._lock:
            if category in self._categories:
                if self._categories[category].start_time is None:
                    self._categories[category].start_time = datetime.now()
            self._dirty = True
        self._queue_update()
    
    def start_control(self, control_id: str, category: str) -> None:
        """Mark a control as currently running."""
        with self._lock:
            if category in self._categories:
                cat_progress = self._categories[category]
                if control_id not in cat_progress.current_controls:
                    cat_progress.current_controls.append(control_id)
                if cat_progress.start_time is None:
                    cat_progress.start_time = datetime.now()
            self._dirty = True
        self._queue_update()
    
    def complete_control(self, result: 'ControlResult') -> None:
        """
        Mark a control as completed with its result.
        
        Args:
            result: ControlResult from the completed control
        """
        with self._lock:
            category = result.category.value
            
            if category in self._categories:
                cat_progress = self._categories[category]
                cat_progress.completed += 1
                
                # Remove from running list
                if result.control_id in cat_progress.current_controls:
                    cat_progress.current_controls.remove(result.control_id)
                
                # Track status counts
                status_value = result.status.value
                if status_value in ("Compliant", "Remediated"):
                    cat_progress.compliant += 1
                elif status_value == "Non-Compliant":
                    cat_progress.non_compliant += 1
                elif status_value == "Timeout":
                    cat_progress.timeouts += 1
                elif status_value == "Error":
                    cat_progress.errors += 1
                
                # Check if category is complete (but not if SFC still running)
                sfc_running_in_category = (
                    category == "Integrity" and 
                    self._sfc_status.is_running
                )
                if cat_progress.completed >= cat_progress.total and not sfc_running_in_category:
                    if cat_progress.end_time is None:
                        cat_progress.end_time = datetime.now()
            
            self._completed_controls += 1
            self._dirty = True
        
        self._queue_update()
    
    def update_sfc_status(self, status: str, elapsed_seconds: int = 0, 
                          result_status: Optional[str] = None) -> None:
        """
        Update the SFC background task status.
        
        Args:
            status: "pending", "running", "done", "timeout", "error"
            elapsed_seconds: Time elapsed since SFC started
            result_status: Final status if completed
        """
        with self._lock:
            self._sfc_status.status = status
            self._sfc_status.elapsed_seconds = elapsed_seconds
            self._sfc_status.result_status = result_status
            
            if status == "running" and self._sfc_status.start_time is None:
                self._sfc_status.start_time = datetime.now()
            
            # Mark Integrity category complete when SFC finishes
            if status in ("done", "timeout", "error"):
                if "Integrity" in self._categories:
                    cat = self._categories["Integrity"]
                    if cat.completed >= cat.total and cat.end_time is None:
                        cat.end_time = datetime.now()
            
            self._dirty = True
        
        self._queue_update()
    
    def _queue_update(self) -> None:
        """Queue an update for the writer thread (non-blocking)."""
        try:
            self._update_queue.put_nowait("update")
        except queue.Full:
            pass  # Skip if queue is full
    
    def _writer_loop(self) -> None:
        """
        Single writer thread with 500ms debounce.
        Only this thread writes to console - eliminates spam/duplicates.
        """
        while not self._stop_event.is_set():
            try:
                # Wait for update signal or timeout (for spinner animation)
                try:
                    self._update_queue.get(timeout=0.2)  # 200ms for spinner
                    self._dirty = True
                except queue.Empty:
                    pass  # Timeout - check if we should render anyway
                
                # Drain queue to collapse multiple updates
                while True:
                    try:
                        self._update_queue.get_nowait()
                        self._dirty = True
                    except queue.Empty:
                        break
                
                # Rate limit: only render if 500ms since last render
                now = time.time()
                should_render = (
                    self._dirty and 
                    (now - self._last_render_time) >= self.update_interval
                )
                
                # Always render for spinner animation (every 200ms)
                if not should_render and (now - self._last_render_time) >= 0.2:
                    should_render = True
                
                if should_render:
                    with self._render_lock:
                        self._render()
                        self._last_render_time = now
                        self._dirty = False
                
            except Exception:
                pass  # Ignore errors in writer thread
    
    def _render(self, final: bool = False) -> None:
        """
        Render the progress display to console.
        
        Uses different strategies based on terminal capabilities:
        - MINIMAL style: Carriage return overwrite (most compatible)
        - BOX/SIMPLE styles: Cursor save/restore with ANSI clear-to-EOL
        - Fallback: Simple print (lines accumulate but at least shows progress)
        """
        with self._lock:
            self._spinner_idx = (self._spinner_idx + 1) % 4
            
            if self._style == ProgressStyle.MINIMAL:
                lines = self._build_minimal_display(final)
            elif self._style == ProgressStyle.BOX:
                lines = self._build_box_display(final)
            else:
                lines = self._build_simple_display(final)
        
        has_ansi = self._capabilities.get('ansi', False)
        is_tty = sys.stdout.isatty() if hasattr(sys.stdout, 'isatty') else False
        
        # MINIMAL style: Use carriage return (single line, most compatible)
        if self._style == ProgressStyle.MINIMAL:
            line = lines[0] if lines else ""
            if is_tty:
                # Real terminal - use carriage return to overwrite
                sys.stdout.write(f"\r{line:<100}")
                sys.stdout.flush()
            else:
                # Piped output - only print on significant changes (every 10 controls)
                # and avoid duplicates
                current_tens = self._completed_controls // 10
                last_tens = self._last_printed_count // 10 if self._last_printed_count >= 0 else -1
                should_print = (
                    final or 
                    self._first_render or 
                    current_tens > last_tens
                )
                if should_print:
                    print(line)
                    self._last_printed_count = self._completed_controls
                    self._first_render = False
            self._lines_printed = 1
            return
        
        # BOX/SIMPLE styles: Use cursor save/restore approach
        if has_ansi:
            # Hide cursor during update for cleaner display
            sys.stdout.write("\033[?25l")
            
            if self._first_render:
                # First render: save cursor position, then print
                sys.stdout.write("\033[s")  # Save cursor position
                self._first_render = False
            else:
                # Subsequent renders: restore to saved position
                sys.stdout.write("\033[u")  # Restore cursor position
            
            # Print all lines with clear-to-EOL to handle varying line lengths
            for i, line in enumerate(lines):
                sys.stdout.write(line)
                sys.stdout.write("\033[K")  # Clear from cursor to end of line
                if i < len(lines) - 1:
                    sys.stdout.write("\n")
            
            # Show cursor again
            sys.stdout.write("\033[?25h")
            sys.stdout.flush()
        else:
            # Non-ANSI fallback: just print (lines will accumulate)
            # Only print on significant changes to reduce spam
            if final or self._first_render or self._completed_controls % 10 == 0:
                output = "\n".join(lines)
                print(output)
                self._first_render = False
        
        self._lines_printed = len(lines)
    
    def _build_box_display(self, final: bool = False) -> List[str]:
        """Build box-style display with Unicode borders."""
        lines = []
        c = self._chars
        
        # Calculate box width
        box_width = 60
        
        # Top border
        lines.append(f"{c['box_tl']}{c['box_h'] * box_width}{c['box_tr']}")
        
        # Category lines
        for cat_name in self.CATEGORY_ORDER:
            if cat_name in self._categories:
                inner = self._format_category_line(self._categories[cat_name])
                # Pad to box width
                padded = f"{inner:<{box_width}}"
                lines.append(f"{c['box_v']}{padded}{c['box_v']}")
        
        # Bottom border
        lines.append(f"{c['box_bl']}{c['box_h'] * box_width}{c['box_br']}")
        
        # Overall progress line (outside box)
        lines.append(self._format_overall_line(final))
        
        return lines
    
    def _build_simple_display(self, final: bool = False) -> List[str]:
        """Build simple display without borders."""
        lines = []
        
        # Category lines
        for cat_name in self.CATEGORY_ORDER:
            if cat_name in self._categories:
                lines.append(self._format_category_line(self._categories[cat_name]))
        
        # Blank line
        lines.append("")
        
        # Overall progress line
        lines.append(self._format_overall_line(final))
        
        return lines
    
    def _build_minimal_display(self, final: bool = False) -> List[str]:
        """Build single-line minimal display."""
        parts = []
        
        # Category summaries
        for cat_name in self.CATEGORY_ORDER:
            if cat_name in self._categories:
                cat = self._categories[cat_name]
                abbrev = self.CATEGORY_ABBREV.get(cat_name, cat_name[:4].upper())
                
                if cat.is_complete and not (cat_name == "Integrity" and self._sfc_status.is_running):
                    status = self._color(self._chars['check'], 'green')
                    parts.append(f"{abbrev}:{cat.completed}/{cat.total}{status}")
                elif cat_name == "Integrity" and self._sfc_status.is_running:
                    elapsed = self._format_time(self._sfc_status.elapsed_seconds)
                    parts.append(f"{abbrev}:{cat.completed}/{cat.total}(SFC:{elapsed})")
                else:
                    parts.append(f"{abbrev}:{cat.completed}/{cat.total}")
        
        # Build line
        elapsed = self._format_time(
            (datetime.now() - self._start_time).total_seconds() if self._start_time else 0
        )
        
        cat_str = " ".join(parts)
        
        if final:
            return [f"Completed: {self._completed_controls}/{self._total_controls} | {cat_str} | {elapsed}"]
        else:
            return [f"Progress: {self._completed_controls}/{self._total_controls} | {cat_str} | {elapsed}"]
    
    def _format_category_line(self, cat: CategoryProgress) -> str:
        """Format a single category progress line with colors and spinner."""
        c = self._chars
        
        # Get abbreviation
        abbrev = self.CATEGORY_ABBREV.get(cat.name, cat.name[:4].upper())
        
        # Build progress bar
        filled = int(self.bar_width * cat.completed / max(cat.total, 1))
        empty = self.bar_width - filled
        bar = c['bar_filled'] * filled + c['bar_empty'] * empty
        
        # Count display
        count_str = f"{cat.completed:>2}/{cat.total}"
        
        # Status indicator with colors
        is_sfc_category = cat.name == "Integrity" and self._sfc_status.is_running
        
        if cat.is_complete and not is_sfc_category:
            # Completed - green check with time
            check = self._color(c['check'], 'green')
            elapsed = f"{cat.elapsed_seconds:.1f}s"
            status = f"{check} {elapsed:>6}"
        elif is_sfc_category:
            # SFC running - orange clock with elapsed time
            clock = self._color(c['clock'], 'orange')
            elapsed = self._format_time(self._sfc_status.elapsed_seconds)
            status = f"{clock} SFC: {elapsed} elapsed"
        elif cat.current_controls:
            # Active controls - animated spinner
            spinner = c['spinner'][self._spinner_idx]
            spinner_colored = self._color(spinner, 'cyan')
            current = cat.current_controls[0][:8] if cat.current_controls else ""
            status = f"{spinner_colored} {current}"
        else:
            # Waiting
            status = ""
        
        return f" {abbrev} [{bar}] {count_str} {status}"
    
    def _format_overall_line(self, final: bool = False) -> str:
        """Format the overall progress summary line."""
        elapsed = 0.0
        if self._start_time:
            elapsed = (datetime.now() - self._start_time).total_seconds()
        
        elapsed_str = self._format_time(elapsed)
        
        # Center the line
        if final:
            text = f"Completed: {self._completed_controls}/{self._total_controls} controls in {elapsed_str}"
        else:
            text = f"Progress: {self._completed_controls}/{self._total_controls} controls | Elapsed: {elapsed_str}"
        
        return f"          {text}"
    
    def _format_time(self, seconds: float) -> str:
        """Format seconds as MM:SS or H:MM:SS."""
        seconds = int(seconds)
        if seconds < 3600:
            return f"{seconds // 60:02d}:{seconds % 60:02d}"
        else:
            hours = seconds // 3600
            minutes = (seconds % 3600) // 60
            secs = seconds % 60
            return f"{hours}:{minutes:02d}:{secs:02d}"
    
    def _clear_lines(self) -> None:
        """Clear previously printed lines using ANSI escape codes or carriage return."""
        if self._lines_printed > 0:
            if self._capabilities.get('ansi', False):
                # ANSI method: Move cursor up and clear each line
                for _ in range(self._lines_printed):
                    sys.stdout.write("\033[A")  # Move up
                    sys.stdout.write("\033[2K")  # Clear entire line (not just to end)
                sys.stdout.write("\033[G")  # Move cursor to column 0
            else:
                # Fallback for terminals without ANSI: use carriage return
                # This only works for single-line displays
                sys.stdout.write("\r")
                # Clear with spaces for the last line only
                sys.stdout.write(" " * 80)
                sys.stdout.write("\r")
            sys.stdout.flush()
    
    def get_summary(self) -> Dict[str, Any]:
        """Get a summary of the progress state."""
        with self._lock:
            category_summaries = {}
            for name, cat in self._categories.items():
                category_summaries[name] = {
                    "total": cat.total,
                    "completed": cat.completed,
                    "compliant": cat.compliant,
                    "non_compliant": cat.non_compliant,
                    "errors": cat.errors,
                    "timeouts": cat.timeouts,
                    "elapsed_seconds": cat.elapsed_seconds
                }
            
            return {
                "total_controls": self._total_controls,
                "completed_controls": self._completed_controls,
                "categories": category_summaries,
                "sfc_status": self._sfc_status.status,
                "elapsed_seconds": (datetime.now() - self._start_time).total_seconds() if self._start_time else 0
            }

