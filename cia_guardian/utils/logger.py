"""
Guardian Logger Utility
Rich console + file logging with multiple verbosity levels.
"""

import logging
import os
import sys
from datetime import datetime
from typing import Optional
from pathlib import Path

try:
    from colorama import init, Fore, Style
    init(autoreset=True)
    COLORAMA_AVAILABLE = True
except ImportError:
    COLORAMA_AVAILABLE = False


class ColorFormatter(logging.Formatter):
    """Custom formatter with colored output for console."""
    
    COLORS = {
        'DEBUG': Fore.CYAN if COLORAMA_AVAILABLE else '',
        'INFO': Fore.GREEN if COLORAMA_AVAILABLE else '',
        'WARNING': Fore.YELLOW if COLORAMA_AVAILABLE else '',
        'ERROR': Fore.RED if COLORAMA_AVAILABLE else '',
        'CRITICAL': Fore.RED + Style.BRIGHT if COLORAMA_AVAILABLE else '',
    }
    RESET = Style.RESET_ALL if COLORAMA_AVAILABLE else ''
    
    def format(self, record):
        color = self.COLORS.get(record.levelname, '')
        record.levelname = f"{color}{record.levelname}{self.RESET}"
        return super().format(record)


class GuardianLogger:
    """
    CIA-Guardian Logger with rich console output and file logging.
    Supports DEBUG, INFO, WARNING, ERROR, and CRITICAL levels.
    """
    
    SYMBOLS = {
        'CHECK': '[+]' if not COLORAMA_AVAILABLE else f'{Fore.GREEN}[+]{Style.RESET_ALL}',
        'FAIL': '[-]' if not COLORAMA_AVAILABLE else f'{Fore.RED}[-]{Style.RESET_ALL}',
        'INFO': '[*]' if not COLORAMA_AVAILABLE else f'{Fore.BLUE}[*]{Style.RESET_ALL}',
        'WARN': '[!]' if not COLORAMA_AVAILABLE else f'{Fore.YELLOW}[!]{Style.RESET_ALL}',
        'WORK': '[~]' if not COLORAMA_AVAILABLE else f'{Fore.CYAN}[~]{Style.RESET_ALL}',
    }
    
    def __init__(self, name: str = "CIA-Guardian", log_dir: Optional[str] = None,
                 console_level: int = logging.INFO, file_level: int = logging.DEBUG):
        """
        Initialize the Guardian Logger.
        
        Args:
            name: Logger name
            log_dir: Directory for log files (default: ./logs/)
            console_level: Console logging level
            file_level: File logging level
        """
        self.name = name
        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.DEBUG)
        self.logger.handlers.clear()
        
        # Set up log directory
        if log_dir is None:
            log_dir = os.path.join(os.getcwd(), 'logs')
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        
        # Console handler with color
        self._console_handler = logging.StreamHandler(sys.stdout)
        self._console_handler.setLevel(console_level)
        self._console_level = console_level  # Save for restore
        console_format = ColorFormatter(
            '%(asctime)s | %(levelname)-8s | %(message)s',
            datefmt='%H:%M:%S'
        )
        self._console_handler.setFormatter(console_format)
        self.logger.addHandler(self._console_handler)
        
        # File handler
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        log_file = self.log_dir / f'cia_guardian_{timestamp}.log'
        file_handler = logging.FileHandler(log_file, encoding='utf-8')
        file_handler.setLevel(file_level)
        file_format = logging.Formatter(
            '%(asctime)s | %(levelname)-8s | %(name)s | %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        file_handler.setFormatter(file_format)
        self.logger.addHandler(file_handler)
        
        self.log_file = log_file
        self._console_suppressed = False
    
    def suppress_console(self) -> None:
        """
        Suppress console output (file logging continues).
        Used during parallel execution to prevent progress bar interference.
        """
        if not self._console_suppressed:
            self._console_handler.setLevel(logging.CRITICAL + 1)  # Above all levels
            self._console_suppressed = True
    
    def restore_console(self) -> None:
        """Restore console output to normal level."""
        if self._console_suppressed:
            self._console_handler.setLevel(self._console_level)
            self._console_suppressed = False
    
    def debug(self, message: str):
        """Log debug message."""
        self.logger.debug(message)
    
    def info(self, message: str):
        """Log info message."""
        self.logger.info(message)
    
    def warning(self, message: str):
        """Log warning message."""
        self.logger.warning(message)
    
    def error(self, message: str):
        """Log error message."""
        self.logger.error(message)
    
    def critical(self, message: str):
        """Log critical message."""
        self.logger.critical(message)
    
    def success(self, message: str):
        """Log a success message with check symbol."""
        self.logger.info(f"{self.SYMBOLS['CHECK']} {message}")
    
    def fail(self, message: str):
        """Log a failure message with fail symbol."""
        self.logger.error(f"{self.SYMBOLS['FAIL']} {message}")
    
    def status(self, message: str):
        """Log a status/info message with info symbol."""
        self.logger.info(f"{self.SYMBOLS['INFO']} {message}")
    
    def warn(self, message: str):
        """Log a warning message with warn symbol."""
        self.logger.warning(f"{self.SYMBOLS['WARN']} {message}")
    
    def working(self, message: str):
        """Log a working/in-progress message."""
        self.logger.info(f"{self.SYMBOLS['WORK']} {message}")
    
    def banner(self):
        """Print the CIA-Guardian banner."""
        banner_text = """
╔═══════════════════════════════════════════════════════════════════════════════╗
║                                                                               ║
║     ██████╗██╗ █████╗        ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗         ║
║    ██╔════╝██║██╔══██╗      ██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗        ║
║    ██║     ██║███████║█████╗██║  ███╗██║   ██║███████║██████╔╝██║  ██║        ║
║    ██║     ██║██╔══██║╚════╝██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║        ║
║    ╚██████╗██║██║  ██║      ╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝        ║
║     ╚═════╝╚═╝╚═╝  ╚═╝       ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝         ║
║                                                                               ║
║                    Windows Security Hardening Tool v1.0                       ║
║              Confidentiality | Integrity | Availability                       ║
║                                                                               ║
╚═══════════════════════════════════════════════════════════════════════════════╝
"""
        if COLORAMA_AVAILABLE:
            print(f"{Fore.CYAN}{banner_text}{Style.RESET_ALL}")
        else:
            print(banner_text)
    
    def section(self, title: str):
        """Print a section header."""
        separator = "=" * 70
        if COLORAMA_AVAILABLE:
            print(f"\n{Fore.YELLOW}{separator}")
            print(f"  {title.upper()}")
            print(f"{separator}{Style.RESET_ALL}\n")
        else:
            print(f"\n{separator}")
            print(f"  {title.upper()}")
            print(f"{separator}\n")
    
    def control_result(self, control_id: str, name: str, status: str, details: str = ""):
        """Print a formatted control result."""
        status_symbol = self.SYMBOLS['CHECK'] if status == 'Compliant' else self.SYMBOLS['FAIL']
        status_color = Fore.GREEN if status == 'Compliant' and COLORAMA_AVAILABLE else ''
        status_color = Fore.RED if status != 'Compliant' and COLORAMA_AVAILABLE else status_color
        reset = Style.RESET_ALL if COLORAMA_AVAILABLE else ''
        
        msg = f"{status_symbol} [{control_id}] {name}: {status_color}{status}{reset}"
        if details:
            msg += f" - {details}"
        print(msg)
        self.logger.info(f"[{control_id}] {name}: {status} - {details}")
