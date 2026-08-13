"""
Windows Command Runner Utility
Handles subprocess execution with proper encoding and error handling.
"""

import subprocess
import sys
from typing import Optional, Tuple
from dataclasses import dataclass


@dataclass
class CommandResult:
    """Result of a command execution."""
    success: bool
    stdout: str
    stderr: str
    return_code: int
    command: str


class WindowsCommandRunner:
    """
    Executes Windows commands (PowerShell, CMD, WMIC) with proper error handling.
    Handles encoding issues and Access Denied gracefully.
    """
    
    ENCODINGS = ['utf-8', 'cp1252', 'latin-1', 'cp437']
    
    def __init__(self, logger=None):
        """Initialize the command runner with optional logger."""
        self.logger = logger
        self._check_platform()
    
    def _check_platform(self):
        """Ensure we're running on Windows."""
        if sys.platform != 'win32':
            raise OSError("CIA-Guardian is designed for Windows systems only.")
    
    def _decode_output(self, output: bytes) -> str:
        """Attempt to decode output with multiple encodings."""
        for encoding in self.ENCODINGS:
            try:
                return output.decode(encoding)
            except (UnicodeDecodeError, AttributeError):
                continue
        return output.decode('utf-8', errors='replace')
    
    def _log(self, level: str, message: str):
        """Log a message if logger is available."""
        if self.logger:
            getattr(self.logger, level.lower(), self.logger.info)(message)
    
    def run_cmd(self, command: str, timeout: int = 120, shell: bool = True) -> CommandResult:
        """
        Execute a CMD command.
        
        Args:
            command: The command to execute
            timeout: Command timeout in seconds
            shell: Whether to use shell execution
            
        Returns:
            CommandResult with execution details
        """
        self._log('debug', f"Executing CMD: {command}")
        
        try:
            result = subprocess.run(
                command,
                shell=shell,
                capture_output=True,
                timeout=timeout,
                creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == 'win32' else 0
            )
            
            stdout = self._decode_output(result.stdout)
            stderr = self._decode_output(result.stderr)
            
            # Check for Access Denied
            if 'Access is denied' in stdout or 'Access is denied' in stderr:
                self._log('warning', f"Access Denied for command: {command}")
            
            return CommandResult(
                success=result.returncode == 0,
                stdout=stdout.strip(),
                stderr=stderr.strip(),
                return_code=result.returncode,
                command=command
            )
            
        except subprocess.TimeoutExpired:
            self._log('error', f"Command timed out: {command}")
            return CommandResult(
                success=False,
                stdout='',
                stderr='Command timed out',
                return_code=-1,
                command=command
            )
        except Exception as e:
            self._log('error', f"Command failed: {command} - {str(e)}")
            return CommandResult(
                success=False,
                stdout='',
                stderr=str(e),
                return_code=-1,
                command=command
            )
    
    def run_powershell(self, command: str, timeout: int = 120, 
                       use_pwsh: bool = True) -> CommandResult:
        """
        Execute a PowerShell command.
        
        Args:
            command: The PowerShell command to execute
            timeout: Command timeout in seconds
            use_pwsh: Use PowerShell 7+ (pwsh) if available, fallback to powershell
            
        Returns:
            CommandResult with execution details
        """
        # Try pwsh first (PowerShell 7+), fallback to powershell (5.1)
        ps_executable = 'pwsh' if use_pwsh else 'powershell'
        
        # Build the full command
        full_command = [
            ps_executable,
            '-NoProfile',
            '-NonInteractive',
            '-ExecutionPolicy', 'Bypass',
            '-Command',
            command
        ]
        
        self._log('debug', f"Executing PowerShell: {command}")
        
        try:
            result = subprocess.run(
                full_command,
                capture_output=True,
                timeout=timeout,
                creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == 'win32' else 0
            )
            
            stdout = self._decode_output(result.stdout)
            stderr = self._decode_output(result.stderr)
            
            return CommandResult(
                success=result.returncode == 0,
                stdout=stdout.strip(),
                stderr=stderr.strip(),
                return_code=result.returncode,
                command=command
            )
            
        except FileNotFoundError:
            if use_pwsh:
                # Fallback to PowerShell 5.1
                self._log('info', "pwsh not found, falling back to powershell")
                return self.run_powershell(command, timeout, use_pwsh=False)
            else:
                self._log('error', "PowerShell not found")
                return CommandResult(
                    success=False,
                    stdout='',
                    stderr='PowerShell not found on system',
                    return_code=-1,
                    command=command
                )
        except subprocess.TimeoutExpired:
            self._log('error', f"PowerShell command timed out: {command}")
            return CommandResult(
                success=False,
                stdout='',
                stderr='Command timed out',
                return_code=-1,
                command=command
            )
        except Exception as e:
            self._log('error', f"PowerShell command failed: {command} - {str(e)}")
            return CommandResult(
                success=False,
                stdout='',
                stderr=str(e),
                return_code=-1,
                command=command
            )
    
    def run_reg_query(self, key_path: str, value_name: Optional[str] = None) -> CommandResult:
        """
        Query the Windows Registry.
        
        Args:
            key_path: The registry key path
            value_name: Optional specific value to query
            
        Returns:
            CommandResult with registry data
        """
        command = f'reg query "{key_path}"'
        if value_name:
            command += f' /v "{value_name}"'
        
        return self.run_cmd(command)
    
    def run_reg_add(self, key_path: str, value_name: str, value_type: str, 
                    value_data: str) -> CommandResult:
        """
        Add or modify a Windows Registry value.
        
        Args:
            key_path: The registry key path
            value_name: The value name to set
            value_type: The value type (REG_DWORD, REG_SZ, etc.)
            value_data: The data to set
            
        Returns:
            CommandResult with operation status
        """
        command = f'reg add "{key_path}" /v "{value_name}" /t {value_type} /d {value_data} /f'
        return self.run_cmd(command)
    
    def run_wmic(self, wmic_command: str) -> CommandResult:
        """
        Execute a WMIC command.
        
        Args:
            wmic_command: The WMIC command to execute
            
        Returns:
            CommandResult with WMIC output
        """
        full_command = f'wmic {wmic_command}'
        return self.run_cmd(full_command)
    
    def run_netsh(self, netsh_command: str) -> CommandResult:
        """
        Execute a netsh command.
        
        Args:
            netsh_command: The netsh command to execute
            
        Returns:
            CommandResult with netsh output
        """
        full_command = f'netsh {netsh_command}'
        return self.run_cmd(full_command)
    
    def run_sc(self, sc_command: str) -> CommandResult:
        """
        Execute a sc (service control) command.
        
        Args:
            sc_command: The sc command to execute
            
        Returns:
            CommandResult with sc output
        """
        full_command = f'sc {sc_command}'
        return self.run_cmd(full_command)
    
    def is_admin(self) -> bool:
        """Check if the current process has administrator privileges."""
        result = self.run_cmd('net session 2>&1')
        return 'Access is denied' not in result.stdout and 'Access is denied' not in result.stderr
