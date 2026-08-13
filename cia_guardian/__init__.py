"""
CIA-Guardian v1.0 - Windows Security Auditing and Remediation Tool
Based on the CIA Triad (Confidentiality, Integrity, Availability)
"""

__version__ = "1.0.0"
__author__ = "CIA-Guardian Team"

from .engine import GuardianEngine

__all__ = ['GuardianEngine', '__version__']
