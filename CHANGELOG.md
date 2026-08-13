# Changelog

All notable changes to CIA-Guardian will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.3.0] - 2026-02-09

### Added
- **10 new enterprise security controls** (90 -> 100 total)
  - INTG-21: Windows Exploit Protection (DEP, CFG, SEHOP, ForceRelocateImages)
  - INTG-22: Controlled Folder Access (ransomware protection)
  - INTG-23: Early Launch Anti-Malware (ELAM boot protection)
  - CONF-20: Windows LAPS (Local Administrator Password Solution)
  - CONF-21: Kerberos Armoring (FAST pre-authentication)
  - NETW-14: SMB 3.0 Encryption requirement
  - NETW-15: Firewall Advanced Logging with retention
  - AVBL-18: Backup Configuration verification
  - APPS-12: PowerShell Constrained Language Mode
  - SRVC-11: RD Gateway Requirement for RDP

### Changed
- Updated version to v2.3.0
- Enhanced banner with developer credit
- Updated help text with accurate control counts per category

### Fixed
- N/A handling for domain-specific controls on non-domain systems
- N/A handling for UEFI-specific controls on Legacy BIOS systems
- N/A handling for Defender-specific controls with third-party AV

## [2.2.0] - 2026-02-08

### Added
- **Parallel execution** for concurrent control processing
- **Background SFC** - non-blocking System File Checker
- `--skip-sfc` flag for faster execution
- Service Hardening category (SRVC-01 to SRVC-10)
- Application Security category (APPS-01 to APPS-11)
- Network Security category (NETW-01 to NETW-13)
- Extended to 90 total controls

### Changed
- Engine refactored for ThreadPoolExecutor-based parallelism
- Improved progress display with real-time status updates
- Enhanced report generation with all 6 categories

### Performance
- Full audit time reduced from ~15 minutes to ~2-5 minutes
- SFC skip mode completes in ~30 seconds

## [2.1.0] - 2026-02-07

### Added
- Extended Confidentiality controls (CONF-05 to CONF-19)
- Extended Integrity controls (INTG-06 to INTG-20)
- Extended Availability controls (AVBL-05 to AVBL-17)
- CIS Benchmark mappings for all controls
- NIST 800-53 mappings for all controls

### Changed
- Improved check/fix/verify pattern consistency
- Enhanced error handling with graceful degradation
- Better N/A status detection for unsupported configurations

## [2.0.0] - 2026-02-06

### Added
- Complete rewrite with modular architecture
- `SecurityControl` base class for consistent implementation
- Separate control modules by category
- Rich console output with progress indicators
- JSON and CSV export formats
- Verbose logging mode
- `--controls` flag for running specific controls by ID
- Custom audit mode in interactive menu

### Changed
- Migrated from single-file to package structure
- Improved HTML dashboard with Bootstrap 5
- Enhanced PDF certificate generation
- Better Windows API integration

### Removed
- Legacy single-file implementation
- Deprecated command-line options

## [1.0.0] - 2026-02-01

### Added
- Initial release
- 13 security controls across CIA Triad
- Interactive menu mode
- Command-line interface
- HTML Dashboard report
- PDF Certificate generation
- Basic Windows security auditing
- Auto-remediation capabilities

### Controls (v1.0)
- CONF-01: BitLocker Encryption
- CONF-02: SMB1 Protocol Disabled
- CONF-03: Administrative Shares
- CONF-04: SMB Signing Required
- INTG-01: Defender Real-time
- INTG-02: UAC Configuration
- INTG-03: PowerShell Execution Policy
- INTG-04: Logon Audit Policy
- INTG-05: System File Integrity
- AVBL-01: Windows Firewall
- AVBL-02: Volume Shadow Copy
- AVBL-03: Virtual Memory
- AVBL-04: Windows Time Service

---

## Version History Summary

| Version | Date | Controls | Key Features |
|---------|------|----------|--------------|
| 1.0.0 | 2026-02-01 | 13 | Initial release, CIA Triad |
| 2.0.0 | 2026-02-06 | 13 | Modular rewrite, enhanced reports |
| 2.1.0 | 2026-02-07 | 52 | Extended controls, compliance mappings |
| 2.2.0 | 2026-02-08 | 90 | Parallel execution, 6 categories |
| 2.3.0 | 2026-02-09 | 100 | Enterprise controls, LAPS, ELAM |
