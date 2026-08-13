# CIA-Guardian v2.3

## Windows Security Hardening Tool

CIA-Guardian is a production-ready Python CLI tool that performs live Windows security auditing, automated remediation, and compliance certification. It implements **100 security controls** mapped to CIS Benchmarks and NIST 800-53, organized around the CIA Triad plus Network, Application, and Service hardening.

**Developed by:** [razzsecdev](https://github.com/razzsecdev)

## Features

- **100 Security Controls** across 6 categories
- **Parallel Execution** - Concurrent control processing for speed
- **Background SFC** - Non-blocking system file integrity checks
- **Interactive Menu Mode** - User-friendly menu-driven interface
- **Check-Fix-Verify Pattern** - Consistent remediation workflow
- **Real-time Windows Integration** - PowerShell, Registry, WMI, native APIs
- **Executive-grade Reports** - HTML Dashboard + PDF Certificate
- **Multiple Export Formats** - HTML, PDF, JSON, CSV
- **Dry-Run Mode** - Safe audit without system changes
- **Granular Control Selection** - Run specific controls or categories

## Requirements

- Windows 10/11 or Windows Server 2019+
- Python 3.11+
- Administrator privileges (for full functionality)

## Installation

```bash
# Clone the repository
git clone https://github.com/razzsecdev/CIA_GUARDIAN.git
cd CIA_GUARDIAN

# Install dependencies
pip install -r requirements.txt
```

## Quick Start

```bash
# Launch interactive menu (default)
python cia_guardian.py

# Full audit with auto-remediation (requires admin)
python cia_guardian.py --skip-sfc

# Audit only - no changes made
python cia_guardian.py --dry-run --skip-sfc

# Run specific controls
python cia_guardian.py --controls CONF-01,INTG-01,AVBL-01 --dry-run

# Run specific categories
python cia_guardian.py --categories confidentiality,integrity --dry-run
```

## Interactive Menu

When launched without arguments, CIA-Guardian presents an interactive menu:

```
+===================================================================+
|                         MAIN MENU                                 |
+===================================================================+
| [1] Full Security Audit + Auto-Remediation                        |
|     Scan all security controls and automatically fix issues.      |
|                                                                   |
| [2] Audit Only (Dry Run)                                          |
|     Scan and report without making any system changes.            |
|                                                                   |
| [3] Report Only (Quick Scan)                                      |
|     Generate reports from current system state.                   |
|                                                                   |
| [4] Custom Audit                                                  |
|     Choose specific categories, controls, and options.            |
|                                                                   |
| [5] View Security Controls                                        |
|     Display all 100 controls with descriptions.                   |
|                                                                   |
| [Q] Quit                                                          |
+===================================================================+
```

## CLI Options

| Option | Description |
|--------|-------------|
| `--interactive, -i` | Launch interactive menu mode |
| `--dry-run` | Audit only, no remediation applied |
| `--report-only` | Generate reports without full audit |
| `--output DIR` | Report output directory (default: ./reports/) |
| `--formats` | Report formats: html,pdf,json,csv (default: html,pdf) |
| `--categories` | Filter by category (see below) |
| `--controls` | Run specific controls by ID (comma-separated) |
| `--skip-sfc` | Skip SFC scan (faster execution) |
| `--verbose` | Enable verbose output |
| `--version` | Show version information |

## Security Controls (100 Total)

### Confidentiality (21 Controls)

| ID | Control | Risk | Description |
|----|---------|------|-------------|
| CONF-01 | BitLocker Encryption | Critical | Full disk encryption status |
| CONF-02 | SMB1 Protocol Disabled | High | Legacy protocol removal |
| CONF-03 | Administrative Shares | Medium | Default share security |
| CONF-04 | SMB Signing Required | High | Network traffic integrity |
| CONF-05 | Credential Guard | Critical | Virtualization-based security |
| CONF-06 | NTLM Restriction | High | Legacy auth protocol control |
| CONF-07 | LSA Protection | Critical | Credential theft prevention |
| CONF-08 | WDigest Disabled | High | Cleartext password prevention |
| CONF-09 | Cached Credentials Limit | Medium | Offline logon credential limit |
| CONF-10 | Anonymous Enumeration | Medium | SAM/Share enumeration block |
| CONF-11 | LAN Manager Hash | High | Weak hash storage prevention |
| CONF-12 | NTLMv2 Required | High | Modern auth enforcement |
| CONF-13 | Remote Registry Disabled | Medium | Remote access restriction |
| CONF-14 | AutoRun Disabled | Medium | Removable media protection |
| CONF-15 | Screen Saver Lock | Low | Physical access protection |
| CONF-16 | TPM Status | High | Hardware security module |
| CONF-17 | Secure Boot | High | Boot integrity verification |
| CONF-18 | Memory Integrity (HVCI) | High | Kernel code integrity |
| CONF-19 | Spectre/Meltdown Mitigations | High | CPU vulnerability protection |
| CONF-20 | Windows LAPS | High | Local admin password management |
| CONF-21 | Kerberos Armoring (FAST) | Medium | Kerberos pre-auth protection |

### Integrity (23 Controls)

| ID | Control | Risk | Description |
|----|---------|------|-------------|
| INTG-01 | Defender Real-time | Critical | Antimalware protection |
| INTG-02 | UAC Configuration | High | Privilege elevation control |
| INTG-03 | PowerShell Execution Policy | Medium | Script execution control |
| INTG-04 | Logon Audit Policy | High | Authentication logging |
| INTG-05 | System File Integrity | High | SFC verification |
| INTG-06 | Secure Boot UEFI | High | Firmware integrity |
| INTG-07 | Driver Signature Enforcement | High | Unsigned driver prevention |
| INTG-08 | PowerShell Logging | Medium | Script block logging |
| INTG-09 | Command Line Auditing | Medium | Process creation logging |
| INTG-10 | Object Access Auditing | Medium | File/registry audit |
| INTG-11 | Privilege Use Auditing | Medium | Sensitive privilege logging |
| INTG-12 | Policy Change Auditing | Medium | Security policy logging |
| INTG-13 | Account Management Auditing | High | User/group change logging |
| INTG-14 | Windows Event Log Config | Medium | Log size and retention |
| INTG-15 | Boot Configuration Integrity | High | BCD security |
| INTG-16 | Code Integrity Policy | High | WDAC/AppLocker status |
| INTG-17 | Device Guard | Critical | Virtualization-based code integrity |
| INTG-18 | AppLocker Configuration | High | Application whitelisting |
| INTG-19 | DLL Safe Search | Medium | DLL hijacking prevention |
| INTG-20 | Certificate Padding Check | Medium | Authenticode validation |
| INTG-21 | Exploit Protection | High | DEP, CFG, SEHOP mitigations |
| INTG-22 | Controlled Folder Access | High | Ransomware protection |
| INTG-23 | Early Launch Anti-Malware | High | ELAM boot protection |

### Availability (18 Controls)

| ID | Control | Risk | Description |
|----|---------|------|-------------|
| AVBL-01 | Windows Firewall | Critical | Network protection |
| AVBL-02 | Volume Shadow Copy | Medium | Restore point service |
| AVBL-03 | Virtual Memory | Low | Pagefile configuration |
| AVBL-04 | Windows Time Service | Medium | Time synchronization |
| AVBL-05 | Windows Update Service | Critical | Patch management |
| AVBL-06 | Automatic Updates Config | High | Update automation |
| AVBL-07 | Recovery Options | Medium | Boot recovery settings |
| AVBL-08 | System Restore | Medium | Restore point availability |
| AVBL-09 | Disk Health (SMART) | High | Storage reliability |
| AVBL-10 | Critical Services Status | High | Essential service monitoring |
| AVBL-11 | Boot Timeout Config | Low | Boot menu timing |
| AVBL-12 | Crash Dump Config | Medium | BSOD diagnostics |
| AVBL-13 | Power Settings | Low | Sleep/hibernate security |
| AVBL-14 | Network Profile | Medium | Network location awareness |
| AVBL-15 | DNS Client Config | Medium | Name resolution security |
| AVBL-16 | WSUS/WUfB Config | High | Enterprise update management |
| AVBL-17 | Delivery Optimization | Low | Update bandwidth control |
| AVBL-18 | Backup Configuration | Medium | Backup service verification |

### Network (15 Controls)

| ID | Control | Risk | Description |
|----|---------|------|-------------|
| NETW-01 | IPv6 Configuration | Medium | Protocol stack security |
| NETW-02 | Network Discovery | Medium | Discovery protocol control |
| NETW-03 | File/Printer Sharing | Medium | Share service security |
| NETW-04 | LLMNR Disabled | High | Name resolution poisoning |
| NETW-05 | NetBIOS over TCP/IP | Medium | Legacy protocol control |
| NETW-06 | WPAD Disabled | Medium | Proxy auto-discovery security |
| NETW-07 | WiFi Sense Disabled | Low | WiFi sharing control |
| NETW-08 | Hotspot 2.0 Disabled | Low | Auto-connect prevention |
| NETW-09 | Remote Desktop Security | High | RDP configuration |
| NETW-10 | WinRM Configuration | High | Remote management security |
| NETW-11 | SNMP Configuration | Medium | Management protocol security |
| NETW-12 | Telnet Client Disabled | Medium | Legacy protocol removal |
| NETW-13 | TFTP Client Disabled | Low | Trivial FTP removal |
| NETW-14 | SMB 3.0 Encryption | High | SMB traffic encryption |
| NETW-15 | Firewall Advanced Logging | Medium | Connection logging |

### Application Security (12 Controls)

| ID | Control | Risk | Description |
|----|---------|------|-------------|
| APPS-01 | Windows Script Host | Medium | Script engine control |
| APPS-02 | Office Macro Settings | High | Macro execution policy |
| APPS-03 | Adobe Reader Security | Medium | PDF reader hardening |
| APPS-04 | Browser Security (Edge) | High | Browser configuration |
| APPS-05 | Java Security | High | Java runtime control |
| APPS-06 | .NET Framework Security | Medium | Runtime hardening |
| APPS-07 | Windows Installer Config | Medium | MSI security |
| APPS-08 | Print Spooler Security | Critical | PrintNightmare mitigation |
| APPS-09 | Windows Sandbox | Low | Isolation availability |
| APPS-10 | Hyper-V Security | Medium | Hypervisor configuration |
| APPS-11 | Windows Subsystem Linux | Medium | WSL security settings |
| APPS-12 | PowerShell Constrained Language | High | PowerShell CLM enforcement |

### Service Hardening (11 Controls)

| ID | Control | Risk | Description |
|----|---------|------|-------------|
| SRVC-01 | Unnecessary Services | Medium | Attack surface reduction |
| SRVC-02 | Service Account Permissions | High | Privilege minimization |
| SRVC-03 | IIS Configuration | High | Web server hardening |
| SRVC-04 | SQL Server Security | High | Database hardening |
| SRVC-05 | DNS Server Security | High | DNS service hardening |
| SRVC-06 | DHCP Server Security | Medium | DHCP service hardening |
| SRVC-07 | Active Directory Security | Critical | AD hardening (if DC) |
| SRVC-08 | Certificate Services | High | PKI security |
| SRVC-09 | Remote Access Services | High | VPN/DirectAccess security |
| SRVC-10 | Print Server Security | Medium | Print service hardening |
| SRVC-11 | RD Gateway Requirement | Medium | RDP gateway enforcement |

## Attack Mitigations

CIA-Guardian addresses common attack vectors:

| Attack | Mitigating Controls |
|--------|---------------------|
| **Mimikatz/Credential Theft** | CONF-05, CONF-07, CONF-08, CONF-11 |
| **PrintNightmare** | APPS-08 |
| **Pass-the-Hash** | CONF-05, CONF-06, CONF-12 |
| **Ransomware** | INTG-22, AVBL-02, AVBL-08, AVBL-18 |
| **LLMNR/NBT-NS Poisoning** | NETW-04, NETW-05 |
| **Kerberoasting** | CONF-21 |
| **Boot Attacks** | CONF-17, INTG-06, INTG-23 |
| **DLL Hijacking** | INTG-19 |
| **PowerShell Attacks** | INTG-03, INTG-08, APPS-12 |
| **Lateral Movement** | CONF-02, CONF-03, NETW-09 |

## Report Examples

### HTML Dashboard
- Executive Summary with Security Score (A-F grade)
- Risk Heatmap and Compliance Percentage
- CIA Triad + Extended Category Breakdown
- Control-by-control details with remediation status
- Dark/Light theme toggle
- Export buttons (PDF, JSON, CSV)

### PDF Certificate
- Formal letterhead format
- Security Score with letter grade
- Category breakdown
- Executive sign-off section
- Valid for 90 days watermark

## Project Structure

```
CIA_GUARDIAN/
├── cia_guardian.py              # CLI entrypoint
├── requirements.txt
├── README.md
└── cia_guardian/
    ├── __init__.py
    ├── engine.py                # Main orchestrator (parallel execution)
    ├── controls/
    │   ├── __init__.py
    │   ├── base.py              # SecurityControl base class
    │   ├── confidentiality.py   # CONF-01 to CONF-21 (21 controls)
    │   ├── integrity.py         # INTG-01 to INTG-23 (23 controls)
    │   ├── availability.py      # AVBL-01 to AVBL-18 (18 controls)
    │   ├── network.py           # NETW-01 to NETW-15 (15 controls)
    │   ├── application.py       # APPS-01 to APPS-12 (12 controls)
    │   └── services.py          # SRVC-01 to SRVC-11 (11 controls)
    ├── reporter/
    │   ├── __init__.py
    │   ├── html_dashboard.py    # Bootstrap 5 HTML reports
    │   └── pdf_certificate.py   # FPDF2 certificates
    └── utils/
        ├── __init__.py
        ├── command_runner.py    # Windows command execution
        └── logger.py            # Rich console + file logging
```

## Compliance Mapping

| Framework | Coverage |
|-----------|----------|
| **CIS Windows Benchmarks** | ~85% of Level 1 + Level 2 controls |
| **NIST 800-53** | SC, AC, AU, SI, CP, IA, CM families |
| **NIST CSF** | Identify, Protect, Detect, Respond |
| **ISO 27001** | A.8, A.9, A.12, A.13 controls |
| **PCI DSS** | Requirements 1, 2, 5, 6, 8, 10 |

## N/A Conditions

Some controls return N/A status when not applicable:

- **CONF-05, CONF-18, INTG-17**: Require hardware virtualization support
- **CONF-16, CONF-17**: Require TPM and UEFI
- **CONF-20, CONF-21**: Require domain-joined systems
- **INTG-22**: Requires Windows Defender (not 3rd-party AV)
- **INTG-23**: Requires UEFI boot (not Legacy BIOS)
- **SRVC-03 to SRVC-10**: Only checked if respective services/roles installed
- **SRVC-11**: Only checked if RDP is enabled

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Security score >= 85% (Grade A/B) |
| 1 | Security score 60-84% (Grade C/D) |
| 2 | Security score < 60% (Grade F) |
| 130 | Cancelled by user (Ctrl+C) |

## Performance

- **Parallel Execution**: Controls run concurrently using ThreadPoolExecutor
- **Background SFC**: System File Checker runs non-blocking
- **Typical Runtime**: 2-5 minutes for full audit (varies by system)
- **Skip SFC**: Use `--skip-sfc` for faster execution (~30 seconds)

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-control`)
3. Implement control following the `SecurityControl` base class pattern
4. Add tests and documentation
5. Submit a pull request

### Adding New Controls

```python
from cia_guardian.controls.base import SecurityControl

class MyNewControl(SecurityControl):
    def __init__(self):
        super().__init__(
            control_id="CATG-XX",
            name="Control Name",
            description="What this control does",
            category="category_name",
            risk_level="Critical|High|Medium|Low",
            cis_mapping="CIS Control X.X",
            nist_mapping="NIST XX-X"
        )
    
    def check(self) -> dict:
        # Return {"status": "PASS|FAIL|N/A", "details": "..."}
        pass
    
    def fix(self) -> dict:
        # Return {"status": "FIXED|MANUAL|FAILED", "details": "..."}
        pass
```

## License

MIT License - See LICENSE file for details.

## Support

- **Issues**: [GitHub Issues](https://github.com/razzsecdev/CIA_GUARDIAN/issues)
- **Discussions**: [GitHub Discussions](https://github.com/razzsecdev/CIA_GUARDIAN/discussions)

## Acknowledgments

- CIS Benchmarks for Windows
- NIST 800-53 Security Controls
- Microsoft Security Baselines
- Windows Security Documentation
