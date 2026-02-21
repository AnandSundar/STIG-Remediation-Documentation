<img width="196" height="132" alt="image" src="https://github.com/user-attachments/assets/7729a257-5939-4df6-9f80-131ac4ace016" />

# STIG Remediation Documentation

This repository contains documented STIG remediations performed on a Microsoft Windows 11 Pro 64-bit Azure virtual machine.

## Purpose

- Provide clear, verifiable evidence of STIG remediation work done using PowerShell

## STIG Remediation Reports

[1.) STIG: WN11-CC-000330 — WDigest Authentication must be disabled](./stigs/WN11-CC-000330-WDigest-Authentication.md)

[2.) STIG: WN11-00-000170 — The Server Message Block (SMB) v1 protocol must be disabled](./WN11-00-000170-SMBv1-Disabled.md)

[3.) STIG: WN11-AU-000050 — Logon/Logoff events must be audited for Success and Failure](./WN11-AU-000050-Logon-Auditing.md)

[4.) STIG: WN11-AC-000045 — Passwords must not be stored using reversible encryption](./WN11-AC-000045-Reversible-Encryption.md)

[5.) STIG: WN11-SO-000030 — LAN Manager authentication level must be set to NTLMv2 only](./WN11-SO-000030-LM-Auth-Level.md)

[6.) STIG: WN11-SO-000025 — Anonymous SID/Name translation must not be allowed](./WN11-SO-000025-Anonymous-SID-Translation.md)

[7.) STIG: WN11-00-000070 — Data Execution Prevention (DEP) must be configured to at least OptOut](./WN11-00-000070-DEP-Configuration.md)

[8.) STIG: WN11-CC-000210 — AutoPlay must be disabled for all drives](./WN11-CC-000210-AutoPlay-Disabled.md)

[9.) STIG: WN11-SO-000060 — SMB client must not send unencrypted passwords to third-party servers](./WN11-SO-000060-SMB-Plaintext-Password.md)

[10.) STIG: WN11-SO-000070 — Anonymous enumeration of SAM accounts must not be allowed](./WN11-SO-000070-Anonymous-SAM-Enumeration.md)

## Environment

| Property | Value |
|---|---|
| **OS** | Microsoft Windows 11 Pro 64-bit |
| **Machine Type** | Azure Virtual Machine (x64), standalone |
| **Scanner** | Tenable Vulnerability Management |
| **Audit Policy** | DISA STIG Microsoft Windows 11 v2r6 |
| **STIG Severity** | CAT I (High) |

## Repository Structure

```
stig-remediation-reports/
├── README.md
├── WN11-CC-000330-WDigest-Authentication.md
├── WN11-00-000170-SMBv1-Disabled.md
├── WN11-AU-000050-Logon-Auditing.md
├── WN11-AC-000045-Reversible-Encryption.md
├── WN11-SO-000030-LM-Auth-Level.md
├── WN11-SO-000025-Anonymous-SID-Translation.md
├── WN11-00-000070-DEP-Configuration.md
├── WN11-CC-000210-AutoPlay-Disabled.md
├── WN11-SO-000060-SMB-Plaintext-Password.md
└── WN11-SO-000070-Anonymous-SAM-Enumeration.md
```

## References

- [DISA STIG Microsoft Windows 11 v2r6](https://www.tenable.com/audits/DISA_STIG_Microsoft_Windows_11_v2r6)
- [DISA STIG Viewer](https://stigviewer.com/stigs/microsoft_windows_11)
- [Tenable Vulnerability Management](https://www.tenable.com/products/tenable-io)
